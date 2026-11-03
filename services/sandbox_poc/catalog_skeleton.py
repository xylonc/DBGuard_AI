"""Targeted catalog stand-in for per-object fix rehearsals (Wave 2a, F6).

Given the source snapshot and the selected object-fix proposals, this module
recreates in a disposable sandbox ONLY the objects those fixes touch and what
they need:

- target roles with their exact attributes, connection limit and expiry, and a
  random throwaway password only when the source role had one (type only is
  known; the password itself never leaves this module);
- roles a target needs (owners, grantees) as plain NOLOGIN roles if missing;
- for a table: its schema (if missing) and a zero-column stand-in with the
  source owner, row-level-security flags and exact ACL;
- for a function: a stub with the same schema, name, identity arguments, owner,
  SECURITY DEFINER flag, search_path and exact ACL.

No rows, function bodies, policies, passwords or role settings are copied.
Every name comes from snapshot evidence and goes through ``ident`` (the reviewed
``template_service.quote_identifier`` plus a length check); nothing is
concatenated raw. A name the helper refuses stops the run (ContractError).

Execution is only through ``runtime.sql()`` of a run-owned DisposablePostgres,
as the sandbox superuser. The sandbox's own role is never a target.
"""
from __future__ import annotations

import copy
import re
import secrets

from app.services.spec_engine.catalog_checks import BOOTSTRAP_SUPERUSER_OID, _parse_aclitem
from app.models import FUNCTION_ARG_TYPES, pg_identifier
from app.services.template_service import literal, quote_identifier

from .shared import ContractError

# The sandbox superuser and database created by runtime.DisposablePostgres.
SANDBOX_ROLE = "dbguard_poc"
SANDBOX_DATABASE = "dbguard_sandbox"
# Schemas a fresh sandbox database already has; never created or altered here.
EXISTING_SCHEMAS = frozenset({"public"})
# Roles a fresh PG17 sandbox already has besides the pg_* predefined roles.
EXISTING_ROLES = frozenset({SANDBOX_ROLE})
# NAMEDATALEN - 1: PostgreSQL silently truncates longer names, which would be a
# different object, so such a name is refused rather than shortened.
MAX_IDENTIFIER_BYTES = 63

ROLE_ATTRIBUTES = (("rolsuper", "SUPERUSER"), ("rolcreaterole", "CREATEROLE"),
                   ("rolcreatedb", "CREATEDB"), ("rolreplication", "REPLICATION"),
                   ("rolbypassrls", "BYPASSRLS"), ("rolcanlogin", "LOGIN"),
                   ("rolinherit", "INHERIT"))
TABLE_PRIVILEGES = {"a": "INSERT", "r": "SELECT", "w": "UPDATE", "d": "DELETE",
                    "D": "TRUNCATE", "x": "REFERENCES", "t": "TRIGGER", "m": "MAINTAIN"}
FUNCTION_PRIVILEGES = {"X": "EXECUTE"}
# Password types the collector reports (pg_authid, type only) that a stand-in can
# reproduce, mapped to the password_encryption used for the throwaway password.
PASSWORD_ENCRYPTION = {"scram-sha-256": "scram-sha-256", "md5": "md5"}
# Stub bodies per source language: fixed text, never the source body.
STUB_BODIES = {"sql": "''", "plpgsql": "'BEGIN END'"}
# Built-in argument types a stub may declare: the reviewed allowlist the fix
# templates use (app.models.FUNCTION_ARG_TYPES, identity-argument spelling -> SQL).
# Anything else (domains, enums, composite, polymorphic or extension types) cannot
# be recreated without its definition, so the fix is "can't rehearse".
BUILTIN_ARG_TYPES = FUNCTION_ARG_TYPES
_ARG_NAME = re.compile(r"[a-z_][a-z0-9_$]*")
_VALID_UNTIL = re.compile(r"(?:-?infinity|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?"
                          r"(?:Z|[+-]\d{2}(?::?\d{2})?)?)")

ROLE_FIX_TYPES = frozenset({"role_connection_limit", "role_drop_attribute", "role_nologin"})
FUNCTION_FIX_TYPES = frozenset({"function_security_invoker", "function_revoke_public_execute"})
TABLE_FIX_TYPES = frozenset({"table_revoke_dml"})


def ident(name) -> str:
    """The one quoting helper for every evidence name in this module.

    app.models.pg_identifier (the check the fix templates use: non-empty, at most
    63 bytes, no NUL, control or invisible characters), then
    template_service.quote_identifier (doubles embedded quotes).
    """
    try:
        if len(pg_identifier(name).encode("utf-8")) > MAX_IDENTIFIER_BYTES:
            raise ValueError("too long")
        return quote_identifier(name)
    except (ValueError, UnicodeEncodeError):
        raise ContractError("Stand-in refused: an object name is not a valid PostgreSQL identifier") from None


def _grantee(name: str) -> str:
    return "PUBLIC" if name == "" else ident(name)


def _need_rows(snapshot: dict, section: str) -> list[dict]:
    baseline = snapshot.get("baseline") or {}
    rows = baseline.get(section)
    gapped = any(isinstance(g, dict) and g.get("section") == section for g in baseline.get("gaps") or [])
    if not isinstance(rows, list) or gapped or not all(isinstance(r, dict) for r in rows):
        raise ContractError(f"Stand-in refused: section {section} was not collected")
    return rows


def _is_predefined(name: str) -> bool:
    return name.startswith("pg_")


def _exists_in_sandbox(name: str) -> bool:
    return name in EXISTING_ROLES or _is_predefined(name)


def target_key(proposal: dict) -> str:
    """Stable key of the one object a proposal changes (matches fingerprints())."""
    fix_type, target = proposal.get("fix_type"), proposal.get("target") or {}
    if fix_type in ROLE_FIX_TYPES:
        return "role:" + _text(target, "role")
    if fix_type in FUNCTION_FIX_TYPES:
        return "function:" + "\x1f".join((_text(target, "schema"), _text(target, "name"),
                                          _text(target, "identity_args", allow_empty=True)))
    if fix_type in TABLE_FIX_TYPES:
        return "table:" + _text(target, "schema") + "\x1f" + _text(target, "table")
    raise ContractError("Stand-in refused: unsupported fix type")


def _text(mapping: dict, key: str, allow_empty: bool = False) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or (not value and not allow_empty):
        raise ContractError(f"Stand-in refused: target {key} is missing")
    return value


def parse_identity_args(text: str) -> list[tuple[str | None, str | None, str]]:
    """'a integer, VARIADIC b text[]' -> [(None,'a','integer'), ('VARIADIC','b','text[]')].

    Only built-in types and simple lowercase argument names; IN is implicit, OUT
    and INOUT cannot belong to a void stub. Anything else is refused.
    """
    if not isinstance(text, str):
        raise ContractError("Stand-in refused: function identity arguments are missing")
    if text == "":
        return []
    out = []
    for part in text.split(","):
        part = part.strip()
        mode = None
        if part.startswith("VARIADIC "):
            mode, part = "VARIADIC", part[len("VARIADIC "):].strip()
        base = part[:-2] if part.endswith("[]") else part
        if base in BUILTIN_ARG_TYPES:
            out.append((mode, None, part))
            continue
        name, _, rest = part.partition(" ")
        rest_base = rest[:-2] if rest.endswith("[]") else rest
        if _ARG_NAME.fullmatch(name) and rest_base in BUILTIN_ARG_TYPES:
            out.append((mode, name, rest))
            continue
        raise ContractError("Stand-in refused: function arguments use a type a stub cannot recreate")
    if any(mode == "VARIADIC" and not t.endswith("[]") for mode, _, t in out):
        raise ContractError("Stand-in refused: unsupported VARIADIC argument")
    return out


def _sql_type(spelling: str) -> str:
    array = spelling.endswith("[]")
    return BUILTIN_ARG_TYPES[spelling[:-2] if array else spelling] + ("[]" if array else "")


def render_args(args: list[tuple[str | None, str | None, str]]) -> str:
    # Types are emitted only from the reviewed allowlist (already checked).
    return ", ".join(" ".join(x for x in (mode, ident(name) if name else None, _sql_type(t)) if x)
                     for mode, name, t in args)


def parse_search_path(value: str) -> list[str]:
    """Stored proconfig search_path text -> element names (unquoted)."""
    if not isinstance(value, str):
        raise ContractError("Stand-in refused: function search_path is not collected")
    items, pos = [], 0
    while True:
        while pos < len(value) and value[pos] == " ":
            pos += 1
        if pos < len(value) and value[pos] == '"':
            out, pos = [], pos + 1
            while True:
                if pos >= len(value):
                    raise ContractError("Stand-in refused: unreadable function search_path")
                if value[pos] == '"':
                    if value[pos + 1:pos + 2] == '"':
                        out.append('"')
                        pos += 2
                        continue
                    pos += 1
                    break
                out.append(value[pos])
                pos += 1
            items.append("".join(out))
        else:
            end = value.find(",", pos)
            end = len(value) if end < 0 else end
            item = value[pos:end].strip()
            if not item or '"' in item:
                raise ContractError("Stand-in refused: unreadable function search_path")
            items.append(item)
            pos = end
        while pos < len(value) and value[pos] == " ":
            pos += 1
        if pos >= len(value):
            return items
        if value[pos] != ",":
            raise ContractError("Stand-in refused: unreadable function search_path")
        pos += 1


def _acl_items(acl, privileges: dict, owner: str) -> list[tuple[str, list[str], list[str]]]:
    """Parsed aclitems -> [(grantee, privileges, privileges_with_grant_option)]."""
    items = []
    for item in acl:
        parsed = _parse_aclitem(item)
        if parsed is None:
            raise ContractError("Stand-in refused: unreadable ACL entry")
        grantee, privs, grantor = parsed
        if grantor != owner:
            # A superuser's GRANT is recorded as granted by the owner; another
            # grantor's entry cannot be reproduced the same way.
            raise ContractError("Stand-in refused: a grant made by a role other than the owner cannot be rehearsed")
        plain, option, index = [], [], 0
        while index < len(privs):
            letter = privs[index]
            if letter not in privileges:
                raise ContractError("Stand-in refused: unsupported privilege in ACL")
            star = privs[index + 1:index + 2] == "*"
            (option if star else plain).append(privileges[letter])
            index += 2 if star else 1
        items.append((grantee, plain, option))
    return items


def _grant_statements(object_sql: str, items) -> list[str]:
    out = []
    for grantee, plain, option in items:
        if plain:
            out.append(f"GRANT {', '.join(plain)} ON {object_sql} TO {_grantee(grantee)};")
        if option:
            out.append(f"GRANT {', '.join(option)} ON {object_sql} TO {_grantee(grantee)} WITH GRANT OPTION;")
    return out


def plan(snapshot: dict, proposals: list[dict]) -> dict:
    """Pure: the stand-in for these proposals (statements, never passwords)."""
    if not proposals:
        raise ContractError("Stand-in refused: no object fix selected")
    roles = {}
    for row in _need_rows(snapshot, "roles"):
        if not isinstance(row.get("rolname"), str):
            raise ContractError("Stand-in refused: unreadable role evidence")
        roles[row["rolname"]] = row
    exact: list[str] = []       # target roles, recreated with exact attributes
    deps: list[str] = []        # roles a target needs (owner, grantee), NOLOGIN if missing
    schemas: list[str] = []
    tables: list[dict] = []
    functions: list[dict] = []

    def need_role(name: str):
        if not isinstance(name, str) or name == "":
            raise ContractError("Stand-in refused: missing role name")
        ident(name)
        if name not in deps and name not in exact and not _exists_in_sandbox(name):
            deps.append(name)

    def need_schema(name: str):
        ident(name)
        if name in EXISTING_SCHEMAS or name in schemas:
            return
        if _is_predefined(name) or name == "information_schema":
            raise ContractError("Stand-in refused: system schemas are never recreated")
        schemas.append(name)

    for proposal in proposals:
        fix_type, target = proposal.get("fix_type"), proposal.get("target") or {}
        target_key(proposal)
        if proposal.get("rehearsable") is False:
            raise ContractError("Stand-in refused: this fix is marked not rehearsable")
        if fix_type in ROLE_FIX_TYPES:
            name = target["role"]
            ident(name)
            if name == SANDBOX_ROLE:
                raise ContractError("Stand-in refused: the sandbox's own role cannot be a fix target")
            if _is_predefined(name):
                raise ContractError("Stand-in refused: predefined roles are never fix targets")
            row = roles.get(name)
            if row is None:
                raise ContractError("Stand-in refused: target role is not in the source evidence")
            if str(row.get("oid")) == str(BOOTSTRAP_SUPERUSER_OID):
                raise ContractError("Stand-in refused: the bootstrap superuser is never a fix target")
            if name in deps:
                deps.remove(name)
            if name not in exact:
                exact.append(name)
        elif fix_type in TABLE_FIX_TYPES:
            schema, table = target["schema"], target["table"]
            row = next((r for r in _need_rows(snapshot, "object_acls")
                        if r.get("schema") == schema and r.get("name") == table), None)
            if row is None:
                raise ContractError("Stand-in refused: target table is not in the source evidence")
            if row.get("kind") != "r":
                raise ContractError("Stand-in refused: only ordinary tables have a stand-in")
            if any(t["schema"] == schema and t["name"] == table for t in tables):
                continue
            need_schema(schema)
            need_role(row.get("owner"))
            acl = row.get("acl")
            if acl is not None and (not isinstance(acl, list) or not all(isinstance(a, str) for a in acl)):
                raise ContractError("Stand-in refused: unreadable table ACL")
            items = _acl_items(acl, TABLE_PRIVILEGES, row["owner"]) if acl is not None else None
            for grantee, _, _ in items or []:
                if grantee:
                    need_role(grantee)
            if not isinstance(row.get("rls"), bool) or not isinstance(row.get("rls_forced"), bool):
                raise ContractError("Stand-in refused: table row-level-security flags are missing")
            tables.append({"schema": schema, "name": table, "owner": row["owner"], "acl_items": items,
                           "rls": row["rls"], "rls_forced": row["rls_forced"]})
        elif fix_type in FUNCTION_FIX_TYPES:
            schema, name, args_text = target["schema"], target["name"], target["identity_args"]
            row = next((r for r in _need_rows(snapshot, "functions")
                        if r.get("schema") == schema and r.get("name") == name
                        and r.get("identity_args") == args_text), None)
            if row is None:
                raise ContractError("Stand-in refused: target function is not in the source evidence")
            if any(f["schema"] == schema and f["name"] == name and f["identity_args"] == args_text
                   for f in functions):
                continue
            if row.get("kind") != "f":
                raise ContractError("Stand-in refused: only plain functions have a stub")
            if row.get("extension") is not None:
                raise ContractError("Stand-in refused: extension-owned functions are never fix targets")
            if row.get("language") not in STUB_BODIES:
                raise ContractError("Stand-in refused: no stub for this function language")
            config = row.get("config_names")
            if not isinstance(config, list) or not set(config) <= {"search_path"} or len(config) != len(set(config)):
                # Other SET values are withheld by the collector, so they cannot be recreated.
                raise ContractError("Stand-in refused: the function pins settings a stub cannot recreate")
            search_path = parse_search_path(row.get("search_path")) if config else None
            if not config and row.get("search_path") is not None:
                raise ContractError("Stand-in refused: inconsistent function search_path evidence")
            if not isinstance(row.get("prosecdef"), bool):
                raise ContractError("Stand-in refused: function SECURITY DEFINER flag is missing")
            args = parse_identity_args(args_text)
            need_schema(schema)
            need_role(row.get("owner"))
            acl = row.get("acl")
            if not isinstance(acl, list) or not all(isinstance(a, str) for a in acl):
                raise ContractError("Stand-in refused: unreadable function ACL")
            items = _acl_items(acl, FUNCTION_PRIVILEGES, row["owner"])
            for grantee, _, _ in items:
                if grantee:
                    need_role(grantee)
            default = items == [("", ["EXECUTE"], []), (row["owner"], ["EXECUTE"], [])]
            functions.append({"schema": schema, "name": name, "identity_args": args_text, "args": args,
                              "owner": row["owner"], "prosecdef": row["prosecdef"], "language": row["language"],
                              "search_path": search_path, "acl_items": None if default else items})
        else:
            raise ContractError("Stand-in refused: unsupported fix type")

    schema_rows = {}
    if schemas:
        schema_rows = {r.get("nspname"): r for r in _need_rows(snapshot, "schemas")}
        for name in schemas:
            row = schema_rows.get(name)
            if row is None or not isinstance(row.get("owner"), str):
                raise ContractError("Stand-in refused: target schema is not in the source evidence")
            need_role(row["owner"])

    password_rows = (snapshot.get("baseline") or {}).get("password_types")
    passwords = {}
    password_notes = {}
    for name in exact:
        row = roles[name]
        listed = next((p for p in password_rows or [] if isinstance(p, dict) and p.get("rolname") == name), None)
        if listed is None:
            password_notes[name] = "not_listed" if isinstance(password_rows, list) else "password_type_not_collected"
            continue
        kind = listed.get("password_type")
        if kind == "none":
            password_notes[name] = "none"
        elif kind in PASSWORD_ENCRYPTION:
            passwords[name] = PASSWORD_ENCRYPTION[kind]
            password_notes[name] = kind
        else:
            raise ContractError("Stand-in refused: unsupported password type")

    statements = []
    for name in exact:
        statements.append(_create_exact_role(name, roles[name]))
    for name in deps:
        statements.append(f"CREATE ROLE {ident(name)} NOLOGIN;")
    created = set(exact) | set(deps)
    memberships = []
    for row in _need_rows(snapshot, "role_memberships") if exact else []:
        group, member = row.get("role"), row.get("member")
        if (group in created and member in created and (group in exact or member in exact)):
            admin = row.get("admin_option") is True
            memberships.append({"role": group, "member": member, "admin_option": admin})
            statements.append(f"GRANT {ident(group)} TO {ident(member)}" + (" WITH ADMIN OPTION;" if admin else ";"))
    for name in schemas:
        statements.append(f"CREATE SCHEMA {ident(name)} AUTHORIZATION {ident(schema_rows[name]['owner'])};")
    for table in tables:
        obj = f"{ident(table['schema'])}.{ident(table['name'])}"
        statements.append(f"CREATE TABLE {obj} ();")
        statements.append(f"ALTER TABLE {obj} OWNER TO {ident(table['owner'])};")
        if table["rls"]:
            statements.append(f"ALTER TABLE {obj} ENABLE ROW LEVEL SECURITY;")
        if table["rls_forced"]:
            statements.append(f"ALTER TABLE {obj} FORCE ROW LEVEL SECURITY;")
        if table["acl_items"] is not None:
            statements.append(f"REVOKE ALL ON TABLE {obj} FROM PUBLIC, {ident(table['owner'])};")
            statements.extend(_grant_statements("TABLE " + obj, table["acl_items"]))
    for function in functions:
        obj = f"{ident(function['schema'])}.{ident(function['name'])}({render_args(function['args'])})"
        clauses = [f"CREATE FUNCTION {obj} RETURNS void LANGUAGE {function['language']}"]
        if function["prosecdef"]:
            clauses.append("SECURITY DEFINER")
        if function["search_path"] is not None:
            clauses.append("SET search_path = " + ", ".join(ident(p) for p in function["search_path"]))
        clauses.append("AS " + STUB_BODIES[function["language"]] + ";")
        statements.append(" ".join(clauses))
        statements.append(f"ALTER FUNCTION {obj} OWNER TO {ident(function['owner'])};")
        if function["acl_items"] is not None:
            statements.append(f"REVOKE ALL ON FUNCTION {obj} FROM PUBLIC, {ident(function['owner'])};")
            statements.extend(_grant_statements("FUNCTION " + obj, function["acl_items"]))
    return {"exact_roles": exact, "dependency_roles": deps, "memberships": memberships,
            "schemas": schemas,
            "tables": [{k: t[k] for k in ("schema", "name")} for t in tables],
            "functions": [{k: f[k] for k in ("schema", "name", "identity_args")} for f in functions],
            "statements": statements, "throwaway_passwords": passwords,
            "password_types": password_notes}


def _create_exact_role(name: str, row: dict) -> str:
    parts = [f"CREATE ROLE {ident(name)} WITH"]
    for field, keyword in ROLE_ATTRIBUTES:
        value = row.get(field)
        if not isinstance(value, bool):
            raise ContractError(f"Stand-in refused: role attribute {field} is missing")
        parts.append(keyword if value else "NO" + keyword)
    limit = row.get("rolconnlimit")
    if type(limit) is not int or limit < -1:
        raise ContractError("Stand-in refused: role connection limit is missing")
    parts.append(f"CONNECTION LIMIT {limit}")
    until = row.get("rolvaliduntil")
    if until is not None:
        if not isinstance(until, str) or not _VALID_UNTIL.fullmatch(until):
            raise ContractError("Stand-in refused: unreadable role expiry")
        parts.append(f"VALID UNTIL '{literal(until)}'")
    return " ".join(parts) + ";"


def summary(skeleton: dict) -> dict:
    """What was recreated, for evidence. Never a password (only whether one was set)."""
    out = {k: copy.deepcopy(v) for k, v in skeleton.items() if k != "throwaway_passwords"}
    out["throwaway_password_roles"] = sorted(skeleton["throwaway_passwords"])
    return out


def build(runtime, snapshot: dict, proposals: list[dict]) -> dict:
    """Create the stand-in in a run-owned sandbox; returns summary() of the plan."""
    skeleton = plan(snapshot, proposals)
    runtime.sql("BEGIN;\n" + "\n".join(skeleton["statements"]) + "\nCOMMIT;\n")
    for name, encryption in skeleton["throwaway_passwords"].items():
        _set_throwaway_password(runtime, name, encryption)
    return summary(skeleton)


def _set_throwaway_password(runtime, name: str, encryption: str) -> None:
    """A random password nobody keeps: never logged, returned or stored.

    It travels only on psql's stdin. Statement logging is switched off for this
    session (the reconstructed settings may log DDL), errors are terse and any
    failure is replaced by a fixed message so the statement text cannot surface.
    """
    if encryption not in PASSWORD_ENCRYPTION.values():
        raise ContractError("Stand-in refused: unsupported password type")
    script = ("\\set VERBOSITY terse\n\\set SHOW_CONTEXT never\n"
              "SET log_statement = 'none';\nSET log_min_error_statement = 'panic';\n"
              "SET log_min_duration_statement = -1;\nSET log_duration = off;\n"
              f"SET password_encryption = '{encryption}';\n"
              f"ALTER ROLE {ident(name)} PASSWORD '{literal(secrets.token_urlsafe(32))}';\n")
    try:
        runtime.sql(script)
    except Exception:
        raise RuntimeError("Setting a throwaway password on a stand-in role failed") from None
    finally:
        script = None


def fingerprints(snapshot: dict, skeleton: dict) -> dict:
    """Collected rows of every recreated object, keyed like target_key()."""
    baseline = snapshot.get("baseline") or {}
    out = {}
    roles = {r.get("rolname"): r for r in baseline.get("roles") or [] if isinstance(r, dict)}
    for name in skeleton["exact_roles"] + skeleton["dependency_roles"]:
        row = roles.get(name)
        out["role:" + name] = None if row is None else {k: v for k, v in row.items() if k != "oid"}
    acls = {(r.get("schema"), r.get("name")): r for r in baseline.get("object_acls") or [] if isinstance(r, dict)}
    for table in skeleton["tables"]:
        out["table:" + table["schema"] + "\x1f" + table["name"]] = copy.deepcopy(acls.get((table["schema"], table["name"])))
    functions = {(r.get("schema"), r.get("name"), r.get("identity_args")): r
                 for r in baseline.get("functions") or [] if isinstance(r, dict)}
    for f in skeleton["functions"]:
        key = "function:" + "\x1f".join((f["schema"], f["name"], f["identity_args"]))
        out[key] = copy.deepcopy(functions.get((f["schema"], f["name"], f["identity_args"])))
    schemas = {r.get("nspname"): r for r in baseline.get("schemas") or [] if isinstance(r, dict)}
    for name in skeleton["schemas"]:
        out["schema:" + name] = copy.deepcopy(schemas.get(name))
    members = baseline.get("role_memberships") or []
    for m in skeleton["memberships"]:
        out["membership:" + m["role"] + "\x1f" + m["member"]] = next(
            (copy.deepcopy(r) for r in members if r.get("role") == m["role"] and r.get("member") == m["member"]), None)
    return out
