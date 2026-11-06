"""Catalog check kind: fixed evaluators over collected baseline sections.

A spec with ``check.kind: catalog`` names one evaluator from REGISTRY. The
spec never carries SQL or a fix: an evaluator only reads sections that the
read-only collector already produced and returns a result, the evidence a
human needs, and a structured explanation (a code plus facts, never prose).

Rules shared by every evaluator:

- ``[]`` means collected and empty. ``null``, an absent section, or a section
  with a matching ``gaps`` entry means not collected: GAPPED, never PASS.
- A row that lacks a field the evaluator needs is GAPPED (``field_missing``).
- A snapshot from another PostgreSQL major than the spec is GAPPED.
- Evidence is names and attributes only. Password hashes, function bodies,
  policy expressions and archive_command text are never read or returned.

Every function here is pure: no clock, no I/O. 7.4 compares timestamps with
the snapshot's own ``envelope.collected_at``. 3.2 reads one key of the policy
profile passed to ``evaluate`` (never a file), and only when it is approved.

This module must not import ``validate`` (validate imports REGISTRY).
"""
from __future__ import annotations

import copy
import ipaddress
import re
import string
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any, Callable

from .redaction import is_redacted
from .sources import session_override

# 7.4: maximum age of the last successful archive, relative to the collection
# time, for a PASS. Default approved by Melvin at Gate 1 (recorded in
# docs/gates/F6-gate1.md §6); see the interpretation
# entries in catalog/specs/cis-pg17-v1.1.0/7.4.yaml. A policy-profile override is
# owned by the main branch (approval-gated) and is deliberately not wired here.
WAL_ARCHIVE_MAX_AGE_HOURS = 24

# 7.4: a last_archived_time later than collected_at by more than this is not
# trusted (clock skew or a corrupted snapshot) and gives MANUAL.
ARCHIVE_FUTURE_TOLERANCE_SECONDS = 300

# Fixed, reviewed notices shown with every result of a recommendation, whatever
# its status. Requested by Melvin for 7.4 (F6). Never model output.
RESTORE_TEST_REMINDER = (
    "DBGuard checks PostgreSQL's archiver status: archiving is on, one archive method is set, "
    "files were copied recently, and no failure came after the last copy. It cannot see your "
    "backup storage, so it cannot confirm the archive files exist or can be restored. Run a "
    "periodic restore test and record the result (CIS review and procedure controls)."
)
NOTICES: "MappingProxyType[str, tuple[tuple[str, str], ...]]" = MappingProxyType({
    "7.4": (("restore_test_reminder", RESTORE_TEST_REMINDER),),
})


def notices_for(recommendation: Any) -> list[dict[str, str]]:
    """The fixed notices for a recommendation, as fresh {code, text} dicts."""
    return [{"code": code, "text": text} for code, text in NOTICES.get(recommendation, ())]


# Role OID of the bootstrap superuser created by initdb.
BOOTSTRAP_SUPERUSER_OID = 10

ADMIN_ATTRIBUTES = ("rolsuper", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls")
DML_PRIVILEGES = {"a": "INSERT", "w": "UPDATE", "d": "DELETE"}
TABLE_KINDS = ("r", "p")  # pg_tables, as in the CIS 4.6 audit query
CIS_NAMED_NON_PASSWORD_METHODS = ("cert", "gss", "ldap")  # "certificate, GSSAPI, or LDAP"
ARCHIVE_MODES_ENABLED = ("on", "always")


class _Gapped(Exception):
    def __init__(self, explanation: dict[str, Any], paths: list[str]):
        super().__init__(explanation["code"])
        self.explanation = explanation
        self.paths = paths


def _field_missing(section: str, field: str) -> _Gapped:
    return _Gapped({"code": "field_missing", "section": section, "field": field}, [f"{section}.{field}"])


class _Context:
    def __init__(self, spec: dict[str, Any], snapshot: dict[str, Any], policy: Any = None):
        self.spec = spec
        self.policy = policy  # a PolicyProfile or None; read only by evaluators with policy_keys
        snapshot = snapshot if isinstance(snapshot, dict) else {}
        baseline = snapshot.get("baseline")
        self.baseline = baseline if isinstance(baseline, dict) else {}
        envelope = snapshot.get("envelope")
        self.envelope = envelope if isinstance(envelope, dict) else {}
        gaps = self.baseline.get("gaps")
        self.gaps = [g for g in gaps if isinstance(g, dict)] if isinstance(gaps, list) else []
        self.not_collected: list[str] = []  # optional sections that were not collected

    def gap_for(self, section: str) -> dict[str, Any] | None:
        return next((g for g in self.gaps if g.get("section") == section), None)

    def section(self, name: str, kind: type = list) -> Any:
        """A required section, or raise GAPPED section_not_collected."""
        value = self.baseline.get(name)
        gap = self.gap_for(name)
        # A section of the wrong shape is treated like null without a gap
        # record: the collector contract was violated, so nothing is known.
        if value is None or gap is not None or not isinstance(value, kind):
            explanation: dict[str, Any] = {"code": "section_not_collected", "section": name}
            if gap is not None and isinstance(gap.get("reason"), str):
                explanation["gap_reason"] = gap.get("reason")
            raise _Gapped(explanation, [name])
        return value

    def optional(self, name: str, kind: type = list) -> Any:
        """An optional section, or None (recorded in sections_not_collected)."""
        try:
            return self.section(name, kind)
        except _Gapped:
            self.not_collected.append(name)
            return None

    def rows(self, name: str) -> list[dict[str, Any]]:
        rows = self.section(name, list)
        if not all(isinstance(r, dict) for r in rows):
            raise _field_missing(name, "row")
        return rows

    def connected_database(self) -> str:
        name = self.envelope.get("database")
        if not isinstance(name, str) or not name:
            raise _field_missing("envelope", "database")
        return name


def _need(row: dict[str, Any], section: str, field: str, kind: type | tuple, nullable: bool = False) -> Any:
    if field not in row:
        raise _field_missing(section, field)
    value = row[field]
    if value is None and nullable:
        return None
    # bool is a subclass of int; an int field must not accept a bool.
    if kind is int and isinstance(value, bool):
        raise _field_missing(section, field)
    if not isinstance(value, kind):
        raise _field_missing(section, field)
    return value


def _str_list(row: dict[str, Any], section: str, field: str, nullable: bool = False) -> list[str] | None:
    value = _need(row, section, field, list, nullable)
    if value is not None and not all(isinstance(v, str) for v in value):
        raise _field_missing(section, field)
    return value


def _is_bootstrap(row: dict[str, Any]) -> bool:
    oid = _need(row, "roles", "oid", (str, int))
    return str(oid) == str(BOOTSTRAP_SUPERUSER_OID)


def _role_index(ctx: _Context) -> dict[str, dict[str, Any]]:
    index = {}
    bootstrap = False
    for row in ctx.rows("roles"):
        index[_need(row, "roles", "rolname", str)] = row
        bootstrap = bootstrap or _is_bootstrap(row)
    # Every cluster has the bootstrap superuser; without it the list is incomplete.
    if not bootstrap:
        raise _field_missing("roles", "oid")
    return index


def _members_of(memberships: list[dict[str, Any]], role: str) -> list[str]:
    """Every role that is a direct or indirect member of ``role``."""
    found: list[str] = []
    queue = [role]
    while queue:
        current = queue.pop(0)
        for row in memberships:
            if _need(row, "role_memberships", "role", str) != current:
                continue
            member = _need(row, "role_memberships", "member", str)
            if member != role and member not in found:
                found.append(member)
                queue.append(member)
    return found


def _other_databases(ctx: _Context) -> list[str]:
    """Connectable, non-template databases other than the connected one."""
    connected = ctx.connected_database()
    names = []
    rows = ctx.rows("databases")
    # The connected database must be listed; otherwise the list is incomplete.
    if not any(isinstance(r.get("datname"), str) and r["datname"] == connected for r in rows):
        raise _field_missing("databases", "datname")
    for row in rows:
        name = _need(row, "databases", "datname", str)
        allow = _need(row, "databases", "datallowconn", bool)
        template = _need(row, "databases", "datistemplate", bool)
        if allow and not template and name != connected:
            names.append(name)
    return sorted(names)


def _parse_aclitem(item: Any) -> tuple[str, str, str] | None:
    """'grantee=privs/grantor' -> (grantee, privs, grantor); '' grantee is PUBLIC."""
    if not isinstance(item, str):
        return None

    def ident(text: str, pos: int, stop: str) -> tuple[str, int] | None:
        if pos < len(text) and text[pos] == '"':
            out, pos = [], pos + 1
            while pos < len(text):
                if text[pos] == '"':
                    if pos + 1 < len(text) and text[pos + 1] == '"':
                        out.append('"')
                        pos += 2
                        continue
                    return "".join(out), pos + 1
                out.append(text[pos])
                pos += 1
            return None
        end = text.find(stop, pos) if stop else len(text)
        if end < 0:
            return None
        return text[pos:end], end

    parsed = ident(item, 0, "=")
    if parsed is None:
        return None
    grantee, pos = parsed
    if pos >= len(item) or item[pos] != "=":
        return None
    slash = item.find("/", pos + 1)
    if slash < 0:
        return None
    privs = item[pos + 1:slash]
    if any(c not in "arwdDxtmXUCcTsA*" for c in privs):
        return None
    parsed = ident(item, slash + 1, "")
    if parsed is None or parsed[1] != len(item):
        return None
    return grantee, privs, parsed[0]


def _timestamp(value: Any) -> datetime | None:
    """Timezone-aware ISO 8601 timestamp, or None if absent or unparseable."""
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else None
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _manual(ctx: _Context, evidence: list, paths: list[str], code: str = "manual_review", **facts) -> dict:
    return _result(ctx, "MANUAL", evidence, paths, {"code": code, "evidence_count": len(evidence), **facts})


def _result(ctx: _Context, result: str, evidence: list, paths: list[str], explanation: dict) -> dict:
    if ctx.not_collected:
        explanation = {**explanation, "sections_not_collected": list(ctx.not_collected)}
    return {"result": result, "evidence": evidence, "evidence_paths": paths, "explanation": explanation}


# ---------------------------------------------------------------------------
# Evaluators. Each takes a _Context and returns a result dict, or raises _Gapped.
# ---------------------------------------------------------------------------

def _roles_with_admin_attributes(ctx: _Context) -> dict:  # 4.3
    evidence = []
    for name, row in sorted(_role_index(ctx).items()):
        flags = {attr: _need(row, "roles", attr, bool) for attr in ADMIN_ATTRIBUTES}
        login = _need(row, "roles", "rolcanlogin", bool)
        if name.startswith("pg_") or not any(flags.values()):
            continue
        evidence.append({"rolname": name, **flags, "rolcanlogin": login,
                         "bootstrap_superuser": _is_bootstrap(row)})
    return _manual(ctx, evidence, ["roles"])


def _login_roles(ctx: _Context) -> dict:  # 4.4
    roles = _role_index(ctx)
    types = ctx.optional("password_types")
    by_name = {}
    for row in types or []:
        if not isinstance(row, dict):
            raise _field_missing("password_types", "row")
        by_name[_need(row, "password_types", "rolname", str)] = _need(row, "password_types", "password_type", str)
    evidence = []
    for name, row in sorted(roles.items()):
        if name.startswith("pg_") or not _need(row, "roles", "rolcanlogin", bool):
            continue
        evidence.append({"rolname": name, "rolsuper": _need(row, "roles", "rolsuper", bool),
                         "rolvaliduntil": _need(row, "roles", "rolvaliduntil", str, nullable=True),
                         "password_type": by_name.get(name) if types is not None else None})
    return _manual(ctx, evidence, ["roles", "password_types"])


def _elevated_functions(ctx: _Context) -> dict:  # 4.5
    evidence = []
    for row in ctx.rows("functions"):
        name = _need(row, "functions", "name", str)
        extension = _need(row, "functions", "extension", str, nullable=True)
        if name.startswith("pgaudit") and extension == "pgaudit":
            continue
        evidence.append({
            "schema": _need(row, "functions", "schema", str),
            "name": name,
            "identity_args": _need(row, "functions", "identity_args", str),
            "owner": _need(row, "functions", "owner", str),
            "prosecdef": _need(row, "functions", "prosecdef", bool),
            "search_path": _need(row, "functions", "search_path", str, nullable=True),
            "config_names": _str_list(row, "functions", "config_names"),
            "acl": _str_list(row, "functions", "acl"),
            "extension": extension,
        })
    others = _other_databases(ctx)
    paths = ["functions", "databases", "envelope.database"]
    if others:
        return _manual(ctx, evidence, paths, "databases_not_covered", databases=others)
    if evidence:
        return _manual(ctx, evidence, paths)
    return _result(ctx, "PASS", [], paths, {"code": "empty_review_set", "evidence_count": 0})


def _table_dml_grants(ctx: _Context) -> dict:  # 4.6
    roles = _role_index(ctx)
    memberships = ctx.rows("role_memberships")
    evidence = []
    for row in ctx.rows("object_acls"):
        kind = _need(row, "object_acls", "kind", str)
        if kind not in TABLE_KINDS:
            continue
        schema = _need(row, "object_acls", "schema", str)
        table = _need(row, "object_acls", "name", str)
        owner = _need(row, "object_acls", "owner", str)
        acl = _str_list(row, "object_acls", "acl", nullable=True)
        for item in acl or []:  # null relacl: default privileges, owner only
            parsed = _parse_aclitem(item)
            if parsed is None:
                raise _field_missing("object_acls", "acl")
            grantee, privs, grantor = parsed
            dml = [label for letter, label in DML_PRIVILEGES.items() if letter in privs]
            if not dml or grantee == owner:
                continue
            base = {"type": "table_grant", "schema": schema, "table": table, "owner": owner,
                    "privileges": dml, "grantor": grantor}
            evidence.append({**base, "grantee": grantee or "PUBLIC", "via": None, "upper_bound": False})
            if grantee:
                for member in _members_of(memberships, grantee):
                    if member != owner:
                        evidence.append({**base, "grantee": member, "via": grantee, "upper_bound": True})
    for name, row in sorted(roles.items()):
        if _need(row, "roles", "rolsuper", bool):
            evidence.append({"type": "superuser", "rolname": name,
                             "rolcanlogin": _need(row, "roles", "rolcanlogin", bool)})
    direct = {_need(r, "role_memberships", "member", str) for r in memberships
              if _need(r, "role_memberships", "role", str) == "pg_write_all_data"}
    for member in _members_of(memberships, "pg_write_all_data"):
        evidence.append({"type": "pg_write_all_data_member", "rolname": member,
                         "upper_bound": member not in direct})
    others = _other_databases(ctx)
    paths = ["object_acls", "roles", "role_memberships", "databases", "envelope.database"]
    if others:
        return _manual(ctx, evidence, paths, "databases_not_covered", databases=others)
    return _manual(ctx, evidence, paths)


def _rls_tables_and_bypass_roles(ctx: _Context) -> dict:  # 4.7
    roles = _role_index(ctx)
    policies = []
    for row in ctx.rows("rls_policies"):
        policies.append({
            "schema": _need(row, "rls_policies", "schema", str),
            "table": _need(row, "rls_policies", "table", str),
            "policy": _need(row, "rls_policies", "policy", str),
            "cmd": _need(row, "rls_policies", "cmd", str),
            "permissive": _need(row, "rls_policies", "permissive", str),
            "roles": _str_list(row, "rls_policies", "roles"),
        })  # qual and with_check are never read
    tables, bypass = [], {}
    for row in ctx.rows("object_acls"):
        if not _need(row, "object_acls", "rls", bool):
            continue
        schema = _need(row, "object_acls", "schema", str)
        table = _need(row, "object_acls", "name", str)
        owner = _need(row, "object_acls", "owner", str)
        forced = _need(row, "object_acls", "rls_forced", bool)
        mine = [{k: p[k] for k in ("policy", "cmd", "permissive", "roles")} for p in policies
                if p["schema"] == schema and p["table"] == table]
        tables.append({"type": "rls_table", "schema": schema, "table": table, "owner": owner,
                       "rls_forced": forced, "policy_count": len(mine), "no_policies": not mine,
                       "policies": mine})
        if not forced:
            entry = bypass.setdefault(owner, {"reasons": [], "owned_non_forced_tables": []})
            entry["owned_non_forced_tables"].append(f"{schema}.{table}")
    rls_names = {(t["schema"], t["table"]) for t in tables}
    orphans = [{"type": "policy_without_rls", **p} for p in policies if (p["schema"], p["table"]) not in rls_names]
    for name, row in roles.items():
        if _need(row, "roles", "rolbypassrls", bool):
            bypass.setdefault(name, {"reasons": [], "owned_non_forced_tables": []})["reasons"].append("bypassrls")
        if _need(row, "roles", "rolsuper", bool):
            bypass.setdefault(name, {"reasons": [], "owned_non_forced_tables": []})["reasons"].append("superuser")
    bypass_rows = []
    for name, entry in sorted(bypass.items()):
        reasons = entry["reasons"] + (["owner_of_non_forced_rls_table"] if entry["owned_non_forced_tables"] else [])
        row = roles.get(name)
        bypass_rows.append({"type": "bypass_role", "rolname": name, "reasons": reasons,
                            "rolsuper": _need(row, "roles", "rolsuper", bool) if row else None,
                            "owned_non_forced_tables": entry["owned_non_forced_tables"]})
    evidence = tables + orphans + bypass_rows
    others = _other_databases(ctx)
    paths = ["object_acls", "rls_policies", "roles", "databases", "envelope.database"]
    if others:
        return _manual(ctx, evidence, paths, "databases_not_covered", databases=others)
    return _manual(ctx, evidence, paths)


def _superuser_roles(ctx: _Context) -> dict:  # 4.9
    evidence = []
    for name, row in sorted(_role_index(ctx).items()):
        if _need(row, "roles", "rolsuper", bool):
            evidence.append({"rolname": name, "rolcanlogin": _need(row, "roles", "rolcanlogin", bool),
                             "bootstrap_superuser": _is_bootstrap(row)})
    return _manual(ctx, evidence, ["roles"])


def _hba_rows(ctx: _Context, rules: list | None, extra: tuple[str, ...] = ()) -> list[dict[str, Any]]:
    """pg_hba_file_rules rows as evidence. ``extra`` adds address, netmask and/or
    options; each is read (and must be well formed) only when a caller asks for it.
    The error text is never returned (it can quote the line), only has_error."""
    out = []
    for row in rules or []:
        if not isinstance(row, dict):
            raise _field_missing("hba_rules", "row")
        rule = {
            "line_number": _need(row, "hba_rules", "line_number", int),
            "connection_type": _need(row, "hba_rules", "type", str, nullable=True),
            "database": _str_list(row, "hba_rules", "database", nullable=True),
            "user_name": _str_list(row, "hba_rules", "user_name", nullable=True),
            "auth_method": _need(row, "hba_rules", "auth_method", str, nullable=True),
            "has_error": _need(row, "hba_rules", "error", str, nullable=True) is not None,
        }
        for field in extra:
            if field == "options":
                rule["options"] = _hba_options(row)
            else:
                rule[field] = _need(row, "hba_rules", field, str, nullable=True)
        out.append(rule)
    return out


# pg_hba options whose VALUE is shown (W2B E0). Every other option is shown by
# name only, so a secret-bearing value (ldapbindpasswd, radiussecrets, or one the
# collector failed to mask) never reaches evidence. Nothing is ever unmasked.
HBA_OPTION_VALUES_SHOWN = ("map", "clientcert", "clientname")
_HBA_OPTION_NAME_RE = re.compile(r"[a-z_][a-z0-9_]*")


def _hba_options(row: dict[str, Any]) -> list[dict[str, Any]]:
    """options ('name=value' strings, or null) as [{name[, value]}].

    A name that is not a plain lower-case option name is shown as null, never as text.
    """
    options = _str_list(row, "hba_rules", "options", nullable=True)
    out = []
    for item in options or []:
        name, sep, value = item.partition("=")
        if not sep or not _HBA_OPTION_NAME_RE.fullmatch(name):
            out.append({"name": None})
        elif name in HBA_OPTION_VALUES_SHOWN:
            out.append({"name": name, "value": value})
        else:
            out.append({"name": name})
    return out


def _login_roles_without_password(ctx: _Context) -> dict:  # 4.10
    roles = _role_index(ctx)
    types = ctx.rows("password_types")
    rules = _hba_rows(ctx, ctx.optional("hba_rules"))
    listed = set()
    missing = []
    for row in types:
        name = _need(row, "password_types", "rolname", str)
        listed.add(name)
        if _need(row, "password_types", "password_type", str) == "none":
            missing.append(name)
    # password_types lists every login role; one absent from it is unknown.
    for name, row in roles.items():
        if _need(row, "roles", "rolcanlogin", bool) and name not in listed:
            raise _field_missing("password_types", "password_type")
    evidence = []
    for name in sorted(missing):
        matching = None
        if "hba_rules" not in ctx.not_collected:
            matching = []
            for rule in rules:
                users = rule["user_name"] or []
                # Over-include: groups, files, regexes and broken lines could all match.
                if rule["has_error"] or any(u == name or u == "all" or u[:1] in ("+", "@", "/") for u in users):
                    matching.append({**rule, "trust": rule["auth_method"] == "trust",
                                     "cis_named_non_password_method": rule["auth_method"] in CIS_NAMED_NON_PASSWORD_METHODS})
        row = roles.get(name)
        evidence.append({"rolname": name,
                         "rolsuper": _need(row, "roles", "rolsuper", bool) if row else None,
                         "hba_rules": matching})
    paths = ["password_types", "roles", "hba_rules"]
    if evidence:
        return _manual(ctx, evidence, paths)
    return _result(ctx, "PASS", [], paths, {"code": "empty_review_set", "evidence_count": 0})


def _role_connection_limits(ctx: _Context) -> dict:  # 5.5
    failing, passing, info = [], [], []
    for name, row in sorted(_role_index(ctx).items()):
        if name.startswith("pg_"):  # literal prefix, not LIKE 'pg_%'
            continue
        login = _need(row, "roles", "rolcanlogin", bool)
        limit = _need(row, "roles", "rolconnlimit", int)
        if not login:
            if limit == -1:
                info.append({"type": "nologin_information_only", "rolname": name, "rolconnlimit": limit})
            continue
        superuser = _need(row, "roles", "rolsuper", bool)
        entry = {"type": "in_scope", "rolname": name, "rolconnlimit": limit, "rolsuper": superuser,
                 "unlimited": limit == -1, "superuser_limit_not_enforced": superuser,
                 "limit_zero_blocks_login": limit == 0 and not superuser}
        (failing if limit == -1 else passing).append(entry)
    evidence = failing + passing + info
    if failing:
        return _result(ctx, "FAIL", evidence, ["roles"], {"code": "unlimited_connections", "role_count": len(failing)})
    return _result(ctx, "PASS", evidence, ["roles"], {"code": "connection_limits_set", "evidence_count": len(evidence)})


def _replication_roles(ctx: _Context) -> dict:  # 7.1
    evidence = []
    for name, row in sorted(_role_index(ctx).items()):
        repl = _need(row, "roles", "rolreplication", bool)
        superuser = _need(row, "roles", "rolsuper", bool)
        if repl or superuser:
            evidence.append({"type": "replication_role", "rolname": name, "rolreplication": repl,
                             "rolsuper": superuser, "rolcanlogin": _need(row, "roles", "rolcanlogin", bool),
                             "bootstrap_superuser": _is_bootstrap(row)})
    for rule in _hba_rows(ctx, ctx.optional("hba_rules")):
        if "replication" in (rule["database"] or []):
            evidence.append({"type": "replication_hba_rule", **{k: rule[k] for k in
                             ("line_number", "connection_type", "user_name", "auth_method", "has_error")}})
    replication = ctx.optional("replication", dict)
    if replication is not None:
        slots = replication.get("slots")
        if slots is None or ctx.gap_for("replication.slots"):
            ctx.not_collected.append("replication.slots")
        else:
            if not isinstance(slots, list) or not all(isinstance(s, dict) for s in slots):
                raise _field_missing("replication.slots", "row")
            for slot in slots:
                evidence.append({"type": "replication_slot",
                                 "slot_name": _need(slot, "replication.slots", "slot_name", str),
                                 "slot_type": _need(slot, "replication.slots", "slot_type", str, nullable=True),
                                 "database": _need(slot, "replication.slots", "database", str, nullable=True),
                                 "active": _need(slot, "replication.slots", "active", bool, nullable=True)})
        # Optional evidence for 7.1: an unreadable field is shown as not collected.
        if isinstance(replication.get("in_recovery"), bool):
            evidence.append({"type": "recovery_state", "in_recovery": replication["in_recovery"]})
        else:
            ctx.not_collected.append("replication.in_recovery")
        # primary_conninfo_parsed is deliberately not read: the collector's parser
        # is not quote- or URI-aware, so its "user" can hold part of a password.
    return _manual(ctx, evidence, ["roles", "hba_rules", "replication.slots", "replication.in_recovery"])


def _wal_archiving(ctx: _Context) -> dict:  # 7.4
    archiving = ctx.section("archiving", dict)
    mode = _need(archiving, "archiving", "archive_mode", str)
    library = _need(archiving, "archiving", "archive_library", str, nullable=True)
    command_set = _need(archiving, "archiving", "archive_command_is_set", bool)
    library_set = library not in (None, "")
    evidence = {"archive_mode": mode, "archive_library": library, "archive_command_is_set": command_set}
    paths = ["archiving.archive_mode", "archiving.archive_library", "archiving.archive_command_is_set"]

    def out(result: str, code: str, **facts) -> dict:
        return _result(ctx, result, [dict(evidence)], list(paths), {"code": code, **facts})

    if mode not in ARCHIVE_MODES_ENABLED:
        return out("FAIL", "archive_mode_off", archive_mode=mode)
    if not command_set and not library_set:
        return out("FAIL", "archive_destination_missing")
    if command_set and library_set:
        return out("FAIL", "archive_destination_conflict")

    replication = ctx.section("replication", dict)
    in_recovery = _need(replication, "replication", "in_recovery", bool)
    evidence["in_recovery"] = in_recovery
    paths.append("replication.in_recovery")
    if in_recovery:
        return out("MANUAL", "archive_standby")

    stats = _need(archiving, "archiving", "stat_archiver", dict)
    section = "archiving.stat_archiver"
    archived_count = _need(stats, section, "archived_count", int)
    failed_count = _need(stats, section, "failed_count", int)
    for field, count in (("archived_count", archived_count), ("failed_count", failed_count)):
        if count < 0:
            raise _field_missing(section, field)
    raw = {f: _need(stats, section, f, (str, datetime), nullable=True)
           for f in ("last_archived_time", "last_failed_time", "stats_reset")}
    times = {}
    for field, value in raw.items():
        times[field] = _timestamp(value)
        if value is not None and times[field] is None:
            raise _field_missing(section, field)
    shown = {f: (v.isoformat() if isinstance(v, datetime) else v) for f, v in raw.items()}
    evidence.update(archived_count=archived_count, failed_count=failed_count,
                    last_archived_wal=_need(stats, section, "last_archived_wal", str, nullable=True),
                    last_failed_wal=_need(stats, section, "last_failed_wal", str, nullable=True), **shown)
    paths.append(section)
    archived, failed = times["last_archived_time"], times["last_failed_time"]
    if failed is not None and (archived is None or failed > archived):
        return out("FAIL", "archive_latest_failed", last_failed_time=shown["last_failed_time"],
                   last_archived_time=shown["last_archived_time"])

    raw_collected = ctx.envelope.get("collected_at")
    collected = _timestamp(raw_collected)
    if collected is None:
        raise _field_missing("envelope", "collected_at")
    collected_text = raw_collected.isoformat() if isinstance(raw_collected, datetime) else raw_collected
    paths.append("envelope.collected_at")
    max_age = timedelta(hours=WAL_ARCHIVE_MAX_AGE_HOURS)
    if archived is None:
        reset = times["stats_reset"]
        if reset is not None and collected - reset <= max_age:
            return out("MANUAL", "archive_stats_reset_recent", stats_reset=shown["stats_reset"],
                       max_age_hours=WAL_ARCHIVE_MAX_AGE_HOURS)
        if archived_count == 0:
            return out("MANUAL", "archive_never_run", archived_count=archived_count, failed_count=failed_count)
        return out("MANUAL", "archive_timestamp_missing", field="last_archived_time")
    if (archived - collected).total_seconds() > ARCHIVE_FUTURE_TOLERANCE_SECONDS:
        return out("MANUAL", "archive_timestamp_after_collection", field="last_archived_time",
                   collected_at=collected_text)
    if collected - archived > max_age:
        return out("MANUAL", "archive_older_than_max_age", last_archived_time=shown["last_archived_time"],
                   collected_at=collected_text, max_age_hours=WAL_ARCHIVE_MAX_AGE_HOURS)
    return out("PASS", "archive_recent", last_archived_time=shown["last_archived_time"],
               collected_at=collected_text, max_age_hours=WAL_ARCHIVE_MAX_AGE_HOURS)


# ---------------------------------------------------------------------------
# Wave 2b (Gate W2B, rulings 1-9 and round 2): add-ons (F5) and login and
# encryption (F7). Shared rules (E0):
#
# - Settings are read by name from baseline.settings (_setting). A section that
#   was not collected is GAPPED section_not_collected; a sanitised or redacted row
#   is GAPPED redacted_secret_setting; a per-role, database or session source is
#   GAPPED session_override (sources.session_override, the setting-check rule).
# - shared_preload_libraries is split by preload_items, which mirrors PostgreSQL
#   17 SplitDirectoriesString + canonicalize_path. Anything it cannot read for
#   certain is MANUAL preload_list_unparseable, never PASS.
# - connections rows (_read_connections): backend_type NULL means not visible,
#   never "not a client"; rows are never filtered by backend_type before the
#   visibility check; only TCP classes (loopback, private, public) say anything
#   about encryption. A not_visible row or a 'connections.tls' gap makes the TLS
#   part GAPPED connections_not_visible, unless something readable already FAILs.
# ---------------------------------------------------------------------------

# CIS 6.10: the four TLS 1.2 ciphers named in the audit (verbatim quote tokens).
CIS_TLS12_CIPHERS = ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384",
                     "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256")
# OpenSSL's cipher-list separators (ssl_ciph.c ITEM_SEP): colon, space, semicolon, comma.
_CIPHER_SEPARATORS_RE = re.compile(r"[:, ;]")

# pgaudit.log classes (pgaudit 17). 'all' and 'none' are keywords, not classes.
PGAUDIT_LOG_CLASSES = ("read", "write", "function", "role", "ddl", "misc", "misc_set")
PGAUDIT_POLICY_KEY = "pgaudit_log_classes"

TCP_ADDR_CLASSES = ("loopback", "private", "public")
CONNECTION_ADDR_CLASSES = ("not_visible", "unix_socket") + TCP_ADDR_CLASSES
CONNECTIONS_TLS_GAP = "connections.tls"

NON_TLS_HBA_TYPES = ("host", "hostnossl")          # CIS 6.8 query
GSS_HBA_TYPES = ("hostgssenc", "hostnogssenc")     # Gate W2B round 2 ruling 2
LOCAL_OK_METHODS = ("peer", "reject")              # 5.3 highlight: anything else
REMOTE_WEAK_METHODS = ("trust", "password", "ident")  # 5.4: "not to be used for remote logins"

# PostgreSQL scanner_isspace: space, \t, \n, \r, \f (and \v, as in SplitGUCList's callers).
_SCANNER_SPACE = " \t\n\r\f\v"
MAXPGPATH = 1024
# ASCII-only case folding, as pg_strcasecmp and downcase_identifier do for UTF-8:
# str.lower() would fold U+212A KELVIN SIGN onto 'k'.
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def _setting(ctx: _Context, name: str) -> str | None:
    """The server-wide value of a baseline.settings row, or None when there is no row."""
    rows = ctx.rows("settings")
    matches = [r for r in rows if r.get("name") == name]
    if not matches:
        return None
    if len(matches) > 1:  # two rows for one name: the collector contract is broken
        raise _field_missing("settings", name)
    row = matches[0]
    path = [f"settings.{name}"]
    if ("sanitised" in row and row["sanitised"] is not False) or is_redacted(row.get("setting")):
        raise _Gapped({"code": "redacted_secret_setting", "setting_name": name}, path)
    override = session_override(rows, name)
    if override is not None:
        raise _Gapped({"code": "session_override", **override}, path)
    value = row.get("setting")
    if not isinstance(value, str):
        raise _field_missing("settings", name)
    return value


def _required_setting(ctx: _Context, name: str) -> str:
    """Like _setting, but a missing row is GAPPED field_missing (settings.<name>)."""
    value = _setting(ctx, name)
    if value is None:
        raise _field_missing("settings", name)
    return value


def _canonical_library_path(name: str) -> str:
    """The subset of PostgreSQL canonicalize_path that is certain on Linux.

    Duplicate and trailing '/' are removed. A '.' or '..' component, an empty name
    or a name PostgreSQL would truncate is not read (ValueError)."""
    if name == "" or len(name.encode("utf-8")) >= MAXPGPATH:
        raise ValueError("empty or over-long library name")
    parts = name.split("/")
    if any(part in (".", "..") for part in parts):
        raise ValueError("relative path component")
    out = "/".join(p for p in parts if p)
    return "/" + out if name.startswith("/") else out


def preload_items(value: str) -> list[str]:
    """Split shared_preload_libraries the way PostgreSQL 17 does.

    Mirrors SplitDirectoriesString(rawstring, ',') (utils/adt/varlena.c):
    leading and trailing whitespace is skipped; a double-quoted name keeps
    everything inside, with '""' read as '"'; an unquoted name runs to the next
    ',' and loses trailing whitespace (inner spaces stay); names are not
    case-folded; an empty unquoted name (',,', a trailing ',') or text after a
    closing quote is a syntax error. Each name is then canonicalised
    (_canonical_library_path). A control character, a syntax error or a name
    that cannot be canonicalised for certain raises ValueError.
    """
    if not isinstance(value, str):
        raise ValueError("not a string")
    if any((ord(c) < 32 and c not in _SCANNER_SPACE) or ord(c) == 127 for c in value):
        raise ValueError("control character")
    items: list[str] = []
    i, n = 0, len(value)
    while i < n and value[i] in _SCANNER_SPACE:
        i += 1
    if i == n:
        return items
    while True:
        if i == n:
            raise ValueError("empty list element after ','")
        if value[i] == '"':
            chars = []
            i += 1
            while True:
                if i >= n:
                    raise ValueError("unclosed double quote")
                if value[i] == '"':
                    if i + 1 < n and value[i + 1] == '"':
                        chars.append('"')
                        i += 2
                        continue
                    i += 1
                    break
                chars.append(value[i])
                i += 1
            name = "".join(chars)
        else:
            start = end = i
            while i < n and value[i] != ",":
                if value[i] not in _SCANNER_SPACE:
                    end = i + 1
                i += 1
            if end == start:
                raise ValueError("empty list element")
            name = value[start:end]
        while i < n and value[i] in _SCANNER_SPACE:
            i += 1
        items.append(_canonical_library_path(name))
        if i == n:
            return items
        if value[i] != ",":
            raise ValueError("invalid list syntax")
        i += 1
        while i < n and value[i] in _SCANNER_SPACE:
            i += 1


def names_pgaudit(item: str) -> bool:
    """True when the last path part, minus one trailing '.so', is exactly 'pgaudit'."""
    last = item.rsplit("/", 1)[-1]
    return (last[:-3] if last.endswith(".so") else last) == "pgaudit"


def _split_identifier_string(value: str) -> list[str]:
    """PostgreSQL 17 SplitIdentifierString(rawstring, ','), as pgaudit reads pgaudit.log.

    Unquoted names end at ',' or whitespace and are ASCII-downcased; quoted names
    keep their case, with '""' read as '"'. ValueError on a syntax error."""
    if any((ord(c) < 32 and c not in _SCANNER_SPACE) or ord(c) == 127 for c in value):
        raise ValueError("control character")
    names: list[str] = []
    i, n = 0, len(value)
    while i < n and value[i] in _SCANNER_SPACE:
        i += 1
    if i == n:
        return names
    while True:
        if i == n:
            raise ValueError("empty list element after ','")
        if value[i] == '"':
            chars = []
            i += 1
            while True:
                if i >= n:
                    raise ValueError("unclosed double quote")
                if value[i] == '"':
                    if i + 1 < n and value[i + 1] == '"':
                        chars.append('"')
                        i += 2
                        continue
                    i += 1
                    break
                chars.append(value[i])
                i += 1
            name = "".join(chars)
        else:
            start = i
            while i < n and value[i] != "," and value[i] not in _SCANNER_SPACE:
                i += 1
            if i == start:
                raise ValueError("empty list element")
            name = value[start:i].translate(_ASCII_LOWER)
        while i < n and value[i] in _SCANNER_SPACE:
            i += 1
        names.append(name)
        if i == n:
            return names
        if value[i] != ",":
            raise ValueError("invalid list syntax")
        i += 1
        while i < n and value[i] in _SCANNER_SPACE:
            i += 1


def pgaudit_log_classes(value: str) -> list[str]:
    """The classes pgaudit logs for a pgaudit.log value, in PGAUDIT_LOG_CLASSES order.

    pgaudit check_pgaudit_log: words left to right, compared case-insensitively;
    'all' adds every class, 'none' adds nothing, a leading '-' removes. Any other
    word, or a list syntax error, raises ValueError."""
    if not isinstance(value, str):
        raise ValueError("not a string")
    found: set[str] = set()
    for token in _split_identifier_string(value):
        subtract = token.startswith("-")
        word = (token[1:] if subtract else token).translate(_ASCII_LOWER)
        if word == "none":
            bits: set[str] = set()
        elif word == "all":
            bits = set(PGAUDIT_LOG_CLASSES)
        elif word in PGAUDIT_LOG_CLASSES:
            bits = {word}
        else:
            raise ValueError("unknown pgaudit.log class")
        found = found - bits if subtract else found | bits
    return [c for c in PGAUDIT_LOG_CLASSES if c in found]


def pgaudit_policy_classes_error(value: Any) -> str | None:
    """Why value is not a valid pgaudit_log_classes policy value, or None (E9)."""
    if not (isinstance(value, list) and value):
        return "must be a non-empty list of pgaudit.log classes"
    for item in value:
        if not isinstance(item, str) or item not in PGAUDIT_LOG_CLASSES:
            return f"item {item!r} is not one of {PGAUDIT_LOG_CLASSES}"
    if len(set(value)) != len(value):
        return "must not repeat items"
    return None


def _policy_missing(ctx: _Context) -> dict[str, Any]:
    policy = ctx.policy
    case = ("no_profile" if policy is None else
            "profile_unapproved" if getattr(policy, "approved", False) is not True else "no_value_for_spec")
    facts: dict[str, Any] = {"code": "policy_missing", "case": case}
    profile_id = getattr(policy, "profile_id", None)
    if isinstance(profile_id, str) and profile_id:
        facts["profile_id"] = profile_id
    return facts


def _approved_pgaudit_classes(ctx: _Context) -> list[str] | None:
    """pgaudit_log_classes from an APPROVED profile, or None (policy_missing)."""
    policy = ctx.policy
    if policy is None or getattr(policy, "approved", False) is not True:
        return None
    value = getattr(policy, PGAUDIT_POLICY_KEY, None)
    value = list(value) if isinstance(value, (list, tuple)) else value
    if pgaudit_policy_classes_error(value) is not None:
        return None
    return [c for c in PGAUDIT_LOG_CLASSES if c in value]


def _setting_evidence(name: str, value: str | None, **extra) -> dict[str, Any]:
    return {"type": "setting", "setting_name": name, "value": value, **extra}


def _pgaudit_enabled(ctx: _Context) -> dict:  # 3.2
    preload = _required_setting(ctx, "shared_preload_libraries")
    paths = ["settings.shared_preload_libraries"]
    try:
        items = preload_items(preload)
    except ValueError:
        return _result(ctx, "MANUAL", [_setting_evidence("shared_preload_libraries", preload)], paths,
                       {"code": "preload_list_unparseable", "setting_name": "shared_preload_libraries"})
    preloaded = any(names_pgaudit(item) for item in items)
    evidence = [_setting_evidence("shared_preload_libraries", preload, items=items, pgaudit_preloaded=preloaded)]
    if not preloaded:
        return _result(ctx, "FAIL", evidence, paths, {"code": "pgaudit_not_preloaded"})
    paths.append("settings.pgaudit.log")
    log = _setting(ctx, "pgaudit.log")  # GAPPED: redacted row or session_override
    if log is None:
        evidence.append(_setting_evidence("pgaudit.log", None))
        return _result(ctx, "FAIL", evidence, paths, {"code": "pgaudit_log_missing"})
    policy_classes = _approved_pgaudit_classes(ctx)
    if policy_classes is None:
        evidence.append(_setting_evidence("pgaudit.log", log))
        return _result(ctx, "MANUAL", evidence, paths, _policy_missing(ctx))
    try:
        effective = pgaudit_log_classes(log)
    except ValueError:
        evidence.append(_setting_evidence("pgaudit.log", log))
        return _result(ctx, "MANUAL", evidence, paths,
                       {"code": "pgaudit_log_unparseable", "setting_name": "pgaudit.log"})
    evidence.append(_setting_evidence("pgaudit.log", log, effective_classes=effective))
    missing = [c for c in policy_classes if c not in effective]
    facts = {"policy_classes": policy_classes, "effective_classes": effective}
    if missing:
        return _result(ctx, "FAIL", evidence, paths,
                       {"code": "pgaudit_log_classes_missing", **facts, "missing_classes": missing})
    return _result(ctx, "PASS", evidence, paths, {"code": "pgaudit_log_classes_present", **facts})


PASSWORDCHECK_ITEMS = ("passwordcheck", "$libdir/passwordcheck")  # CIS 5.6, exact items


def _password_complexity_module(ctx: _Context) -> dict:  # 5.6
    preload = _required_setting(ctx, "shared_preload_libraries")
    paths = ["settings.shared_preload_libraries"]
    try:
        items = preload_items(preload)
    except ValueError:
        return _result(ctx, "MANUAL", [_setting_evidence("shared_preload_libraries", preload)], paths,
                       {"code": "preload_list_unparseable", "setting_name": "shared_preload_libraries"})
    found = [item for item in items if item in PASSWORDCHECK_ITEMS]
    evidence = [_setting_evidence("shared_preload_libraries", preload, items=items, passwordcheck_items=found)]
    if not found:
        return _result(ctx, "FAIL", evidence, paths, {"code": "passwordcheck_not_preloaded"})
    paths.append("settings.dynamic_library_path")
    path = _required_setting(ctx, "dynamic_library_path")  # GAPPED: session_override
    evidence.append(_setting_evidence("dynamic_library_path", path))
    if path == "$libdir":
        return _result(ctx, "PASS", evidence, paths, {"code": "passwordcheck_preloaded"})
    if "passwordcheck" in found:  # a bare name may load another library from the path
        return _result(ctx, "FAIL", evidence, paths,
                       {"code": "dynamic_library_path_not_libdir", "dynamic_library_path": path})
    return _result(ctx, "MANUAL", evidence, paths,
                   {"code": "libdir_form_with_custom_library_path", "dynamic_library_path": path})


class _Connections:
    """What the connections section says, without deciding the result."""

    def __init__(self) -> None:
        self.collected = False
        self.problem: _Gapped | None = None   # first unreadable-row or section problem
        self.hidden = 0                        # sessions the collector could not see
        self.tls_gap = False
        self.visible: list[dict[str, Any]] = []

    def unknown(self) -> _Gapped | None:
        """The GAPPED reason for the TLS facts, or None when they are complete."""
        if self.problem is not None:
            return self.problem
        if self.hidden or self.tls_gap:
            return _Gapped({"code": "connections_not_visible", "section": "connections",
                            "hidden_connection_count": self.hidden, "tls_details_gap": self.tls_gap},
                           ["connections"])
        return None


def _read_connections(ctx: _Context) -> _Connections:
    """Parse baseline.connections; never raises (6.8 and 6.10 report a FAIL first)."""
    out = _Connections()
    try:
        rows = ctx.section("connections", list)
    except _Gapped as gap:
        ctx.not_collected.append("connections")
        out.problem = gap
        return out
    out.collected = True
    out.tls_gap = ctx.gap_for(CONNECTIONS_TLS_GAP) is not None
    for row in rows:
        try:
            parsed = _connection_row(row)
        except _Gapped as gap:
            out.problem = out.problem or gap
            continue
        if parsed is None:
            count = row.get("connection_count")
            out.hidden += count if isinstance(count, int) and not isinstance(count, bool) and count > 0 else 1
        else:
            out.visible.append(parsed)
    return out


def _connection_row(row: Any) -> dict[str, Any] | None:
    """A visible connection group, or None when the collector could not see it."""
    section = "connections"
    if not isinstance(row, dict):
        raise _field_missing(section, "row")
    backend_type = _need(row, section, "backend_type", str, nullable=True)
    visible = _need(row, section, "visible", bool)
    addr_class = _need(row, section, "client_addr_class", str)
    if addr_class not in CONNECTION_ADDR_CLASSES:
        raise _field_missing(section, "client_addr_class")
    # Visibility first, on every row: a NULL backend_type is a hidden session.
    if backend_type is None or not visible or addr_class == "not_visible":
        return None
    count = _need(row, section, "connection_count", int)
    if count < 1:
        raise _field_missing(section, "connection_count")
    entry = {"backend_type": backend_type,
             "usename": _need(row, section, "usename", str, nullable=True),
             "datname": _need(row, section, "datname", str, nullable=True),
             "client_addr_class": addr_class, "connection_count": count, "tcp": addr_class in TCP_ADDR_CLASSES}
    if not entry["tcp"]:
        return entry  # a Unix socket says nothing about encryption
    entry["ssl"] = _need(row, section, "ssl", bool)
    entry["tls_version"] = _need(row, section, "tls_version", str, nullable=not entry["ssl"])
    entry["tls_cipher"] = _need(row, section, "tls_cipher", str, nullable=not entry["ssl"])
    return entry


def _connection_evidence(row: dict[str, Any], *keys: str) -> dict[str, Any]:
    base = ("backend_type", "usename", "datname", "client_addr_class")
    return {"type": "connection", **{k: row[k] for k in base + keys}, "connection_count": row["connection_count"]}


def _tls_cipher_suites(ctx: _Context) -> dict:  # 6.10
    value = _required_setting(ctx, "ssl_ciphers")
    items = [item for item in _CIPHER_SEPARATORS_RE.split(value) if item]
    other = list(dict.fromkeys(item for item in items if item not in CIS_TLS12_CIPHERS))
    conns = _read_connections(ctx)
    in_use = [r for r in conns.visible if r["tcp"] and r["ssl"] and r["tls_version"] == "TLSv1.2"
              and r["tls_cipher"] not in CIS_TLS12_CIPHERS]
    evidence = [_setting_evidence("ssl_ciphers", value, items=items, other_items=other)]
    evidence += [_connection_evidence(r, "tls_version", "tls_cipher") for r in in_use]
    paths = ["settings.ssl_ciphers", "connections"]
    if other:
        return _result(ctx, "FAIL", evidence, paths, {"code": "unapproved_ciphers_configured", "other_items": other})
    if in_use:
        return _result(ctx, "FAIL", evidence, paths,
                       {"code": "unapproved_cipher_in_use",
                        "connection_count": sum(r["connection_count"] for r in in_use),
                        "ciphers": sorted({r["tls_cipher"] for r in in_use})})
    unknown = conns.unknown()
    if unknown is not None:
        raise unknown
    if not items:
        return _result(ctx, "MANUAL", evidence, paths, {"code": "ssl_ciphers_empty"})
    return _result(ctx, "PASS", evidence, paths, {"code": "approved_ciphers_only"})


def _tls_enabled_and_enforced(ctx: _Context) -> dict:  # 6.8
    failing: list[str] = []
    unknown: list[tuple[str, _Gapped]] = []   # (part, reason) for parts that could not be read
    evidence: list[dict[str, Any]] = []
    try:
        ssl = _required_setting(ctx, "ssl")
        if ssl not in ("on", "off"):
            raise _field_missing("settings", "ssl")
        evidence.append(_setting_evidence("ssl", ssl))
        if ssl == "off":
            failing.append("ssl_off")
    except _Gapped as gap:
        unknown.append(("ssl", gap))
    try:
        rules = _hba_rows(ctx, ctx.section("hba_rules"), extra=("address", "netmask"))
    except _Gapped as gap:
        if gap.explanation["code"] == "section_not_collected":
            ctx.not_collected.append("hba_rules")
        unknown.append(("hba_rules", gap))
        rules = []
    non_tls = [r for r in rules if r["connection_type"] in NON_TLS_HBA_TYPES]
    gss = [r for r in rules if r["connection_type"] in GSS_HBA_TYPES]
    broken = [r for r in rules if r["has_error"]]
    if non_tls:
        failing.append("non_tls_hba_rules")
    conns = _read_connections(ctx)
    unencrypted = [r for r in conns.visible if r["tcp"] and r["ssl"] is False]
    if unencrypted:
        failing.append("unencrypted_tcp_connections")
    if conns.unknown() is not None:
        unknown.append(("connections", conns.unknown()))
    for finding, group in (("non_tls_hba_rule", non_tls), ("gss_hba_rule", gss), ("hba_rule_error", broken)):
        evidence += [{"type": "hba_rule", **r, "finding": finding} for r in group]
    evidence += [{**_connection_evidence(r, "ssl"), "finding": "unencrypted_tcp_connection"} for r in unencrypted]
    paths = ["settings.ssl", "hba_rules", "connections"]
    if failing:
        facts: dict[str, Any] = {"code": "tls_not_enabled_or_enforced", "failing_parts": failing}
        if unknown:
            facts["unknown_parts"] = [part for part, _ in unknown]
        return _result(ctx, "FAIL", evidence, paths, facts)
    if unknown:
        raise unknown[0][1]
    if gss:
        return _manual(ctx, evidence, paths, "gss_hba_rules", rule_count=len(gss))
    if broken:
        return _manual(ctx, evidence, paths, "hba_rule_error", rule_count=len(broken))
    return _result(ctx, "PASS", evidence, paths, {"code": "tls_enabled_and_enforced"})


def _available_extension(ctx: _Context, name: str) -> dict[str, Any]:
    """Evidence row for one pg_available_extensions name (installed_version: connected DB only)."""
    section = "available_extensions"
    found = None
    for row in ctx.rows(section):
        if _need(row, section, "name", str) == name and found is None:
            found = {"default_version": _need(row, section, "default_version", str, nullable=True),
                     "installed_version": _need(row, section, "installed_version", str, nullable=True)}
    database = ctx.envelope.get("database")
    return {"type": "extension", "name": name, "available": found is not None,
            "default_version": found["default_version"] if found else None,
            "installed_version": found["installed_version"] if found else None,
            "database": database if isinstance(database, str) and database else None}


def _extension_facts(row: dict[str, Any]) -> dict[str, Any]:
    return {"extension_name": row["name"], "available": row["available"],
            "default_version": row["default_version"], "installed_version": row["installed_version"],
            "database": row["database"]}


def _membership_path(memberships: list[dict[str, Any]], top: str, target: str) -> list[str]:
    """Shortest path top -> ... -> target down the membership graph (BFS)."""
    parent: dict[str, str | None] = {top: None}
    queue = [top]
    while queue:
        current = queue.pop(0)
        if current == target:
            break
        for row in memberships:
            if _need(row, "role_memberships", "role", str) != current:
                continue
            member = _need(row, "role_memberships", "member", str)
            if member not in parent:
                parent[member] = current
                queue.append(member)
    path, node = [], target
    while node is not None:
        path.append(node)
        node = parent.get(node)
    return path[::-1]


def _set_user_extension(ctx: _Context) -> dict:  # 4.8
    extension = _available_extension(ctx, "set_user")
    facts = _extension_facts(extension)
    paths = ["available_extensions"]
    if not extension["available"]:
        return _result(ctx, "FAIL", [extension], paths, {"code": "set_user_not_available", **facts})
    roles = _role_index(ctx)                  # required from here on: GAPPED if missing
    memberships = ctx.rows("role_memberships")
    paths += ["roles", "role_memberships"]
    ancestors: dict[str, list[str]] = {}
    for name, row in sorted(roles.items()):
        if _need(row, "roles", "rolsuper", bool):
            for member in _members_of(memberships, name):
                ancestors.setdefault(member, []).append(name)
    review = []
    for name in sorted(set(ancestors) | {n for n, r in roles.items() if _need(r, "roles", "rolsuper", bool)}):
        row = roles.get(name)
        if row is None:  # a member the roles list does not have: the list is incomplete
            raise _field_missing("roles", "rolname")
        if not _need(row, "roles", "rolcanlogin", bool):
            continue
        review.append({"type": "superuser_login", "rolname": name,
                       "rolsuper": _need(row, "roles", "rolsuper", bool),
                       "superuser_ancestors": [{"rolname": top, "path": _membership_path(memberships, top, name)}
                                               for top in ancestors.get(name, [])],
                       "bootstrap_superuser": _is_bootstrap(row)})
    evidence = [extension] + review
    if not review:
        return _result(ctx, "PASS", evidence, paths, {"code": "empty_review_set", "evidence_count": 0, **facts})
    return _manual(ctx, evidence, paths, "superuser_login_review", **facts)


def _pgcrypto_extension(ctx: _Context) -> dict:  # 6.11
    extension = _available_extension(ctx, "pgcrypto")
    return _manual(ctx, [extension], ["available_extensions", "envelope.database"],
                   installed_version_scope="connected_database", **_extension_facts(extension))


def _local_hba_rules(ctx: _Context) -> dict:  # 5.3
    raw = ctx.rows("hba_rules")
    # Options are read (and must be well formed) only on the rules shown.
    selected = [{**rule, "options": _hba_options(row)} for row, rule in zip(raw, _hba_rows(ctx, raw))
                if rule["connection_type"] == "local" or rule["has_error"]]
    mappings = None
    if any(o["name"] == "map" for r in selected for o in r["options"]):
        rows = ctx.optional("ident_mappings")
        if rows is not None:
            mappings = []
            for row in rows:
                if not isinstance(row, dict):
                    raise _field_missing("ident_mappings", "row")
                mappings.append({
                    "line_number": _need(row, "ident_mappings", "line_number", int),
                    "map_name": _need(row, "ident_mappings", "map_name", str, nullable=True),
                    "sys_name": _need(row, "ident_mappings", "sys_name", str, nullable=True),
                    "pg_username": _need(row, "ident_mappings", "pg_username", str, nullable=True),
                    "has_error": _need(row, "ident_mappings", "error", str, nullable=True) is not None})
    evidence = []
    for rule in selected:
        highlights = []
        if rule["connection_type"] == "local" and rule["auth_method"] not in LOCAL_OK_METHODS:
            highlights.append("auth_method_not_peer_or_reject")
        if rule["has_error"]:
            highlights.append("line_error")
        entry = {"type": "hba_rule", **rule, "highlights": highlights}
        maps = [o["value"] for o in rule["options"] if o["name"] == "map"]
        if maps:
            entry["ident_mappings"] = (None if mappings is None else
                                       [m for m in mappings if m["map_name"] in maps])
        evidence.append(entry)
    return _manual(ctx, evidence, ["hba_rules", "ident_mappings"],
                   highlight_count=sum(1 for e in evidence if e["highlights"]))


def _is_any_address(rule: dict[str, Any]) -> bool:
    """address 'all', or a netmask of all zero bits (0.0.0.0/0, ::/0) that matches every address."""
    if rule["address"] == "all":
        return True
    try:
        return rule["netmask"] is not None and int(ipaddress.ip_address(rule["netmask"])) == 0
    except ValueError:
        return False


def _host_hba_rules(ctx: _Context) -> dict:  # 5.4
    rules = _hba_rows(ctx, ctx.rows("hba_rules"), extra=("address", "netmask"))
    evidence = []
    for rule in rules:
        host = isinstance(rule["connection_type"], str) and rule["connection_type"].startswith("host")
        if not (host or rule["has_error"]):
            continue
        highlights = []
        if host and rule["auth_method"] in REMOTE_WEAK_METHODS:
            highlights.append("auth_method_not_for_remote")
        if host and rule["auth_method"] == "md5":
            highlights.append("auth_method_md5")
        if host and _is_any_address(rule):
            highlights.append("any_address")
        if rule["has_error"]:
            highlights.append("line_error")
        evidence.append({"type": "hba_rule", **rule, "highlights": highlights})
    return _manual(ctx, evidence, ["hba_rules"], highlight_count=sum(1 for e in evidence if e["highlights"]))


# ---------------------------------------------------------------------------
# Registry. One evaluator serves exactly one recommendation. quote_tokens are
# the CIS words or constants the evaluator hard-codes; validate.py requires each
# to be a whole token in the spec's pass_condition_quote.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CatalogEvaluator:
    function: Callable[[_Context], dict]
    recommendation: str
    tiers: tuple[str, ...]
    required_sections: tuple[str, ...]
    optional_sections: tuple[str, ...] = ()
    quote_tokens: tuple[str, ...] = ()
    # PostgreSQL settings whose value can change this evaluator's inputs. A fixable
    # setting (planning.POLICIES) may be one of these only through a reviewed
    # declaration (planning.CATALOG_FIX_LINKS or CATALOG_INPUT_AFFECTS); every fix of
    # it then re-checks this evaluator for regressions in the sandbox. A unit test
    # enforces it.
    setting_inputs: tuple[str, ...] = ()
    # Policy-profile keys the evaluator reads (only from an APPROVED profile passed
    # to evaluate). Non-empty means the result depends on the profile, which is
    # then pinned in the assessment report (assess.py).
    policy_keys: tuple[str, ...] = ()


_MANUAL = ("manual_checklist",)
_AUTOMATED = ("automated",)
_POLICY = ("parameterised",)

REGISTRY: "MappingProxyType[str, CatalogEvaluator]" = MappingProxyType({
    "roles_with_admin_attributes": CatalogEvaluator(
        _roles_with_admin_attributes, "4.3", _MANUAL, ("roles",)),
    "login_roles": CatalogEvaluator(
        _login_roles, "4.4", _MANUAL, ("roles",), ("password_types",)),
    "elevated_functions": CatalogEvaluator(
        _elevated_functions, "4.5", _MANUAL, ("functions", "databases"), (), ("prosecdef",)),
    "table_dml_grants": CatalogEvaluator(
        _table_dml_grants, "4.6", _MANUAL, ("object_acls", "roles", "role_memberships", "databases")),
    "rls_tables_and_bypass_roles": CatalogEvaluator(
        _rls_tables_and_bypass_roles, "4.7", _MANUAL, ("object_acls", "rls_policies", "roles", "databases"),
        (), ("RLS",)),
    "superuser_roles": CatalogEvaluator(
        _superuser_roles, "4.9", _MANUAL, ("roles",), (), ("superuser",)),
    "login_roles_without_password": CatalogEvaluator(
        _login_roles_without_password, "4.10", _MANUAL, ("roles", "password_types"), ("hba_rules",),
        ("certificate", "GSSAPI", "LDAP"), ("hba_file",)),
    "role_connection_limits": CatalogEvaluator(
        _role_connection_limits, "5.5", _AUTOMATED, ("roles",), (), ("-1",)),
    "replication_roles": CatalogEvaluator(
        _replication_roles, "7.1", _MANUAL, ("roles",), ("hba_rules", "replication"), ("replication",),
        ("hba_file", "primary_conninfo")),
    "wal_archiving": CatalogEvaluator(
        # replication is read only after the configuration FAILs (in_recovery);
        # from that step on it is required and its absence is GAPPED.
        _wal_archiving, "7.4", _AUTOMATED, ("archiving",), ("replication",),
        ("archive_mode", "on", "archive_command", "archive_library"),
        # wal_level is not read, but archive_mode=on needs it at replica or above.
        ("archive_mode", "archive_library", "archive_command", "wal_level")),
    # ---- Wave 2b (Gate W2B) ----
    "pgaudit_enabled": CatalogEvaluator(
        _pgaudit_enabled, "3.2", _POLICY, ("settings",), (), ("pgaudit", "pgaudit.log"),
        ("shared_preload_libraries", "pgaudit.log"), (PGAUDIT_POLICY_KEY,)),
    "password_complexity_module": CatalogEvaluator(
        _password_complexity_module, "5.6", _AUTOMATED, ("settings",), (),
        ("passwordcheck", "$libdir/passwordcheck", "$libdir"),
        ("shared_preload_libraries", "dynamic_library_path")),
    "tls_cipher_suites": CatalogEvaluator(
        # Connections depend on ssl (TLS at all) and ssl_min_protocol_version (whether
        # a TLS 1.2 session can exist), as well as on ssl_ciphers itself.
        _tls_cipher_suites, "6.10", _AUTOMATED, ("settings",), ("connections",),
        CIS_TLS12_CIPHERS + ("TLSv1.2",), ("ssl_ciphers", "ssl", "ssl_min_protocol_version")),
    "tls_enabled_and_enforced": CatalogEvaluator(
        # A client with sslmode=prefer falls back to an unencrypted session when the
        # TLS handshake fails, so the cipher list and minimum protocol can change the
        # established connections this evaluator reads.
        _tls_enabled_and_enforced, "6.8", _AUTOMATED, ("settings",), ("hba_rules", "connections"),
        ("ssl", "off", "host", "hostnossl"), ("ssl", "hba_file", "ssl_ciphers", "ssl_min_protocol_version")),
    "set_user_extension": CatalogEvaluator(
        # roles and role_memberships are read only after the availability FAIL; from
        # that step on they are required and their absence is GAPPED.
        _set_user_extension, "4.8", _AUTOMATED, ("available_extensions",), ("roles", "role_memberships"),
        ("set_user",)),
    "pgcrypto_extension": CatalogEvaluator(
        _pgcrypto_extension, "6.11", _MANUAL, ("available_extensions",), (), ("pgcrypto",)),
    "local_hba_rules": CatalogEvaluator(
        _local_hba_rules, "5.3", _MANUAL, ("hba_rules",), ("ident_mappings",), (), ("hba_file", "ident_file")),
    "host_hba_rules": CatalogEvaluator(
        _host_hba_rules, "5.4", _MANUAL, ("hba_rules",), (), (), ("hba_file",)),
})


def uses_policy_profile(spec: Any) -> bool:
    """True when a catalog spec's evaluator reads a policy-profile key (3.2)."""
    check = spec.get("check") if isinstance(spec, dict) else None
    if not (isinstance(check, dict) and check.get("kind") == "catalog"):
        return False
    entry = REGISTRY.get(check.get("evaluator"))
    return entry is not None and bool(entry.policy_keys)


def evaluate(spec: dict[str, Any], snapshot: dict[str, Any], policy: Any = None) -> dict[str, Any]:
    """Evaluate a validated catalog spec against a v0.3.0-shaped snapshot.

    ``snapshot`` needs ``baseline`` (collector sections) and, for 4.5/4.6/4.7
    and 7.4, ``envelope``. ``policy`` is the PolicyProfile (or None); an
    evaluator with policy_keys (3.2) reads them only when it is approved,
    otherwise the result is MANUAL policy_missing, never PASS. Returns {result,
    evidence, evidence_paths, explanation, notices}; result is PASS, FAIL, MANUAL
    or GAPPED. notices are the fixed NOTICES for the recommendation, present for
    every result.
    """
    check = spec.get("check") or {}
    entry = REGISTRY.get(check.get("evaluator"))
    ref = spec.get("ref") or {}
    if check.get("kind") != "catalog" or entry is None or entry.recommendation != ref.get("recommendation"):
        raise ValueError("spec is not a valid catalog check")
    # Evidence lists are taken from the snapshot; copy so callers cannot mutate it.
    outcome = copy.deepcopy(_evaluate(entry, ref, _Context(spec, snapshot, policy)))
    outcome["notices"] = notices_for(ref.get("recommendation"))
    return outcome


def _evaluate(entry: CatalogEvaluator, ref: dict[str, Any], ctx: _Context) -> dict[str, Any]:
    try:
        identity = ctx.section("identity", dict)
        version = _need(identity, "identity", "server_version_num", int)
        if version // 10000 != ref.get("pg_major"):
            return _result(ctx, "GAPPED", [], ["identity.server_version_num"],
                           {"code": "wrong_pg_major", "spec_pg_major": ref.get("pg_major"),
                            "snapshot_pg_major": version // 10000})
        for name in entry.required_sections:
            ctx.section(name, dict if name in ("archiving", "replication") else list)
        return entry.function(ctx)
    except _Gapped as gap:
        ctx.not_collected = []
        return _result(ctx, "GAPPED", [], gap.paths, gap.explanation)
