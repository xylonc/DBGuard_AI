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
the snapshot's own ``envelope.collected_at``.

This module must not import ``validate`` (validate imports REGISTRY).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any, Callable

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
    def __init__(self, spec: dict[str, Any], snapshot: dict[str, Any]):
        self.spec = spec
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


def _hba_rows(ctx: _Context, rules: list | None) -> list[dict[str, Any]]:
    out = []
    for row in rules or []:
        if not isinstance(row, dict):
            raise _field_missing("hba_rules", "row")
        out.append({
            "line_number": _need(row, "hba_rules", "line_number", int),
            "connection_type": _need(row, "hba_rules", "type", str, nullable=True),
            "database": _str_list(row, "hba_rules", "database", nullable=True),
            "user_name": _str_list(row, "hba_rules", "user_name", nullable=True),
            "auth_method": _need(row, "hba_rules", "auth_method", str, nullable=True),
            "has_error": _need(row, "hba_rules", "error", str, nullable=True) is not None,
        })
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
    # PostgreSQL settings whose value can change this evaluator's inputs. The
    # sandbox only changes settings, so none of these may ever be a fixable
    # setting (planning.POLICIES); a unit test enforces it.
    setting_inputs: tuple[str, ...] = ()


_MANUAL = ("manual_checklist",)
_AUTOMATED = ("automated",)

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
})


def evaluate(spec: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a validated catalog spec against a v0.3.0-shaped snapshot.

    ``snapshot`` needs ``baseline`` (collector sections) and, for 4.5/4.6/4.7
    and 7.4, ``envelope``. Returns {result, evidence, evidence_paths,
    explanation, notices}; result is PASS, FAIL, MANUAL or GAPPED. notices are the
    fixed NOTICES for the recommendation, present for every result.
    """
    check = spec.get("check") or {}
    entry = REGISTRY.get(check.get("evaluator"))
    ref = spec.get("ref") or {}
    if check.get("kind") != "catalog" or entry is None or entry.recommendation != ref.get("recommendation"):
        raise ValueError("spec is not a valid catalog check")
    # Evidence lists are taken from the snapshot; copy so callers cannot mutate it.
    outcome = copy.deepcopy(_evaluate(entry, ref, _Context(spec, snapshot)))
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
