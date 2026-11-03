"""Per-object fix proposals for the F6 catalog checks (Wave 2a; Gate 1 rulings 30 Oct 2026).

Pure functions, no Docker, no clock, no I/O beyond reading the bundled template
files for a dry render. Every proposal is derived ONLY from:

- the collected catalog evidence in the snapshot (the catalog_checks evaluators
  and their evidence shapes, plus ``_parse_aclitem``), and
- for CIS 5.5, the ``connection_limits`` of the engine's APPROVED policy profile.

A client sends only a ``fix_id``; ``resolve`` re-derives the proposal from the
same snapshot and profile, so names, values and parameters are never taken
from a request or from model output. SQL comes only from the approved,
hash-pinned template for the fix type (``render``), with identifiers through
``ident`` and argument types from the reviewed built-in allowlist.

Catalog specs still carry no proof (validate.py): fixes come from here, never
from a spec.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

from app.models import (DML_PRIVILEGE_ORDER, FUNCTION_ARG_MODES, FUNCTION_ARG_RE,
                        FUNCTION_ARG_TYPES, ROLE_ATTRIBUTES, pg_identifier)
from app.services.spec_engine.catalog_checks import (BOOTSTRAP_SUPERUSER_OID, DML_PRIVILEGES,
                                                     TABLE_KINDS, _parse_aclitem)
from app.services.spec_engine.catalog_checks import evaluate as evaluate_catalog
from app.services.template_service import safe_render_template

from . import catalog_skeleton
from .handoff import OBJECT_FIX_ID_PATTERN
from .shared import ROOT, ContractError

TEMPLATE_DIR = ROOT / "backend" / "app" / "templates"


@dataclass(frozen=True)
class FixType:
    template: str                      # approved registry name and template file stem
    recommendations: tuple[str, ...]   # CIS recommendations this fix type serves
    risk: str                          # reviewed operational risk (Gate 1 table A)
    explanation: str                   # plain-language effect shown to the DBA


# Gate 1 table A, ruled 30 Oct 2026 ("Accept all"). The AI review may only raise
# these. function_revoke_public_execute was ruled "medium-high"; the stored level
# is "high", the conservative end, because the risk scale has no medium-high.
FIX_TYPES: "MappingProxyType[str, FixType]" = MappingProxyType({
    "role_connection_limit": FixType(
        "role_connection_limit", ("5.5",), "medium",
        "Sets a per-account connection limit from your approved company policy. Too low a limit "
        "refuses new connections for this account. Superusers ignore connection limits."),
    "role_drop_attribute": FixType(
        "role_drop_attribute", ("4.3", "4.9"), "high",
        "Removes one administrative power from this account. Tools or applications that use that "
        "power fail. Removing REPLICATION stops streaming replication that uses the account; "
        "removing BYPASSRLS can hide rows from reports."),
    "role_nologin": FixType(
        "role_nologin", ("4.4", "4.10"), "high",
        "Stops this account from logging in. Anything still using the account stops working. "
        "No password is set or changed."),
    "function_security_invoker": FixType(
        "function_security_invoker", ("4.5",), "high",
        "Makes the function run with the caller's privileges instead of its owner's. Callers "
        "without the owner's privileges get permission errors."),
    "function_revoke_public_execute": FixType(
        "function_revoke_public_execute", ("4.5",), "high",
        "Stops PUBLIC (every account) from running the function. Callers that rely on PUBLIC "
        "access lose it; the DBA grants EXECUTE to specific roles separately."),
    "table_revoke_dml": FixType(
        "table_revoke_dml", ("4.6",), "high",
        "Revokes the listed write privileges on this table from this grantee. Application "
        "writes by that grantee fail."),
})

# role_drop_attribute: template keyword -> pg_roles column.
ATTRIBUTE_COLUMNS = MappingProxyType({
    "SUPERUSER": "rolsuper", "CREATEROLE": "rolcreaterole", "CREATEDB": "rolcreatedb",
    "REPLICATION": "rolreplication", "BYPASSRLS": "rolbypassrls",
})
assert tuple(ATTRIBUTE_COLUMNS) == ROLE_ATTRIBUTES

# Function stubs the sandbox can recreate (catalog_skeleton.STUB_BODIES); a
# function in another language is shown as "can't rehearse".
REHEARSABLE_LANGUAGES = ("sql", "plpgsql")
SYSTEM_SCHEMAS = ("pg_catalog", "information_schema")

# Fixed, reviewed note texts. Never model output.
SUPERUSER_LIMIT_NOTE = "limit not enforced; remove SUPERUSER first (fix #2)"  # ruling 4, verbatim
NOTE_TEXTS = MappingProxyType({
    "bootstrap_superuser": "This is the cluster's bootstrap superuser. DBGuard never offers a fix for it: "
                           "removing its powers or login could lock everyone out.",
    "collecting_role": "DBGuard collects evidence with this account, so it does not offer NOLOGIN or "
                       "removing its powers: the next collection must still work.",
    "collecting_role_unknown": "The snapshot does not say which account collected it, so DBGuard offers "
                               "no NOLOGIN or power-removal fixes for this check.",
    "superuser_limit_not_enforced": SUPERUSER_LIMIT_NOTE,
    "policy_missing": "COMPANY POLICY MISSING: set connection limits on the Policy Profile screen and "
                      "approve the profile.",
    "evidence_not_collected": "The evidence this check needs was not collected, so no fix is offered.",
    "extension_owned": "Owned by an extension, which manages it. DBGuard never offers a fix for it.",
    "extension_evidence_missing": "The snapshot cannot show whether these tables belong to an extension "
                                  "(extensions were not collected), so no table fix is offered.",
    "possibly_extension_owned": "An extension is installed in this table's schema and the snapshot cannot "
                                "show whether the table belongs to it, so no fix is offered.",
    "system_schema": "A function in a system schema. DBGuard never offers a fix for it.",
    "not_a_function": "Not a plain function (procedure, aggregate or window function); no fix is offered.",
    "grantor_not_owner": "Granted by a role other than the owner. A REVOKE by the DBA would not remove "
                         "it, so no fix is offered; review it by hand.",
    "dependent_grants": "This grantee passed the privilege on to others. Revoking it would need CASCADE, "
                        "which DBGuard does not offer; review it by hand.",
    "predefined_role": "A built-in pg_ role. DBGuard never offers a fix for it.",
    "ambiguous_grantee": "A role literally named PUBLIC cannot be told apart from PUBLIC safely; review it "
                         "by hand.",
})

_FIX_ID_RE = re.compile(OBJECT_FIX_ID_PATTERN)
_QUOTED = r'"(?:[^"]|"")+"'
_ARG = FUNCTION_ARG_RE.pattern
_ARGS = rf"\((?:{_ARG}(?:, {_ARG})*)?\)"
_PRIVS = r"(?:INSERT|UPDATE|DELETE)(?:, (?:UPDATE|DELETE)){0,2}"
_ATTRS = "|".join(ROLE_ATTRIBUTES)
# Shape of the one statement each template renders, per (fix type, action).
STATEMENT_SHAPES = MappingProxyType({
    ("role_connection_limit", "apply"): rf"ALTER ROLE {_QUOTED} CONNECTION LIMIT [0-9]+;",
    ("role_connection_limit", "rollback"): rf"ALTER ROLE {_QUOTED} CONNECTION LIMIT -?[0-9]+;",
    ("role_drop_attribute", "apply"): rf"ALTER ROLE {_QUOTED} NO(?:{_ATTRS});",
    ("role_drop_attribute", "rollback"): rf"ALTER ROLE {_QUOTED} (?:{_ATTRS});",
    ("role_nologin", "apply"): rf"ALTER ROLE {_QUOTED} NOLOGIN;",
    ("role_nologin", "rollback"): rf"ALTER ROLE {_QUOTED} LOGIN;",
    ("function_security_invoker", "apply"): rf"ALTER FUNCTION {_QUOTED}\.{_QUOTED}{_ARGS} SECURITY INVOKER;",
    ("function_security_invoker", "rollback"): rf"ALTER FUNCTION {_QUOTED}\.{_QUOTED}{_ARGS} SECURITY DEFINER;",
    ("function_revoke_public_execute", "apply"):
        rf"REVOKE EXECUTE ON FUNCTION {_QUOTED}\.{_QUOTED}{_ARGS} FROM PUBLIC;",
    ("function_revoke_public_execute", "rollback"):
        rf"GRANT EXECUTE ON FUNCTION {_QUOTED}\.{_QUOTED}{_ARGS} TO PUBLIC;",
    ("table_revoke_dml", "apply"): rf"REVOKE {_PRIVS} ON TABLE {_QUOTED}\.{_QUOTED} FROM (?:PUBLIC|{_QUOTED});",
    ("table_revoke_dml", "rollback"):
        rf"GRANT {_PRIVS} ON TABLE {_QUOTED}\.{_QUOTED} TO (?:PUBLIC|{_QUOTED})(?: WITH GRANT OPTION)?;",
})

# Role fields compared for rollback equality (oid is excluded: a stand-in differs).
ROLE_SIGNATURE_FIELDS = ("rolname", "rolsuper", "rolinherit", "rolcreaterole", "rolcreatedb",
                         "rolcanlogin", "rolreplication", "rolbypassrls", "rolconnlimit", "rolvaliduntil")
FUNCTION_SIGNATURE_FIELDS = ("schema", "name", "identity_args", "kind", "owner", "prosecdef")
TABLE_SIGNATURE_FIELDS = ("schema", "name", "kind", "owner", "rls", "rls_forced")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def utc_valid_until(value: Any) -> str | None:
    """rolvaliduntil in one timezone-independent form (UTC, microseconds).

    The collector prints a timestamptz in the server's timezone and the sandbox
    runs in UTC, so the same instant is compared in one form. Same normalisation
    as the bundle fingerprint (review_bundle._valid_until). 'infinity',
    '-infinity' and null are kept; anything unreadable or without a timezone is
    refused (ContractError), never compared as text.
    """
    if value is None or value in ("infinity", "-infinity"):
        return value
    if not isinstance(value, str):
        raise ContractError("Unreadable role expiry")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        raise ContractError("Unreadable role expiry") from None
    if parsed.tzinfo is None:
        raise ContractError("Role expiry has no timezone")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fix_id_for(recommendation: str, fix_type: str, target: dict) -> str:
    """fix-<rec>-<fix_type>-<sha256(canonical target JSON)[:10]>."""
    return f"fix-{recommendation}-{fix_type}-{hashlib.sha256(_canonical(target).encode()).hexdigest()[:10]}"


def _rows(snapshot: Any, name: str) -> list[dict] | None:
    """A collected list section, or None when null, absent, malformed or gapped."""
    baseline = snapshot.get("baseline") if isinstance(snapshot, dict) else None
    if not isinstance(baseline, dict):
        return None
    gaps = baseline.get("gaps") if isinstance(baseline.get("gaps"), list) else []
    if any(isinstance(g, dict) and g.get("section") == name for g in gaps):
        return None
    rows = baseline.get(name)
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        return None
    return rows


def _valid_name(value: Any) -> bool:
    try:
        pg_identifier(value)
        return True
    except ValueError:
        return False


def canonical_arg_types(identity_args: Any) -> list[str] | None:
    """pg_get_function_identity_arguments text -> SQL argument types, or None.

    Accepts only built-in types from app.models.FUNCTION_ARG_TYPES (optionally an
    array), an optional simple lowercase argument name, and VARIADIC of an array.
    Names are dropped (they do not identify a function). The result contains only
    allowlist constants, never text from the evidence.
    """
    if not isinstance(identity_args, str):
        return None
    if identity_args == "":
        return []
    out = []
    for part in identity_args.split(","):
        part = part.strip()
        mode = None
        for candidate in FUNCTION_ARG_MODES:
            if part.startswith(candidate + " "):
                mode, part = candidate, part[len(candidate) + 1:].strip()
        array = part.endswith("[]")
        base = part[:-2] if array else part
        if base not in FUNCTION_ARG_TYPES:
            name, _, rest = part.partition(" ")
            array = rest.endswith("[]")
            base = rest[:-2] if array else rest
            if not re.fullmatch(r"[a-z_][a-z0-9_$]*", name) or base not in FUNCTION_ARG_TYPES:
                return None
        if mode == "VARIADIC" and not array:
            return None
        rendered = ("VARIADIC " if mode else "") + FUNCTION_ARG_TYPES[base] + ("[]" if array else "")
        if not FUNCTION_ARG_RE.fullmatch(rendered):
            return None
        out.append(rendered)
    return out


def _acl_items(acl: Any) -> list[tuple[str, str, str]] | None:
    if not isinstance(acl, list):
        return None
    parsed = [_parse_aclitem(item) for item in acl]
    return None if any(p is None for p in parsed) else parsed


def _held(privs: str) -> dict[str, bool]:
    """DML letters in an aclitem privilege string -> {label: has_grant_option}."""
    out = {}
    for index, char in enumerate(privs):
        if char in DML_PRIVILEGES:
            out[DML_PRIVILEGES[char]] = privs[index + 1:index + 2] == "*"
    return out


def _dry_render(template: str, params: dict) -> bool:
    """Render the bundled (reviewed) template file for both actions; False if refused."""
    try:
        sql = (TEMPLATE_DIR / f"{template}.sql.j2").read_text(encoding="utf-8")
    except OSError:
        return False
    for action in ("apply", "rollback"):
        ok, rendered, _ = safe_render_template(template, sql, {**params, "action": action})
        if not ok:
            return False
        try:
            _statement(template, action, rendered)
        except ContractError:
            return False
    return True


def _statement(fix_type: str, action: str, rendered: str) -> str:
    lines = [line.strip() for line in rendered.splitlines()
             if line.strip() and not line.lstrip().startswith("--")]
    if len(lines) != 1 or not re.fullmatch(STATEMENT_SHAPES[(fix_type, action)], lines[0]):
        raise ContractError("Rendered object fix is outside the reviewed statement shape")
    return lines[0]


# ---------------------------------------------------------------------------
# Proposal derivation
# ---------------------------------------------------------------------------

class _Plan:
    def __init__(self, engine, snapshot: dict):
        self.engine = engine
        self.snapshot = snapshot
        envelope = snapshot.get("envelope") if isinstance(snapshot.get("envelope"), dict) else {}
        # The collecting account (current_user) and, when recorded, the login account
        # (session_user; differs after SET ROLE). Both are protected; an unusable value
        # makes the collector unknown. Older snapshots have no login_role key.
        names = [envelope.get("collected_by")]
        if "login_role" in envelope:
            names.append(envelope.get("login_role"))
        valid = all(isinstance(n, str) and n for n in names)
        self.collectors = frozenset(names) if valid else None
        self.roles = {r.get("rolname"): r for r in _rows(snapshot, "roles") or []
                      if isinstance(r.get("rolname"), str)}
        self.proposals: list[dict] = []
        self.notes: list[dict] = []
        self._noted: set[str] = set()

    def note(self, spec: dict, code: str, target: dict | None = None, **facts) -> None:
        entry = {"spec_id": spec["spec_id"], "code": code, "target": target, "text": NOTE_TEXTS[code], **facts}
        key = _canonical(entry)
        if key not in self._noted:
            self._noted.add(key)
            self.notes.append(entry)

    def propose(self, spec: dict, fix_type: str, target: dict, params: dict, prior: dict, title: str,
                *, reason: str | None = None, note: str | None = None) -> None:
        kind = FIX_TYPES[fix_type]
        rec = spec["ref"]["recommendation"]
        if reason is None and not _dry_render(kind.template, params):
            reason = "An object name cannot be rendered safely by the approved template."
        proposal = {"fix_id": fix_id_for(rec, fix_type, target), "spec_id": spec["spec_id"],
                    "fix_type": fix_type, "target": target, "params": params, "prior": prior,
                    "title": title, "explanation": kind.explanation, "risk": kind.risk}
        if reason is None:
            # Rehearsable only if the stand-in can actually be built: the same
            # check the sandbox runs (catalog_skeleton.plan), so a proposal
            # marked rehearsable is never refused by the stand-in at run time.
            try:
                catalog_skeleton.plan(self.snapshot, [proposal])
            except ContractError as exc:
                reason = str(exc)
        proposal["rehearsable"] = reason is None
        if reason is not None:
            proposal["not_rehearsable_reason"] = reason
        if note is not None:
            proposal["note"] = note
        self.proposals.append(proposal)

    def bootstrap(self, name: str) -> bool:
        row = self.roles.get(name) or {}
        return str(row.get("oid")) == str(BOOTSTRAP_SUPERUSER_OID)

    def role_excluded(self, spec: dict, name: str, removes_access: bool) -> bool:
        """Safety list (Gate 1 C). True when no fix may be offered for this role."""
        if name.startswith("pg_"):
            return True
        if name not in self.roles:
            return True
        if self.bootstrap(name):
            self.note(spec, "bootstrap_superuser", {"role": name})
            return True
        if removes_access:
            if self.collectors is None:
                self.note(spec, "collecting_role_unknown")
                return True
            if name in self.collectors:
                self.note(spec, "collecting_role", {"role": name})
                return True
        # An unrenderable name is still listed, marked not rehearsable by the dry render.
        return False


def _role_attributes(ctx: _Plan, spec: dict, outcome: dict, only: tuple[str, ...]) -> None:  # 4.3, 4.9
    for item in outcome["evidence"]:
        name = item.get("rolname")
        if not isinstance(name, str) or ctx.role_excluded(spec, name, removes_access=True):
            continue
        row = ctx.roles[name]
        for attribute in only:
            column = ATTRIBUTE_COLUMNS[attribute]
            if row.get(column) is not True:
                continue  # only an attribute the evidence shows
            ctx.propose(spec, "role_drop_attribute", {"role": name, "attribute": attribute},
                        {"role_name": name, "attribute": attribute}, {column: True},
                        f"Remove {attribute} from {name}")


def _admin_attributes(ctx, spec, outcome):  # 4.3
    _role_attributes(ctx, spec, outcome, ROLE_ATTRIBUTES)


def _superusers(ctx, spec, outcome):  # 4.9 (only the NOSUPERUSER part; ruling 2)
    _role_attributes(ctx, spec, outcome, ("SUPERUSER",))


def _nologin(ctx: _Plan, spec: dict, outcome: dict) -> None:  # 4.4, 4.10
    for item in outcome["evidence"]:
        name = item.get("rolname")
        if not isinstance(name, str) or ctx.role_excluded(spec, name, removes_access=True):
            continue
        if ctx.roles[name].get("rolcanlogin") is not True:
            continue
        ctx.propose(spec, "role_nologin", {"role": name}, {"role_name": name}, {"rolcanlogin": True},
                    f"Stop {name} from logging in (NOLOGIN)")


def _connection_limits(ctx: _Plan, spec: dict, outcome: dict) -> None:  # 5.5
    policy = getattr(ctx.engine, "policy", None)
    approved = policy is not None and getattr(policy, "approved", False)
    limits = (getattr(policy, "connection_limits", None) or {}) if approved else {}
    per_role = limits.get("roles") or {}
    default = limits.get("default_login_limit")
    missing = []
    for item in outcome["evidence"]:
        name = item.get("rolname")
        if item.get("type") != "in_scope" or item.get("unlimited") is not True or not isinstance(name, str):
            continue
        if ctx.role_excluded(spec, name, removes_access=False):
            continue
        row = ctx.roles[name]
        if row.get("rolsuper") is not False:
            ctx.note(spec, "superuser_limit_not_enforced", {"role": name})
            continue
        limit = per_role.get(name, default) if approved else None
        if type(limit) is not int or limit < 0:
            missing.append(name)
            continue
        source = "role" if name in per_role else "default_login_limit"
        notes = []
        if limit == 0:
            notes.append("A limit of 0 stops this account from logging in at all.")
        if ctx.collectors and name in ctx.collectors:
            notes.append("DBGuard collects with this account; keep the limit above what collection needs.")
        ctx.propose(spec, "role_connection_limit", {"role": name},
                    {"role_name": name, "connection_limit": limit}, {"rolconnlimit": row["rolconnlimit"]},
                    f"Set connection limit {limit} on {name} (from your company policy)",
                    note=" ".join(notes) or None)
        ctx.proposals[-1]["limit_source"] = {"source": source, "profile": ctx.engine.policy_pin}
    if missing:
        ctx.note(spec, "policy_missing", None, roles=sorted(missing))


def _functions(ctx: _Plan, spec: dict, outcome: dict) -> None:  # 4.5
    for row in _rows(ctx.snapshot, "functions") or []:
        if row.get("prosecdef") is not True:
            continue  # CIS 4.5 remediation is about SECURITY DEFINER functions
        schema, name, args = row.get("schema"), row.get("name"), row.get("identity_args")
        if not all(isinstance(v, str) for v in (schema, name, args)):
            continue
        target = {"schema": schema, "name": name, "identity_args": args}
        if row.get("extension") is not None:
            ctx.note(spec, "extension_owned", target, extension=row.get("extension"))
            continue
        if schema in SYSTEM_SCHEMAS:
            ctx.note(spec, "system_schema", target)
            continue
        if row.get("kind") != "f":
            ctx.note(spec, "not_a_function", target, kind=row.get("kind"))
            continue
        arg_types = canonical_arg_types(args)
        reason = None
        if arg_types is None:
            reason = ("An argument type is not a reviewed built-in type, so the sandbox cannot "
                      "recreate the function.")
        elif row.get("language") not in REHEARSABLE_LANGUAGES:
            reason = "The sandbox can only stand in SQL or PL/pgSQL functions."
        elif not _valid_name(row.get("owner")):
            reason = "The owner name cannot be rendered safely."
        params = {"schema_name": schema, "function_name": name, "arg_types": arg_types}
        label = f"{schema}.{name}({args})"
        ctx.propose(spec, "function_security_invoker", dict(target), copy.deepcopy(params), {"prosecdef": True},
                    f"Make {label} SECURITY INVOKER", reason=reason)
        items = _acl_items(row.get("acl"))
        if items is None:
            continue
        public = [(privs, grantor) for grantee, privs, grantor in items if grantee == "" and "X" in privs]
        if not public:
            continue  # only when PUBLIC really has EXECUTE
        if any(grantor != row.get("owner") for _, grantor in public):
            ctx.note(spec, "grantor_not_owner", target, grantee="PUBLIC")
            continue
        ctx.propose(spec, "function_revoke_public_execute", dict(target), copy.deepcopy(params),
                    {"acl": sorted(row["acl"])}, f"Stop PUBLIC from executing {label}", reason=reason)


def _table_dml(ctx: _Plan, spec: dict, outcome: dict) -> None:  # 4.6
    extensions = _rows(ctx.snapshot, "extensions")
    ext_schemas = {e.get("schema") for e in extensions or []}
    for row in _rows(ctx.snapshot, "object_acls") or []:
        if row.get("kind") not in TABLE_KINDS:
            continue
        schema, table, owner = row.get("schema"), row.get("name"), row.get("owner")
        items = _acl_items(row.get("acl"))
        if not all(isinstance(v, str) for v in (schema, table, owner)) or not items:
            continue
        grants = [(g, _held(p), grantor) for g, p, grantor in items if _held(p) and g != owner]
        if not grants:
            continue
        where = {"schema": schema, "table": table}
        # The collector records the owning extension on each object_acls row
        # (pg_depend deptype 'e'). Snapshots from an older collector lack the
        # key; only then does the conservative "any extension in this schema"
        # rule apply.
        if "extension" in row:
            if row["extension"] is not None:
                ctx.note(spec, "extension_owned", where, extension=row["extension"])
                continue
        elif extensions is None:
            ctx.note(spec, "extension_evidence_missing", where)
            continue
        elif schema in ext_schemas:
            ctx.note(spec, "possibly_extension_owned", where)
            continue
        for grantee in sorted({g for g, _, _ in grants}):
            label = "PUBLIC" if grantee == "" else grantee
            target_base = {**where, "grantee": label}
            if grantee == "PUBLIC":
                ctx.note(spec, "ambiguous_grantee", target_base)
                continue
            if grantee.startswith("pg_"):
                ctx.note(spec, "predefined_role", target_base)
                continue
            mine = [(held, grantor) for g, held, grantor in grants if g == grantee]
            if any(grantor != owner for _, grantor in mine):
                ctx.note(spec, "grantor_not_owner", target_base)
                continue
            held = {}
            for privileges, _ in mine:
                held.update(privileges)
            if grantee and any(grantor == grantee and set(_held(p)) & set(held) for _, p, grantor in items):
                ctx.note(spec, "dependent_grants", target_base)
                continue
            reason = None if _valid_name(owner) else "The owner name cannot be rendered safely."
            for option in (False, True):
                privileges = [p for p in DML_PRIVILEGE_ORDER if held.get(p) is option]
                if not privileges:
                    continue
                target = {**target_base, "privileges": privileges, "grant_option": option}
                params = {"schema_name": schema, "table_name": table,
                          "grantee": None if grantee == "" else grantee,
                          "privileges": privileges, "grant_option": option}
                prior = {"acl": sorted(row["acl"]), "privileges": privileges, "grant_option": option}
                ctx.propose(spec, "table_revoke_dml", target, params, prior,
                            f"Revoke {', '.join(privileges)} on {schema}.{table} from {label}", reason=reason)


# CIS recommendation -> builder, in display order.
BUILDERS = (("4.3", _admin_attributes), ("4.4", _nologin), ("4.5", _functions), ("4.6", _table_dml),
            ("4.9", _superusers), ("4.10", _nologin), ("5.5", _connection_limits))


def _catalog_specs(engine) -> dict[str, dict]:
    return {s["ref"]["recommendation"]: s for s in engine.specs
            if (s.get("check") or {}).get("kind") == "catalog"}


def plan(engine, snapshot: dict, profile_pin: dict | None = None) -> dict:
    """{"proposals": [...], "notes": [...]} for every F6 check with a fix type.

    ``profile_pin`` must equal ``engine.policy_pin`` (both None when no profile):
    connection limits are read only from the engine's profile, and only if it is
    approved, so a caller cannot derive proposals against another profile.
    """
    if not isinstance(snapshot, dict):
        raise ContractError("Snapshot is required")
    if profile_pin != getattr(engine, "policy_pin", None):
        raise ContractError("Policy profile pin does not match the assessment's profile")
    ctx = _Plan(engine, snapshot)
    specs = _catalog_specs(engine)
    for rec, builder in BUILDERS:
        spec = specs.get(rec)
        if spec is None:
            continue
        outcome = evaluate_catalog(spec, snapshot)
        if outcome["result"] == "GAPPED":
            ctx.note(spec, "evidence_not_collected", None, explanation=outcome.get("explanation"))
            continue
        builder(ctx, spec, outcome)
    ids = [p["fix_id"] for p in ctx.proposals]
    if len(ids) != len(set(ids)):
        raise ContractError("Object fix ids are not unique")
    return {"proposals": ctx.proposals, "notes": ctx.notes}


def proposals(engine, snapshot: dict, profile_pin: dict | None = None) -> list[dict]:
    return plan(engine, snapshot, profile_pin)["proposals"]


def grouped(engine, snapshot: dict, profile_pin: dict | None = None) -> list[dict]:
    """Fix-plan view: [{spec_id, recommendation, title, proposals, notes}] per F6 spec."""
    result = plan(engine, snapshot, profile_pin)
    out = []
    for rec, spec in sorted(_catalog_specs(engine).items(),
                            key=lambda kv: [int(p) for p in kv[0].split(".") if p.isdigit()]):
        mine = [p for p in result["proposals"] if p["spec_id"] == spec["spec_id"]]
        notes = [n for n in result["notes"] if n["spec_id"] == spec["spec_id"]]
        if mine or notes:
            out.append({"spec_id": spec["spec_id"], "recommendation": rec,
                        "title": spec["ref"].get("title"), "proposals": mine, "notes": notes})
    return out


def resolve(engine, snapshot: dict, profile_pin: dict | None, fix_id: Any) -> dict:
    """Re-derive the proposal for ``fix_id`` from this snapshot and profile."""
    if not isinstance(fix_id, str) or len(fix_id) > 96 or not _FIX_ID_RE.fullmatch(fix_id):
        raise ContractError("Malformed object fix id")
    found = [p for p in proposals(engine, snapshot, profile_pin) if p["fix_id"] == fix_id]
    if len(found) != 1:
        raise ContractError("Unknown object fix id for this snapshot and policy profile")
    return copy.deepcopy(found[0])


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render(proposal: dict, approved_template) -> dict:
    """{apply: [sql], rollback: [sql]} from the approved, hash-pinned template."""
    kind = FIX_TYPES.get(proposal.get("fix_type")) if isinstance(proposal, dict) else None
    if kind is None:
        raise ContractError("Unsupported object fix type")
    if getattr(approved_template, "registry_name", None) != kind.template:
        raise ContractError("The approved template does not match this object fix type")
    if proposal.get("rehearsable") is not True:
        raise ContractError(proposal.get("not_rehearsable_reason") or "This fix cannot be rehearsed")
    params = dict(proposal["params"])
    rollback = dict(params)
    if proposal["fix_type"] == "role_connection_limit":
        rollback["connection_limit"] = proposal["prior"]["rolconnlimit"]
    out = {}
    for action, values in (("apply", params), ("rollback", rollback)):
        rendered = approved_template.render_object({**values, "action": action})
        out[action] = [_statement(proposal["fix_type"], action, rendered)]
    return out


def describe_predicate(proposal: dict) -> str:
    """Plain description of the fixed state checked in re-collected evidence."""
    t, target = proposal["fix_type"], proposal["target"]
    if t == "role_connection_limit":
        return f"pg_roles: rolconnlimit of role {target['role']!r} equals {proposal['params']['connection_limit']}"
    if t == "role_drop_attribute":
        return f"pg_roles: {ATTRIBUTE_COLUMNS[target['attribute']]} of role {target['role']!r} is false"
    if t == "role_nologin":
        return f"pg_roles: rolcanlogin of role {target['role']!r} is false"
    if t.startswith("function_"):
        function = f"{target['schema']!r}.{target['name']!r}({target['identity_args']})"
        if t == "function_security_invoker":
            return f"pg_proc: prosecdef of function {function} is false"
        return f"pg_proc: the ACL of function {function} gives PUBLIC no EXECUTE"
    return (f"pg_class: the ACL of table {target['schema']!r}.{target['table']!r} gives "
            f"{target['grantee']} none of {', '.join(target['privileges'])}")


# ---------------------------------------------------------------------------
# Evidence checks on a (re-)collected snapshot
# ---------------------------------------------------------------------------

def _find(proposal: dict, snapshot: dict) -> dict | None:
    """The target's row in the snapshot; ContractError if its section was not collected."""
    t, target = proposal["fix_type"], proposal["target"]
    if t.startswith("role_"):
        rows = _rows(snapshot, "roles")
        match = lambda r: r.get("rolname") == target["role"]  # noqa: E731
        section = "roles"
    elif t.startswith("function_"):
        rows = _rows(snapshot, "functions")
        match = lambda r: (r.get("schema"), r.get("name"), r.get("identity_args")) == (  # noqa: E731
            target["schema"], target["name"], target["identity_args"])
        section = "functions"
    elif t == "table_revoke_dml":
        rows = _rows(snapshot, "object_acls")
        match = lambda r: (r.get("schema"), r.get("name")) == (target["schema"], target["table"]) \
            and r.get("kind") in TABLE_KINDS  # noqa: E731
        section = "object_acls"
    else:
        raise ContractError("Unsupported object fix type")
    if rows is None:
        raise ContractError(f"Evidence section {section} was not collected")
    found = [r for r in rows if match(r)]
    if len(found) > 1:
        raise ContractError("The target object is listed more than once")
    return found[0] if found else None


def _grantee_privileges(row: dict, grantee: str) -> set[str] | None:
    items = _acl_items(row.get("acl"))
    if items is None:
        return None
    name = "" if grantee == "PUBLIC" else grantee
    return {p for g, privs, _ in items if g == name for p in _held(privs)}


def predicate(proposal: dict, snapshot_after: dict) -> bool:
    """True only when the fixed state is visible in the re-collected evidence."""
    try:
        row = _find(proposal, snapshot_after)
    except ContractError:
        return False
    if row is None:
        return False
    t, target = proposal["fix_type"], proposal["target"]
    if t == "role_connection_limit":
        value = row.get("rolconnlimit")
        return type(value) is int and value == proposal["params"]["connection_limit"]
    if t == "role_drop_attribute":
        return row.get(ATTRIBUTE_COLUMNS[target["attribute"]]) is False
    if t == "role_nologin":
        return row.get("rolcanlogin") is False
    if t == "function_security_invoker":
        return row.get("prosecdef") is False
    if t == "function_revoke_public_execute":
        items = _acl_items(row.get("acl"))
        return items is not None and not any(g == "" and "X" in privs for g, privs, _ in items)
    held = _grantee_privileges(row, target["grantee"])
    return held is not None and not (held & set(target["privileges"]))


def prior_holds(proposal: dict, snapshot: dict) -> bool:
    """True only when the object is exactly as recorded in ``prior``."""
    try:
        row = _find(proposal, snapshot)
    except ContractError:
        return False
    if row is None:
        return False
    prior = proposal["prior"]
    t, target = proposal["fix_type"], proposal["target"]
    if t == "table_revoke_dml":
        acl = row.get("acl")
        if not isinstance(acl, list) or sorted(acl) != prior["acl"]:
            return False
        items = _acl_items(acl)
        name = "" if target["grantee"] == "PUBLIC" else target["grantee"]
        held = {}
        for g, privs, _ in items or []:
            if g == name:
                held.update(_held(privs))
        return all(held.get(p) is prior["grant_option"] for p in prior["privileges"])
    for key, value in prior.items():
        current = row.get(key)
        if key == "acl":
            if not isinstance(current, list) or sorted(current) != value:
                return False
        elif key == "rolvaliduntil":
            try:
                if utc_valid_until(current) != utc_valid_until(value):
                    return False
            except ContractError:
                return False
        elif type(current) is not type(value) or current != value:
            return False
    return True


def object_signature(proposal: dict, snapshot: dict) -> dict:
    """Comparable state of the target object (ACLs as sorted lists; no oid).

    ContractError when the section was not collected, so two gapped snapshots can
    never compare equal. A missing object is {"present": False}.
    """
    row = _find(proposal, snapshot)
    if row is None:
        return {"present": False}
    t = proposal["fix_type"]
    fields = (ROLE_SIGNATURE_FIELDS if t.startswith("role_")
              else FUNCTION_SIGNATURE_FIELDS if t.startswith("function_") else TABLE_SIGNATURE_FIELDS)
    out = {"present": True, **{key: copy.deepcopy(row.get(key)) for key in fields}}
    if t.startswith("role_"):
        out["rolvaliduntil"] = utc_valid_until(out["rolvaliduntil"])
    else:
        acl = row.get("acl")
        out["acl"] = sorted(acl) if isinstance(acl, list) else acl
    return out


def target_verification(proposal: dict, source: dict, applied: dict | None, fresh: dict) -> dict:
    """Step 7 for one object fix: is the fix visible on the freshly collected target?

    ``source`` is the recorded source snapshot, ``applied`` the sandbox snapshot
    after the rehearsed fix (None if the run recorded none) and ``fresh`` the new
    target collection. Verified only when the object predicate holds on the
    target, the target object is exactly in the rehearsed post-fix state, and it
    is no longer in its recorded prior state. Uncollected evidence never verifies.
    """
    out = {"fix_id": proposal.get("fix_id"), "spec_id": proposal.get("spec_id"),
           "predicate": bool(predicate(proposal, fresh)), "matches_applied": False,
           "still_prior": False, "verified": False}
    try:
        current = object_signature(proposal, fresh)
        prior = object_signature(proposal, source)
        out["still_prior"] = current == prior
        if applied is None:
            out["reason"] = "The recorded run has no rehearsed post-fix state"
            return out
        expected = object_signature(proposal, applied)
    except ContractError as exc:
        out["reason"] = str(exc)
        return out
    out["matches_applied"] = current == expected and expected != prior and expected.get("present") is True
    out["verified"] = out["predicate"] and out["matches_applied"] and not out["still_prior"]
    return out
