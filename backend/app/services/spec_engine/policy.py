"""Policy profile: organisation-chosen values for parameterised specs.

A parameterised spec whose check has ``expected_from: policy`` takes its
expected value, sandbox fix value and break value from an approved profile:

    catalog/policies/<benchmark_id>/reference.yaml
    profile_id: <non-empty string>
    benchmark: <benchmark_id>              # must equal RecordsIndex.benchmark_id
    approved_by: null | <human name>       # only a human sets this
    approved_at: null | <ISO date>         # set together with approved_by
    values:
      <spec_id>: {expected: ..., fix: "...", break: "..."}
    fixes:                                 # optional: site-specific fix values
      <spec_id>: "<value>"                 # for automated specs (e.g. 5.2)
    connection_limits:                     # optional: stored for F6 proposals
      default_login_limit: null | <int >= 0>
      roles: {<rolename>: <int >= 0>}

The profile is pinned by the SHA-256 of the file bytes. The engine never
treats a value as authoritative unless ``approved_by`` is a non-empty string;
an unapproved profile, or one without a value for the spec, gives MANUAL
(reason_code ``policy_missing``), never PASS. Values are validated like spec
proofs: ``fix`` must pass and ``break`` must fail the spec's operator.

``fixes`` holds a sandbox fix value for an AUTOMATED spec whose expected value
comes from CIS but whose fix is site-specific (5.2 listen_addresses: the DBA's
real address). The fix must satisfy the spec operator. Without an approved
profile carrying the value there is no fix at all (planning.fix_scope refuses).
For 5.2 the value rule (setting_values.listen_addresses_error, Gate 1 ruling)
also requires ``localhost`` as one list item, refuses ``*`` and ``0.0.0.0``,
and accepts other items only as IPv4/IPv6 addresses or host names: the sandbox
has only loopback, so PostgreSQL must be able to start on localhost after the
restart (e.g. ``localhost, 10.0.0.5``).

``connection_limits`` is validated, stored and loaded only; nothing reads it yet.

Every fix/break value must also pass the reviewed per-setting value rule
(app.services.setting_values) because it may be rendered into SQL.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .records import RecordsIndex
from .specs import DuplicateKeyLoader
from .validate import OPERATORS, expected_errors, proof_value_errors, uses_policy
from ..setting_values import SettingValueError, check_setting_value

REPO_ROOT = Path(__file__).resolve().parents[4]
PROFILE_KEYS = ("profile_id", "benchmark", "approved_by", "approved_at", "values")
OPTIONAL_PROFILE_KEYS = ("fixes", "connection_limits")
CONNECTION_LIMIT_KEYS = ("default_login_limit", "roles")
# Role names accepted in connection_limits: a plain lower/upper-case identifier of at
# most 63 bytes (PostgreSQL NAMEDATALEN - 1), not a reserved pg_ role.
ROLE_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
VALUE_KEYS = ("expected", "fix", "break")
DEFAULT_PROFILE_NAME = "reference.yaml"
# How a profile approval is authenticated in this build: the approver types a name,
# there is no sign-in. Every output that carries approved_by also carries this label
# (pin(), profile summaries, bundles, batch output, run results) so the approval is
# never read as authenticated outside the UI.
APPROVAL_AUTH = "DEMO_NO_SIGN_IN"
DEMO_APPROVAL_LABEL = "DEMO approval: no sign-in"
APPROVER_MAX = 120
# Approval names must look like a person. These words mark an automated identity
# and are refused outright (whole words, case-insensitive).
NON_HUMAN_WORDS = ("hermes", "mcp", "agent", "model", "llm", "assistant", "claude", "gpt",
                   "chatgpt", "bot", "automated", "automation", "system")
_NON_HUMAN_RE = re.compile(r"\b(" + "|".join(NON_HUMAN_WORDS) + r")\b", re.IGNORECASE)


class PolicyProfileError(ValueError):
    """The profile file is malformed or inconsistent with the specs."""


def approver_name_error(name: Any) -> str | None:
    """Why name cannot be recorded as a human approver, or None if it can.

    Used by the profile store when a human approves in the UI and by parse_profile
    for every profile it reads, including the repository seed.
    """
    if not isinstance(name, str):
        return "Approver name is required"
    name = name.strip()
    if not name or len(name) > APPROVER_MAX:
        return f"Approver name must be 1-{APPROVER_MAX} characters"
    if any(unicodedata.category(c).startswith("C") for c in name):
        return "Approver name must not contain control characters"
    if not any(c.isalpha() for c in name):
        return "Approver name must contain letters"
    if _NON_HUMAN_RE.search(name):
        return "Approval must be recorded under a named human reviewer"
    return None


def profile_pin(profile: "PolicyProfile | None") -> dict[str, Any] | None:
    """The pin of profile, or None."""
    return profile.pin() if profile is not None else None


def approval_text(pin: dict[str, Any] | None) -> str:
    """One human-readable line for a profile pin (report.html, README.txt files)."""
    if not pin:
        return "Policy profile: none"
    line = f"Policy profile: {pin.get('profile_id')} (sha256 {pin.get('sha256')})"
    if pin.get("approved_by"):
        return (f"{line}, approved by {pin['approved_by']} at {pin.get('approved_at')}"
                f" [{DEMO_APPROVAL_LABEL}]")
    return f"{line}, not approved"


@dataclass(frozen=True)
class PolicyProfile:
    profile_id: str
    benchmark: str
    approved_by: str | None
    approved_at: str | None
    values: dict[str, dict[str, Any]]
    sha256: str
    fixes: dict[str, str] = field(default_factory=dict, compare=False)
    connection_limits: dict[str, Any] | None = field(default=None, compare=False)
    source: str = field(default="", compare=False)

    @property
    def approved(self) -> bool:
        return isinstance(self.approved_by, str) and bool(self.approved_by.strip())

    def pin(self) -> dict[str, Any]:
        """What the assessment report, runs and bundles record about the profile.

        approval_auth travels with approved_by everywhere: approvals in this build
        are a typed name without sign-in (APPROVAL_AUTH).
        """
        return {"profile_id": self.profile_id, "sha256": self.sha256,
                "approved_by": self.approved_by, "approved_at": self.approved_at,
                "approval_auth": APPROVAL_AUTH}


def default_profile_path(benchmark_id: str) -> Path:
    return REPO_ROOT / "catalog" / "policies" / benchmark_id / DEFAULT_PROFILE_NAME


def parse_profile(data: bytes, records: RecordsIndex, source: str = "<bytes>") -> PolicyProfile:
    """Parse and shape-check profile bytes. Raises PolicyProfileError."""
    try:
        doc = yaml.load(data.decode("utf-8"), Loader=DuplicateKeyLoader)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PolicyProfileError(f"{source}: cannot load policy profile: {exc}") from exc
    if not isinstance(doc, dict):
        raise PolicyProfileError(f"{source}: policy profile must be a mapping")
    errors: list[str] = []
    for key in PROFILE_KEYS:
        if key not in doc:
            errors.append(f"missing key: {key}")
    for key in doc:
        if key not in PROFILE_KEYS + OPTIONAL_PROFILE_KEYS:
            errors.append(f"unknown key: {key}")

    profile_id = doc.get("profile_id")
    if not (isinstance(profile_id, str) and profile_id.strip()):
        errors.append("profile_id must be a non-empty string")
    if doc.get("benchmark") != records.benchmark_id:
        errors.append(f"benchmark must be {records.benchmark_id!r}, got {doc.get('benchmark')!r}")

    # Approval is a named human. null means unapproved; anything else that is
    # not a non-empty string is refused outright rather than read as either.
    approved_by = doc.get("approved_by")
    if approved_by is not None and not (isinstance(approved_by, str) and approved_by.strip()):
        errors.append(f"approved_by must be null or a non-empty name, got {approved_by!r}")
    elif approved_by is not None:
        # The same human-name rule as a UI approval, for every source (seed included).
        problem = approver_name_error(approved_by)
        if problem is not None:
            errors.append(f"approved_by: {problem}")
    approved_at = doc.get("approved_at")
    if isinstance(approved_at, (_dt.date, _dt.datetime)):
        approved_at = approved_at.isoformat()
    if approved_by is None and approved_at is not None:
        errors.append("approved_at must be null while approved_by is null")
    if approved_by is not None and not (isinstance(approved_at, str) and approved_at.strip()):
        errors.append("approved_at must be an ISO-8601 date when approved_by is set")

    values = doc.get("values")
    if values is None:
        values = {}  # `values:` with nothing under it is an empty profile
    if not isinstance(values, dict):
        errors.append("values must be a mapping of spec_id to {expected, fix, break}")
        values = {}
    for spec_id, entry in values.items():
        where = f"values[{spec_id!r}]"
        if not (isinstance(spec_id, str) and spec_id.startswith(records.benchmark_id + ":")):
            errors.append(f"{where}: spec_id must start with {records.benchmark_id + ':'!r}")
        if not isinstance(entry, dict):
            errors.append(f"{where} must be a mapping with keys {VALUE_KEYS}")
            continue
        for key in VALUE_KEYS:
            if key not in entry:
                errors.append(f"{where}: missing key: {key}")
        for key in entry:
            if key not in VALUE_KEYS:
                errors.append(f"{where}: unknown key: {key}")
        for key in ("fix", "break"):
            if key in entry and not (isinstance(entry[key], str) and entry[key]):
                errors.append(f"{where}.{key} must be a non-empty string")

    fixes = doc.get("fixes")
    if fixes is None:
        fixes = {}
    if not isinstance(fixes, dict):
        errors.append("fixes must be a mapping of spec_id to a fix value string")
        fixes = {}
    for spec_id, value in fixes.items():
        where = f"fixes[{spec_id!r}]"
        if not (isinstance(spec_id, str) and spec_id.startswith(records.benchmark_id + ":")):
            errors.append(f"{where}: spec_id must start with {records.benchmark_id + ':'!r}")
        if not (isinstance(value, str) and value):
            errors.append(f"{where} must be a non-empty string")
        if spec_id in values:
            errors.append(f"{where}: a policy spec takes its fix from values, not fixes")

    connection_limits = doc.get("connection_limits")
    errors.extend(connection_limit_errors(connection_limits))

    if errors:
        raise PolicyProfileError(f"{source}: invalid policy profile: " + "; ".join(errors))
    return PolicyProfile(profile_id=profile_id, benchmark=doc["benchmark"], approved_by=approved_by,
                         approved_at=approved_at, values=values,
                         sha256=hashlib.sha256(data).hexdigest(), source=source,
                         fixes=dict(fixes), connection_limits=connection_limits)


def _is_limit(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def connection_limit_errors(limits: Any) -> list[str]:
    """{default_login_limit: int >= 0 | null, roles: {rolename: int >= 0}} or absent/null."""
    if limits is None:
        return []
    if not isinstance(limits, dict):
        return ["connection_limits must be a mapping with keys default_login_limit and roles"]
    errors = [f"connection_limits: unknown key: {key}" for key in limits if key not in CONNECTION_LIMIT_KEYS]
    errors += [f"connection_limits: missing key: {key}" for key in CONNECTION_LIMIT_KEYS if key not in limits]
    default = limits.get("default_login_limit")
    if default is not None and not _is_limit(default):
        errors.append(f"connection_limits.default_login_limit must be null or an integer >= 0, got {default!r}")
    roles = limits.get("roles")
    if roles is None:
        roles = {}
    if not isinstance(roles, dict):
        errors.append("connection_limits.roles must be a mapping of role name to integer >= 0")
        roles = {}
    for name, limit in roles.items():
        if not (isinstance(name, str) and ROLE_NAME_RE.fullmatch(name)) or str(name).lower().startswith("pg_"):
            errors.append(f"connection_limits.roles: invalid role name {name!r} "
                          "(letters, digits and _, at most 63, not starting with pg_)")
        if not _is_limit(limit):
            errors.append(f"connection_limits.roles[{name!r}] must be an integer >= 0, got {limit!r}")
    return errors


def load_profile(path: Path, records: RecordsIndex) -> PolicyProfile:
    return parse_profile(Path(path).read_bytes(), records, str(path))


def load_default_profile(records: RecordsIndex) -> PolicyProfile | None:
    """The installed profile for this benchmark, or None if there is none."""
    path = default_profile_path(records.benchmark_id)
    return load_profile(path, records) if path.is_file() else None


def profile_value_errors(profile: PolicyProfile, specs: list[dict], strict: bool = False) -> list[str]:
    """Check profile values against the specs that use them.

    Every value for a spec in ``specs`` must belong to a spec with
    ``expected_from: policy``, have the operator's expected shape, and its fix
    must pass and break must fail. With ``strict`` (full catalog validation),
    a value for a spec_id that is not in ``specs`` is also an error.
    """
    by_id = {s.get("spec_id"): s for s in specs if isinstance(s, dict)}
    errors: list[str] = []
    for spec_id, entry in profile.values.items():
        where = f"policy values[{spec_id!r}]"
        spec = by_id.get(spec_id)
        if spec is None:
            if strict:
                errors.append(f"{where}: no spec with this spec_id")
            continue
        if not uses_policy(spec):
            errors.append(f"{where}: spec does not take its expected value from policy")
            continue
        check = spec["check"]
        if check.get("operator") not in OPERATORS:
            continue  # the spec itself is invalid; validate_spec reports it
        shape = expected_errors(check["operator"], check.get("setting_name"), entry["expected"],
                                f"{where}.expected")
        if shape:
            errors.extend(shape)
            continue
        for phase in ("break", "fix"):
            errors.extend(proof_value_errors(check, phase, entry[phase], entry["expected"], where))
            errors.extend(_value_rule_errors(check["setting_name"], entry[phase], f"{where}.{phase}"))
    for spec_id, value in profile.fixes.items():
        where = f"policy fixes[{spec_id!r}]"
        spec = by_id.get(spec_id)
        if spec is None:
            if strict:
                errors.append(f"{where}: no spec with this spec_id")
            continue
        if spec.get("tier") != "automated" or not isinstance(spec.get("check"), dict) or uses_policy(spec):
            errors.append(f"{where}: site-specific fixes are only for automated specs with a literal check")
            continue
        if spec["check"].get("operator") not in OPERATORS:
            continue
        # The value rule first: its message says what to change (for 5.2, e.g. that
        # localhost must be listed). A value it refuses is refused whatever the operator says.
        rule_errors = _value_rule_errors(spec["check"]["setting_name"], value, f"{where}")
        errors.extend(rule_errors or proof_value_errors(spec["check"], "fix", value, None, where))
    return errors


def _value_rule_errors(setting_name: str, value: str, where: str) -> list[str]:
    try:
        check_setting_value(setting_name, value)
    except SettingValueError as exc:
        return [f"{where}: {exc}"]
    return []


def policy_entry(spec: dict, profile: PolicyProfile | None) -> dict | None:
    """The approved {expected, fix, break} for a policy spec, or None (policy_missing)."""
    if not uses_policy(spec) or profile is None or not profile.approved:
        return None
    return profile.values.get(spec["spec_id"])


def site_fix(spec: dict, profile: PolicyProfile | None) -> str | None:
    """The approved site-specific fix value for an automated spec, or None (no fix)."""
    if uses_policy(spec) or profile is None or not profile.approved:
        return None
    return profile.fixes.get(spec["spec_id"])
