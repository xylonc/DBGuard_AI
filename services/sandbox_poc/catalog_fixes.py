"""Catalog-linked setting fixes (W2B gate 1): CIS 3.2 pgaudit, 5.6 passwordcheck, 6.10 ciphers.

A catalog check (``check.kind: catalog``) normally has no fix: the sandbox only changes
settings, and catalog findings are outside its findings map. The three checks named in
planning.CATALOG_FIX_LINKS are the reviewed exception (Melvin's rulings 2, 3, 4 and 9).

- Values are re-derived here, server-side, from the collected evidence and the approved
  policy profile; a handoff only names the control. Nothing is client-supplied.
- SQL is rendered only by approved templates, one statement per changed setting, and
  parsed back to its typed action: set_config_parameter for pgaudit.log and ssl_ciphers
  (workflow.template_action), set_config_list for shared_preload_libraries
  (workflow.list_template_action).
- The proof is the catalog evaluator itself (catalog_checks.evaluate, with the approved
  policy profile): FAIL on the reproduced source, PASS after the fix, the same FAIL
  after rollback. Other catalog checks that read a changed setting must not regress.

shared_preload_libraries is a GUC_LIST_QUOTE list: a single literal 'a,b' would be stored
as ONE library "a,b" (checked on PostgreSQL 17). So it is written by the reviewed
set_config_list template (W2B rulings round 3), one quoted literal per item: the current
items in order plus the missing library, never a duplicate. Rollback restores the prior
exactly: the same list again when it was set in postgresql.auto.conf (only when that value
is in the canonical form ALTER SYSTEM writes), otherwise RESET.
"""
from __future__ import annotations

import copy
import json
import re
from typing import TypedDict

from jsonschema import Draft202012Validator
from langgraph.graph import END, START, StateGraph

from app.services.fix_unit_render import derive_rollback, render_action_script
from app.services.setting_values import (CIS_SSL_CIPHERS, CIS_TLS12_CIPHERS, SettingValueError,
                                         check_setting_value)
from app.models import preload_library_error
from app.services.spec_engine.redaction import is_redacted
from app.services.spec_engine.sources import SERVER_WIDE_SOURCES

from .planning import CATALOG_FIX_LINKS, CHECKS, POLICIES, grounding, review_floor_and_llm
from .provenance import FILES, reconstruct, reconstruction_plan, setting_rows
from .runtime import DisposablePostgres, SandboxStartError
from .shared import ROOT, ContractError, blocking_gaps, digest

PRELOAD = "shared_preload_libraries"
AUDIT_LOG = "pgaudit.log"
LIBDIR = "$libdir"
SCHEMA_VERSION = "catalog-setting-fix-v1"
TEMPLATE_NAME = "set_config_parameter"
LIST_TEMPLATE = "set_config_list"
# TLS 1.2 ciphers outside the CIS list that the throwaway RSA certificate can negotiate;
# the default ssl_ciphers (HIGH:MEDIUM:+3DES:!aNULL) accepts all three.
WEAK_TLS12_PROBES = ("ECDHE-RSA-AES256-SHA384", "ECDHE-RSA-AES128-SHA256", "AES256-GCM-SHA384")
# The CIS ciphers a self-signed RSA certificate can negotiate (the ECDSA two need an EC key).
CIS_RSA_CIPHERS = tuple(c for c in CIS_TLS12_CIPHERS if "-RSA-" in c)

# Reason codes for the frontend (fix plan "manual_review" items carry reason_code).
REASONS = {
    "not_linked": "This catalog check has no reviewed fix.",
    "evaluator_unavailable": "The catalog evaluator for this check is not installed.",
    "source_not_fail": "The selected control must be a source FAIL.",
    "policy_missing": ("COMPANY POLICY MISSING: approve pgaudit_log_classes in the company policy "
                       "profile before DBGuard can offer the pgaudit fix (policy_missing)."),
    "setting_not_collected": "A setting this fix reads or changes was not collected (or is redacted).",
    "preload_list_unparseable": ("shared_preload_libraries could not be read as a list, so DBGuard "
                                 "cannot compute the new list."),
    "preload_list_unsupported": (
        "shared_preload_libraries lists an entry the reviewed list template cannot write back exactly "
        "(only plain library names and the CIS forms $libdir/pgaudit, pgaudit.so, $libdir/pgaudit.so and "
        "$libdir/passwordcheck, without repeats). Add the library by hand following the CIS remediation, "
        "keeping the existing entries and their order."),
    "preload_prior_unsupported": (
        "shared_preload_libraries is set in postgresql.auto.conf to an empty value or in a form ALTER "
        "SYSTEM would not write back identically, so an exact rollback cannot be rendered. Follow the "
        "CIS remediation."),
    "dynamic_library_path_not_libdir": (
        "dynamic_library_path is not $libdir, so a preloaded passwordcheck cannot satisfy CIS 5.6 (the "
        "bare name may load a different library). DBGuard does not offer this fix; review "
        "dynamic_library_path first."),
    "pgaudit_log_not_reconstructable": (
        "pgaudit.log is set in a configuration file while pgaudit is not loaded, or pgaudit is preloaded "
        "but pgaudit.log was not collected; the sandbox cannot reproduce that state."),
    "fix_does_not_reach_pass": "With the reviewed fix values the CIS check would still not PASS.",
    "ciphers_already_cis_sessions_must_reconnect": (
        "ssl_ciphers already allows only the CIS ciphers; CIS 6.10 fails because established TLS 1.2 "
        "sessions still use other ciphers. Existing sessions keep their cipher until they reconnect, "
        "so no configuration change helps: have those clients reconnect, then collect again."),
    "connections_not_visible": (
        "The collection could not see every session's TLS state (the collecting account needs "
        "pg_read_all_stats, or pg_monitor), so CIS 6.10 stays unknown and DBGuard cannot show that this "
        "fix makes it PASS. Grant the role and collect again."),
}


class CatalogFixRefused(ContractError):
    """No reviewed catalog fix for this evidence; ``code`` is a REASONS key."""

    def __init__(self, code: str, detail: str | None = None):
        super().__init__(REASONS[code] + (f" {detail}" if detail else ""))
        self.code = code


# ---------------------------------------------------------------------------
# Lists and values
# ---------------------------------------------------------------------------

def split_preload_list(value) -> list[str] | None:
    """Items of shared_preload_libraries exactly as the 3.2 and 5.6 evaluators read them
    (catalog_checks.preload_items, PostgreSQL 17 SplitDirectoriesString), or None when
    PostgreSQL would reject the value or the evaluator cannot read it for certain."""
    from app.services.spec_engine.catalog_checks import preload_items
    try:
        return preload_items(value)
    except ValueError:
        return None


def names_library(item: str, library: str) -> bool:
    """Whether a list item counts as library, by the evaluator's own rule: pgaudit as
    catalog_checks.names_pgaudit (pgaudit, $libdir/pgaudit, pgaudit.so); passwordcheck
    only as catalog_checks.PASSWORDCHECK_ITEMS (passwordcheck, $libdir/passwordcheck)."""
    from app.services.spec_engine.catalog_checks import PASSWORDCHECK_ITEMS, names_pgaudit
    if library == "pgaudit":
        return names_pgaudit(item)
    if library == "passwordcheck":
        return item in PASSWORDCHECK_ITEMS
    return False


def _list_text(items: list[str]) -> str:
    """A list the way PostgreSQL writes it (", " separated, quoted unless plain)."""
    return ", ".join(i if re.fullmatch(r"[a-z_][a-z0-9_]*", i) else '"' + i.replace('"', '""') + '"'
                     for i in items)


def appended_preload(current, library: str) -> tuple[list[str], bool]:
    """(new item list, changed): current items in order plus library, never a duplicate.

    Raises CatalogFixRefused when the current list cannot be parsed.
    """
    items = split_preload_list(current)
    if items is None:
        raise CatalogFixRefused("preload_list_unparseable")
    if any(names_library(item, library) for item in items):
        return items, False
    return items + [library], True


def policy_pgaudit_classes(policy) -> tuple[str, ...] | None:
    """pgaudit_log_classes from an APPROVED profile (W2B ruling 2), in the order the
    profile lists them, or None (policy_missing). Validated by the evaluator's own rule
    (catalog_checks.pgaudit_policy_classes_error)."""
    from app.services.spec_engine.catalog_checks import PGAUDIT_POLICY_KEY, pgaudit_policy_classes_error
    if policy is None or getattr(policy, "approved", False) is not True:
        return None
    value = getattr(policy, PGAUDIT_POLICY_KEY, None)
    value = list(value) if isinstance(value, (list, tuple)) else value
    if pgaudit_policy_classes_error(value) is not None:
        return None
    return tuple(value)


# ---------------------------------------------------------------------------
# Scope: the reviewed link, the evidence-derived changes and the planning proof
# ---------------------------------------------------------------------------

def catalog_link(engine, control):
    """(spec, evaluator name, link) when control is a reviewed catalog-linked fix, else None."""
    spec = next((s for s in engine.specs if s["spec_id"] == control), None)
    check = (spec or {}).get("check") or {}
    link = CATALOG_FIX_LINKS.get(check.get("evaluator"))
    if (check.get("kind") != "catalog" or link is None
            or link["recommendation"] != spec.get("ref", {}).get("recommendation")):
        return None
    return spec, check["evaluator"], link


def is_catalog_fix(engine, control) -> bool:
    return catalog_link(engine, control) is not None


def _evaluate(spec, snapshot, policy) -> dict:
    from app.services.spec_engine import catalog_checks
    return catalog_checks.evaluate(spec, snapshot, policy)


def _upstream_row(report: dict, control: str) -> dict | None:
    return next((r for r in (report.get("upstream_report") or {}).get("results", [])
                 if r.get("spec_id") == control), None)


def _row_value(rows: dict, name: str) -> dict:
    row = rows.get(name)
    if row is None or not isinstance(row.get("setting"), str) or row.get("sanitised") or is_redacted(row["setting"]):
        raise CatalogFixRefused("setting_not_collected", f"({name})")
    return row


def _prior(row: dict | None) -> dict | None:
    if row is None:
        return None
    return {"value": row["setting"], "source": row["source"], "sourcefile": row.get("sourcefile"),
            "context": row["context"]}


def _change(param: str, value: str, row: dict | None) -> dict:
    try:
        check_setting_value(param, value)
    except SettingValueError as exc:
        raise ContractError(f"Fix value is outside the reviewed value rule: {exc}") from None
    prior = _prior(row)
    apply = {"action": "set_config", "param": param, "value": value}
    # An absent setting (pgaudit.log before pgaudit loads) is removed again by RESET.
    rollback = derive_rollback(prior, apply) if prior else {"action": "reset_config", "param": param}
    return {"param": param, "template": TEMPLATE_NAME, "value": value, "prior_state": prior,
            "apply": apply, "rollback": rollback}


def preload_rollback(prior: dict | None) -> dict:
    """The exact rollback of a shared_preload_libraries change: the same list again when the
    prior came from postgresql.auto.conf (canonical form only), otherwise RESET."""
    if prior and str(prior.get("sourcefile") or "").endswith("postgresql.auto.conf"):
        items = split_preload_list(prior["value"])
        if not items or _list_text(items) != prior["value"] or any(preload_library_error(i) for i in items):
            raise CatalogFixRefused("preload_prior_unsupported")
        return {"action": "set_config_list", "param": PRELOAD, "values": items}
    return {"action": "reset_config", "param": PRELOAD}


def _list_change(items: list[str], row: dict) -> dict:
    """A shared_preload_libraries change written by the set_config_list template."""
    from app.models import SetConfigListTemplateParams
    if any(preload_library_error(i) for i in items) or len(set(items)) != len(items):
        raise CatalogFixRefused("preload_list_unsupported")
    SetConfigListTemplateParams(param_name=PRELOAD, param_values=list(items))
    prior = _prior(row)
    return {"param": PRELOAD, "template": LIST_TEMPLATE, "values": list(items), "value": _list_text(items),
            "prior_state": prior, "apply": {"action": "set_config_list", "param": PRELOAD, "values": list(items)},
            "rollback": preload_rollback(prior)}


def _file_lines(snapshot: dict, name: str) -> list[dict]:
    return [r for r in snapshot["baseline"].get("file_settings") or [] if r.get("name") == name]


def hypothetical(snapshot: dict, changes: list[dict], tls: bool) -> dict:
    """The source evidence with only the changed settings at their fix values (planning
    proof, never stored). For 6.10, established TLS 1.2 sessions on other ciphers are left
    out (they reconnect after the reload, as the impact text says); nothing else changes."""
    snap = copy.deepcopy(snapshot)
    settings = snap["baseline"]["settings"]
    for change in changes:
        row = next((r for r in settings if r.get("name") == change["param"]), None)
        if row is None:
            row = {"name": change["param"], "unit": None, "category": None, "context": "superuser",
                   "vartype": "string", "sourceline": None, "boot_val": None, "sanitised": False}
            settings.append(row)
        row.update(setting=change["value"], reset_val=change["value"], pending_restart=False)
        # A per-role/database/session source stays: ALTER SYSTEM does not remove that
        # override, so the evaluator must still see it (GAPPED, never PASS).
        if row.get("source") in (None, *SERVER_WIDE_SOURCES):
            row.update(source="configuration file", sourcefile=FILES[1])
    if tls and isinstance(snap["baseline"].get("connections"), list):
        # Established TLS 1.2 sessions keep their cipher until they reconnect (impact text);
        # every other row, hidden rows and gaps stay, so unknown stays unknown.
        snap["baseline"]["connections"] = [
            r for r in snap["baseline"]["connections"]
            if not (isinstance(r, dict) and r.get("ssl") is True and r.get("tls_version") == "TLSv1.2"
                    and r.get("tls_cipher") not in CIS_TLS12_CIPHERS)]
    return snap


def _connections_hidden(snapshot: dict) -> bool:
    """A connections gap (connections.tls without pg_read_all_stats) or hidden session rows."""
    baseline = snapshot["baseline"]
    if any(str((g or {}).get("section", "")).startswith("connections") for g in baseline.get("gaps") or []):
        return True
    rows = baseline.get("connections")
    return not isinstance(rows, list) or any(
        not isinstance(r, dict) or r.get("visible") is not True or r.get("client_addr_class") == "not_visible"
        for r in rows)


def catalog_fix_scope(engine, snapshot: dict, control: str, assessment: dict | None = None) -> dict:
    """The reviewed changes for a catalog-linked control on this evidence, or CatalogFixRefused."""
    linked = catalog_link(engine, control)
    if linked is None:
        raise CatalogFixRefused("not_linked")
    spec, evaluator, link = linked
    from app.services.spec_engine.catalog_checks import REGISTRY
    entry = REGISTRY.get(evaluator)
    if entry is None or not set(link["settings"]) <= set(entry.setting_inputs):
        raise CatalogFixRefused("evaluator_unavailable")
    report = assessment if assessment is not None else engine.assess(snapshot)
    row = _upstream_row(report, control)
    if row is None or row.get("result") != "FAIL":
        raise CatalogFixRefused("source_not_fail")
    rows = setting_rows(snapshot)
    policy = getattr(engine, "policy", None)
    changes, library, preload_present = [], link["library"], False
    if library is not None:
        preload_row = _row_value(rows, PRELOAD)
        if evaluator == "password_complexity_module":
            dlp = _row_value(rows, "dynamic_library_path")
            if dlp["setting"] != LIBDIR:
                raise CatalogFixRefused("dynamic_library_path_not_libdir",
                                        f"(collected value {dlp['setting']!r})")
        items, changed = appended_preload(preload_row["setting"], library)
        preload_present = not changed
        if changed:
            changes.append(_list_change(items, preload_row))
    if evaluator == "pgaudit_enabled":
        classes = policy_pgaudit_classes(policy)
        if classes is None:
            raise CatalogFixRefused("policy_missing")
        audit_row = rows.get(AUDIT_LOG)
        if audit_row is None and (preload_present or _file_lines(snapshot, AUDIT_LOG)):
            raise CatalogFixRefused("pgaudit_log_not_reconstructable")
        if audit_row is not None:
            _row_value(rows, AUDIT_LOG)
        value = ",".join(classes)
        if audit_row is None or audit_row["setting"] != value:
            changes.append(_change(AUDIT_LOG, value, audit_row))
    if evaluator == "tls_cipher_suites":
        # The evaluator's own reading: a FAIL only from established sessions is not fixable here.
        if _evaluate(spec, snapshot, policy)["explanation"].get("code") == "unapproved_cipher_in_use":
            raise CatalogFixRefused("ciphers_already_cis_sessions_must_reconnect")
        if _connections_hidden(snapshot):
            raise CatalogFixRefused("connections_not_visible")
        cipher_row = _row_value(rows, "ssl_ciphers")
        changes.append(_change("ssl_ciphers", CIS_SSL_CIPHERS, cipher_row))
    if not changes:
        raise CatalogFixRefused("fix_does_not_reach_pass", "(nothing to change)")
    for change in changes:
        if change["param"] not in link["settings"] or change["param"] not in POLICIES:
            raise ContractError("Catalog fix changes a setting outside its reviewed link")
    # The one rulebook: the fix values must make the evaluator itself PASS.
    outcome = _evaluate(spec, hypothetical(snapshot, changes, evaluator == "tls_cipher_suites"), policy)
    if outcome["result"] != "PASS":
        raise CatalogFixRefused("fix_does_not_reach_pass",
                                f"(the check would give {outcome['result']}: {outcome['explanation'].get('code')})")
    restart = any(c["param"] == PRELOAD or (rows.get(c["param"]) or {}).get("context") == "postmaster"
                  for c in changes)
    return {"spec": spec, "control": control, "evaluator": evaluator, "link": link, "changes": changes,
            "requires": "restart" if restart else "reload",
            "preload_added": [library] if any(c["param"] == PRELOAD for c in changes) else [],
            "tls": evaluator == "tls_cipher_suites",
            "source_proof": {"result": row["result"], "code": row.get("reason_code")}}


def reconstruction_names(engine, snapshot: dict, scope: dict) -> list[str]:
    """Settings the sandbox must reproduce for this fix: the changed settings and the
    evaluator's setting inputs, where the source has a row (an absent pgaudit.log stays absent)."""
    from app.services.spec_engine.catalog_checks import REGISTRY
    rows = setting_rows(snapshot)
    wanted = [c["param"] for c in scope["changes"]] + list(REGISTRY[scope["evaluator"]].setting_inputs)
    if scope["tls"]:
        # 6.10 (ruling 4): the sandbox switches ssl on with its throwaway certificate, so the
        # source's ssl is the one input not reproduced. Reconstructing it (e.g. ssl = 'off'
        # in postgresql.auto.conf) would override that TLS; 6.10 reads ssl_ciphers and the
        # established connections, not ssl itself.
        wanted = [n for n in wanted if n != "ssl"]
    return [n for n in dict.fromkeys(wanted) if n in rows]


def fix_names(engine, scope: dict, plan: dict) -> list[str]:
    """Names the bundle runner fingerprints: the plan's settings plus every changed setting."""
    return list(dict.fromkeys(plan["names"] + [c["param"] for c in scope["changes"]]))


def catalog_signature(snapshot: dict, names: list[str]) -> dict:
    """provenance.signature that leaves out settings with no pg_settings row (pgaudit.log
    before pgaudit loads), exactly as the bundle runner's fingerprint does."""
    from .provenance import FIELDS, _shadowed_duplicate
    settings = setting_rows(snapshot)
    files = snapshot["baseline"].get("file_settings")
    if files is None:
        raise ContractError("File-setting evidence is missing")
    return {
        "settings": {name: {key: settings[name].get(key) for key in FIELDS}
                     for name in names if name in settings},
        "file_settings": sorted(
            [{k: r.get(k) for k in ("name", "setting", "sourcefile", "applied", "error")}
             for r in files if r.get("name") in names and not _shadowed_duplicate(r, files)],
            key=lambda r: (r["name"], r["sourcefile"], r["setting"])),
    }


_ACTION = None


def _action_validator():
    global _ACTION
    if _ACTION is None:
        schema = json.loads((ROOT / "catalog/specs/contracts/fix-unit-v1.json").read_text())
        _ACTION = Draft202012Validator({"$defs": schema["$defs"], "$ref": "#/$defs/action"})
    return _ACTION


def build_fix(scope: dict, template_version: int, list_template_version: int | None = None) -> dict:
    """The catalog fix record: per changed setting, its template and the typed apply and
    rollback actions (fix-unit-v1 action schema; set_config_list checked by its own schema),
    and the effective value PostgreSQL then shows."""
    from app.models import SetConfigListTemplateParams
    uses_list = any(c["template"] == LIST_TEMPLATE for c in scope["changes"])
    if uses_list != (list_template_version is not None):
        raise ContractError("A shared_preload_libraries change needs exactly the approved set_config_list template")
    fix = {"schema_version": SCHEMA_VERSION, "fix_id": scope["link"]["fix_id"], "spec_id": scope["control"],
           "evaluator": scope["evaluator"], "template_id": TEMPLATE_NAME, "template_version": template_version,
           **({"list_template_id": LIST_TEMPLATE, "list_template_version": list_template_version} if uses_list else {}),
           "changes": [{"param": c["param"], "template": c["template"], "prior_state": c["prior_state"],
                        "apply": c["apply"], "rollback": c["rollback"], "expected_value": c["value"]}
                       for c in scope["changes"]],
           "preload_added": list(scope["preload_added"]), "requires": scope["requires"],
           "verify": {"spec_check_ref": scope["control"], "catalog_evaluator": scope["evaluator"],
                      "expected_result": "PASS"}}
    for change in fix["changes"]:
        if change["template"] == LIST_TEMPLATE:
            if change["param"] != PRELOAD or change["apply"]["action"] != "set_config_list":
                raise ContractError("Only shared_preload_libraries is written by the list template")
            SetConfigListTemplateParams(param_name=PRELOAD, param_values=list(change["apply"]["values"]))
            if change["expected_value"] != _list_text(change["apply"]["values"]):
                raise ContractError("List fix value differs from its items")
            expected = preload_rollback(change["prior_state"])
            if expected["action"] == "set_config_list":
                SetConfigListTemplateParams(param_name=PRELOAD, param_values=list(expected["values"]))
            else:
                _action_validator().validate(change["rollback"])
        else:
            for key in ("apply", "rollback"):
                _action_validator().validate(change[key])
            expected = derive_rollback(change["prior_state"], change["apply"]) if change["prior_state"] else {
                "action": "reset_config", "param": change["param"]}
        if change["rollback"] != expected:
            raise ContractError("Catalog fix rollback differs from the source-aware plan")
    return fix


def needs_list_template(engine, snapshot: dict, control: str, assessment: dict | None = None) -> bool:
    """Whether this catalog fix changes shared_preload_libraries (set_config_list)."""
    scope = catalog_fix_scope(engine, snapshot, control, assessment)
    return any(c["template"] == LIST_TEMPLATE for c in scope["changes"])


def rendered_statements(template, scope: dict, list_template=None) -> list[str]:
    """One approved-template rendering per change, each parsed back to its typed action."""
    from .workflow import list_template_action, template_action
    out = []
    for change in scope["changes"]:
        if change["template"] == LIST_TEMPLATE:
            if list_template is None:
                raise ContractError("This fix needs the approved set_config_list template")
            sql = list_template.render_list(change["param"], change["values"])
            parsed = list_template_action(sql)
        else:
            sql = template.render(change["param"], change["value"])
            parsed = template_action(sql, change["param"])
        if parsed != change["apply"]:
            raise ContractError("Approved template does not render the reviewed catalog fix")
        out.append(sql)
    return out


def rollback_sql(fix: dict) -> str:
    return "\n".join(render_action_script(c["rollback"]) for c in reversed(fix["changes"]))


# ---------------------------------------------------------------------------
# Risk review
# ---------------------------------------------------------------------------

def catalog_risk_review(engine, snapshot, control, reviewer=None, template_risk=None, scope=None):
    scope = scope or catalog_fix_scope(engine, snapshot, control)
    link, changes = scope["link"], scope["changes"]
    primary = changes[0]
    if scope["evaluator"] == "pgaudit_enabled":
        source = {"source": "computed_from_evidence_and_policy_profile", "profile": engine.policy_pin}
    elif scope["preload_added"]:
        source = {"source": "computed_from_evidence"}
    else:
        source = {"source": "reviewed_policy"}
    result = {
        "spec_id": control, "fix_id": link["fix_id"], "kind": "catalog_setting",
        "title": scope["spec"]["ref"]["title"],
        "setting": primary["param"], "settings": [c["param"] for c in changes],
        "current_value": (primary["prior_state"] or {}).get("value"),
        "proposed_value": primary["value"],
        "changes": [{"setting": c["param"], "current_value": (c["prior_state"] or {}).get("value"),
                     "current_source": (c["prior_state"] or {}).get("source", "not defined"),
                     "proposed_value": c["value"]} for c in changes],
        "prior_source": (primary["prior_state"] or {}).get("source"),
        "requires": scope["requires"], "operational_risk": link["risk"],
        "reviewed_risk": link["risk"],
        "risk_basis": "Reviewed catalog-fix risk (W2B gate 1, table E); DBA review required",
        "reasoning": link["impact"], "prerequisites": list(link["prerequisites"]),
        "dependencies": [], "fix_value_source": source,
        "preload_added": list(scope["preload_added"]),
        "proof": (f"CIS {link['recommendation']} check ({scope['evaluator']}) must give PASS on the "
                  "sandbox collection after the fix, and the original FAIL after rollback."),
        "rollback_explanation": ("Remove the added overrides (ALTER SYSTEM RESET) so the previous "
                                 "configuration source takes effect"
                                 + ("; a restart unloads the library." if scope["requires"] == "restart" else ".")),
        "security_severity": "Not assessed",
        "unknowns": ["Application workload and dependencies are not reconstructed in the sandbox."],
        "checks": [{"id": k, **v} for k, v in CHECKS.items()],
        "manual_application_checks": [
            "Run a representative application read and write in a controlled test environment."],
        "llm": {"status": "NOT_CONFIGURED"}, "dba_review_required": True,
        "activation_fact": ("This fix requires a PostgreSQL restart." if scope["requires"] == "restart" else
                            "A reload rereads configuration without restarting PostgreSQL; it applies to new connections."),
        "reference_urls": grounding(primary["param"])[1],
    }
    return review_floor_and_llm(result, primary["param"], reviewer, template_risk)


# ---------------------------------------------------------------------------
# Sandbox rehearsal
# ---------------------------------------------------------------------------

def _absent(snapshot: dict, name: str) -> bool:
    return name not in setting_rows(snapshot) and not _file_lines(snapshot, name)


def proof(engine, spec: dict, snapshot: dict) -> dict:
    outcome = _evaluate(spec, snapshot, getattr(engine, "policy", None))
    return {"result": outcome["result"], "code": (outcome.get("explanation") or {}).get("code")}


def catalog_regressions(engine, before_report: dict, after_report: dict, changed, control) -> list[str]:
    """Other catalog checks that read a changed setting and were PASS before but not after."""
    from app.services.spec_engine.catalog_checks import REGISTRY
    readers = {s["spec_id"] for s in engine.specs
               if (s.get("check") or {}).get("kind") == "catalog" and s["spec_id"] != control
               and set(changed) & set(getattr(REGISTRY.get(s["check"].get("evaluator")), "setting_inputs", ()))}
    before = {r["spec_id"]: r["result"] for r in before_report["upstream_report"]["results"]}
    after = {r["spec_id"]: r["result"] for r in after_report["upstream_report"]["results"]}
    return sorted(sid for sid in readers if before.get(sid) == "PASS" and after.get(sid) != "PASS")


def enable_sandbox_tls(runtime, plan: dict) -> None:
    """Throwaway in-sandbox TLS for the 6.10 rehearsal (ruling 4). Refused when the
    reconstructed source settings would override or disable it: an ssl line written by
    reconstruction (postgresql.auto.conf beats the postgresql.conf line enable_tls adds)
    or a minimum protocol above TLS 1.2."""
    if "ssl" in plan["names"] or any(e["name"] == "ssl" for e in plan["entries"]):
        raise ContractError("The source's ssl setting is reconstructed in the sandbox and would "
                            "override the throwaway TLS; the cipher handshake cannot be rehearsed")
    if plan["expected"].get("ssl_min_protocol_version") == "TLSv1.3":
        raise ContractError("ssl_min_protocol_version is TLSv1.3 in the source, so no TLS 1.2 "
                            "handshake can be rehearsed")
    runtime.enable_tls()


def tls_evidence(runtime) -> dict:
    """Handshake facts over loopback inside the sandbox; no key or certificate material."""
    return {"negotiated": runtime.tls_probe("TLSv1.2"),
            "weak_accepted": {c: runtime.tls_accepts_cipher(c) for c in WEAK_TLS12_PROBES},
            "cis_accepted": {c: runtime.tls_accepts_cipher(c) for c in CIS_RSA_CIPHERS}}


def tls_fixed(evidence: dict) -> bool:
    return (evidence["negotiated"]["cipher"] in CIS_TLS12_CIPHERS
            and not any(evidence["weak_accepted"].values()) and all(evidence["cis_accepted"].values()))


def functional_checks(runtime, fix: dict, phase: str) -> dict:
    from .workflow import health_queries
    result = health_queries(runtime, phase)
    for change in fix["changes"]:
        name = change["param"]
        if not re.fullmatch(r"[a-z_][a-z0-9_.]*", name):
            raise ContractError("Unsupported setting name")
        output = runtime.sql(f"SHOW {name};")
        result["query_evidence"]["queries"].append(
            {"id": "setting", "title": "Effective setting in a fresh connection", "query": f"SHOW {name};",
             "expected": change["expected_value"], "output": output, "passed": output == change["expected_value"]})
    result["passed"] = all(q["passed"] for q in result["query_evidence"]["queries"])
    return result


class _State(TypedDict):
    attempts: list[dict]
    done: bool
    status: str
    revisions: list[dict]


class CatalogFixLoop:
    """Rehearse one catalog-linked setting fix (3.2, 5.6, 6.10) in a disposable sandbox.

    fresh sandbox -> reconstruct settings (+ throwaway TLS for 6.10) -> reproduce (catalog
    check FAIL, findings and provenance equal the source) -> apply every change, one
    reload or controlled restart -> catalog check PASS, health, no regressions -> roll back
    -> exact provenance, absent settings absent again, the same FAIL -> cleanup.
    A failed start (SandboxStartError) ends the attempt without rollback SQL.
    """

    def __init__(self, engine, template, runtime_factory=DisposablePostgres, max_attempts: int = 3,
                 control_id: str | None = None, list_template=None):
        if type(max_attempts) is not int or not 1 <= max_attempts <= 3:
            raise ContractError("Attempt limit must be 1, 2 or 3")
        self.engine, self.template, self.runtime_factory = engine, template, runtime_factory
        self.max_attempts, self.control_id, self.list_template = max_attempts, control_id, list_template

    def prepare(self, snapshot: dict, assessment) -> dict:
        engine = self.engine
        actual = engine.bind_assessment(snapshot, assessment)
        if engine.gapped_settings(actual["findings"]):
            raise ContractError("Cannot establish regression coverage with gapped controls")
        scope = catalog_fix_scope(engine, snapshot, self.control_id, actual)
        plan = reconstruction_plan(snapshot, engine.specs, reconstruction_names(engine, snapshot, scope))
        uses_list = any(c["template"] == LIST_TEMPLATE for c in scope["changes"])
        if uses_list and self.list_template is None:
            raise ContractError("This fix changes shared_preload_libraries and needs the approved "
                                "set_config_list template")
        fix = build_fix(scope, self.template.version, self.list_template.version if uses_list else None)
        rendered = rendered_statements(self.template, scope, self.list_template if uses_list else None)
        absent = [c["param"] for c in fix["changes"] if c["prior_state"] is None]
        if any(not _absent(snapshot, name) for name in absent):
            raise CatalogFixRefused("pgaudit_log_not_reconstructable")
        return {"actual": actual, "scope": scope, "plan": plan, "fix": fix, "rendered": rendered,
                "absent": absent, "names": fix_names(engine, scope, plan)}

    def run(self, snapshot: dict, assessment) -> dict:
        snapshot = copy.deepcopy(snapshot)
        bound = self.prepare(snapshot, assessment)
        engine, control = self.engine, self.control_id
        scope, plan, fix, rendered = bound["scope"], bound["plan"], bound["fix"], bound["rendered"]
        spec, absent, names = scope["spec"], bound["absent"], bound["names"]
        expected_after = {**plan["expected"], **{c["param"]: c["expected_value"] for c in fix["changes"]}}
        source_signature = catalog_signature(snapshot, names)

        def attempt(state: _State):
            runtime = self.runtime_factory()
            record = {"attempt": len(state["attempts"]) + 1, "run_id": runtime.run_id, "status": "FAILED",
                      "phase": "create", "rollback_verified": False, "template": self.template.identity(),
                      "fix_unit_hash": digest(fix), "rendered_apply_sql": "\n".join(rendered)}
            terminal, start_error = False, None
            try:
                runtime.start()
                record["image_id"] = runtime.image_id
                record["phase"] = "reproduce"
                reconstruct(runtime, plan)
                if scope["tls"]:
                    enable_sandbox_tls(runtime, plan)
                before = engine.collect(runtime)
                before_report = engine.assess(before)
                record.update(before=before, before_assessment=before_report)
                record["catalog_proof"] = {"before": proof(engine, spec, before)}
                if catalog_signature(before, names) != source_signature:
                    raise ContractError("Reconstruction did not preserve configuration provenance")
                if before_report["findings"] != bound["actual"]["findings"] or blocking_gaps(before):
                    raise ContractError("Reconstruction did not reproduce all scoped findings")
                if record["catalog_proof"]["before"]["result"] != "FAIL" or any(not _absent(before, n) for n in absent):
                    raise ContractError("The sandbox did not reproduce the source FAIL for this check")
                if scope["tls"]:
                    record["tls_before"] = tls_evidence(runtime)
                record["phase"] = "apply"
                try:
                    for sql in rendered:
                        runtime.sql(sql)
                    runtime.activate(expected_after)
                    record["phase"] = "reassess"
                    after = engine.collect(runtime)
                    after_report = engine.assess(after)
                    record.update(after=after, after_assessment=after_report)
                    record["catalog_proof"]["after"] = proof(engine, spec, after)
                    record["health_after_apply"] = runtime.health()
                    record["functional_checks"] = functional_checks(runtime, fix, "AFTER FIX")
                    if scope["evaluator"] == "pgaudit_enabled":
                        record["pgaudit_log_shown"] = runtime.sql("SHOW pgaudit.log;")
                    if scope["tls"]:
                        record["tls_after"] = tls_evidence(runtime)
                    regressions = [sid for sid, finding in before_report["findings"].items()
                                   if _worse(finding["status"], after_report["findings"][sid]["status"])
                                   or sid in engine.gapped_settings(after_report["findings"])]
                    regressions += catalog_regressions(engine, before_report, after_report,
                                                       [c["param"] for c in fix["changes"]], control)
                    record["regressions"] = regressions
                    if blocking_gaps(after):
                        raise RuntimeError("Post-apply collection has gaps")
                    rows = setting_rows(after)
                    if any((rows.get(c["param"]) or {}).get("pending_restart") is not False for c in fix["changes"]):
                        raise RuntimeError("Fix left a pending restart or a setting was not loaded")
                    if (record["catalog_proof"]["after"]["result"] != "PASS" or regressions
                            or not record["health_after_apply"] or not record["functional_checks"]["passed"]
                            or (scope["tls"] and not tls_fixed(record["tls_after"]))):
                        raise RuntimeError("Fix failed acceptance: catalog check/regression/health/TLS")
                except SandboxStartError as exc:
                    start_error = exc
                    record["apply_or_assessment_error"] = f"SandboxStartError: {exc}"
                    raise
                except Exception as exc:
                    record["apply_or_assessment_error"] = f"{type(exc).__name__}: {exc}"
                    raise
                finally:
                    record["phase_before_rollback"] = record["phase"]
                    if start_error is not None:
                        record["phase"] = "start_failed"
                        from .workflow import ROLLBACK_SKIPPED
                        record["rollback_skipped"] = ROLLBACK_SKIPPED
                    else:
                        record["phase"] = "rollback"
                        runtime.sql(rollback_sql(fix))
                        runtime.activate(plan["expected"])
                        restored = engine.collect(runtime)
                        restored_report = engine.assess(restored)
                        record.update(rollback=restored, rollback_assessment=restored_report,
                                      health_after_rollback=runtime.health())
                        record["catalog_proof"]["rollback"] = proof(engine, spec, restored)
                        if scope["tls"]:
                            record["tls_rollback"] = tls_evidence(runtime)
                        record["rollback_verified"] = bool(
                            catalog_signature(restored, names) == source_signature
                            and restored_report["findings"] == before_report["findings"]
                            and all(_absent(restored, n) for n in absent)
                            and record["catalog_proof"]["rollback"] == record["catalog_proof"]["before"]
                            and (not scope["tls"] or _same_tls(record["tls_rollback"], record["tls_before"]))
                            and not blocking_gaps(restored) and record["health_after_rollback"])
                        if not record["rollback_verified"]:
                            raise RuntimeError("Exact rollback verification failed")
                record.update(status="VERIFIED", phase="complete")
            except SandboxStartError as exc:
                # Deterministic (e.g. a library missing from the image): retrying cannot help.
                terminal = True
                record["error"] = f"SandboxStartError: {exc}"
            except ContractError as exc:
                terminal = True
                record["error"] = str(exc)
            except Exception as exc:
                record["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                try:
                    record["cleanup"] = runtime.close()
                    if record["cleanup"].get("verified") is not True:
                        raise RuntimeError("Cleanup did not confirm resource removal")
                except Exception as exc:
                    terminal = True
                    record["status"] = "CLEANUP_FAILED"
                    record["cleanup"] = {"verified": False, "error": str(exc)}
            attempts = state["attempts"] + [record]
            return {"attempts": attempts, "status": record["status"],
                    "done": terminal or record["status"] == "VERIFIED" or len(attempts) >= self.max_attempts}

        graph = StateGraph(_State)
        graph.add_node("test_fix", attempt)
        graph.add_edge(START, "test_fix")
        graph.add_conditional_edges("test_fix", lambda s: "end" if s["done"] else "retry",
                                    {"end": END, "retry": "test_fix"})
        state = graph.compile().invoke({"attempts": [], "done": False, "status": "PENDING", "revisions": []},
                                       config={"recursion_limit": 12})
        final = state["attempts"][-1]
        return {"schema_version": "sandbox-run-v1", "kind": "catalog_setting", "status": state["status"],
                "snapshot_hash": digest(snapshot), "spec_set_hash": engine.spec_set_hash,
                "spec_hashes": engine.hashes, "collector_hash": engine.collector_hash,
                "policy_profile": engine.policy_pin, "template": self.template.identity(),
                **({"list_template": self.list_template.identity()} if "list_template_id" in fix else {}),
                "fix_unit": fix, "fix_unit_hash": digest(fix), "names": names,
                "rendered_apply_statements": list(rendered), "rendered_apply_sql": "\n".join(rendered),
                "rendered_rollback_sql": rollback_sql(fix), "retry_mode": "repeat", "revisions": [],
                "attempts": state["attempts"], "regression_scope": list(engine.hashes),
                "catalog_proof": final.get("catalog_proof"),
                "limitations": ["PostgreSQL 17; reviewed catalog-linked setting fixes only",
                                "Reconstructs settings in supplied specs and this fix, not the full database",
                                *(["The sandbox TLS uses a throwaway self-signed certificate that never "
                                   "leaves it; the bundle does not switch ssl on (CIS 6.8)"] if scope["tls"] else []),
                                *(["The library must be installed on the target; the sandbox image is not "
                                   "the target's package set"] if scope["preload_added"] else []),
                                "No real-target execution by the sandbox"]}


def _worse(before: str, after: str) -> bool:
    from .shared import is_regression
    return is_regression(before, after)


def _same_tls(now: dict, then: dict) -> bool:
    return now["weak_accepted"] == then["weak_accepted"] and now["cis_accepted"] == then["cis_accepted"]
