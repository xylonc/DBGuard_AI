"""Assessment controls generated from the reviewed spec catalog.

The spec YAML files in catalog/specs/<benchmark>/ are the single source of
truth for CIS rules. This module turns each spec into a ControlDefinition so
the offline ASSESS engine (/assessment, HERMES get_snapshot_assessment and
the legacy sandbox) uses exactly the same rule as the sandbox spec engine.

It evaluates a stored collector bundle (pg_settings rows) offline, applying
the spec's own operator and expected value. Evidence that cannot be read as
an exact SHOW value is GAPPED, never PASS, and so is a value set per role,
database or session (pg_settings.source, see spec_engine/sources.py) and a
value the collector redacted because it can carry a secret (spec_engine/redaction.py).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.models import ControlMetadata, Finding, FindingStatus
from app.services.spec_engine import RecordsIndex, load_spec, validate_spec
from app.services.spec_engine.operators import describe_expected, evaluate
from app.services.spec_engine.policy import load_default_profile, policy_entry
from app.services.spec_engine.redaction import is_redacted
from app.services.spec_engine.sources import session_override
from app.services.spec_engine.validate import uses_policy

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BENCHMARK = "cis-pg17-v1.1.0"

# When pg_settings.setting can stand in for the exact SHOW value:
# - bool and enum rows with no unit (as before);
# - string rows, but only for the reviewed PG17 string settings below (vartype
#   verified with pg_settings on PostgreSQL 17.11). Both values come from the same
#   show routine for strings; the allowlist keeps a row that claims the wrong
#   vartype for a bool/enum setting GAPPED.
# Integer and real rows are always GAPPED, even when unitless, and so is any row
# with a unit (log_rotation_age: setting '1440', unit 'min', SHOW '1d'), so a unit
# conversion can never produce a PASS. A row without vartype keeps the historical
# reading of an enum.
SHOW_EQUIVALENT_VARTYPES = ("bool", "enum")
STRING_SETTINGS = frozenset({
    "listen_addresses", "log_destination", "log_directory", "log_filename",
    "log_line_prefix", "log_timezone", "syslog_ident",
})


def _cis(spec: dict) -> dict:
    return {"recommendation": spec["ref"]["recommendation"], "title": spec["ref"]["title"]}


def _gap(spec: dict, rationale: str, explanation: dict, evidence=None, paths=None) -> Finding:
    return Finding(control_id=spec["spec_id"], status=FindingStatus.GAPPED, title=spec["ref"]["title"],
                   rationale=rationale, evidence_found=evidence, control_metadata=None,
                   is_gapped=True, evidence_paths=paths, cis=_cis(spec), explanation=explanation)


def _show_value(snapshot: dict[str, Any], name: str):
    """(value, None) for an exact SHOW-equivalent value, else (None, (rationale, facts, evidence, paths)).

    facts is the structured explanation (code + values) for the UI.
    """
    path = f"settings[name='{name}'].setting"
    settings = snapshot.get("settings")
    if settings is None:
        reason = next((g.get("reason", "unknown") for g in snapshot.get("gaps") or []
                       if isinstance(g, dict) and g.get("section") == "settings"), None)
        detail = (f"gap: {reason}" if reason else
                  "section unavailable without gap record - collector contract violation")
        return None, (f"Collector could not retrieve settings ({detail})",
                      {"code": "not_collected", "setting_name": name, "entry_status": "section_unavailable",
                       "gap_reason": reason if isinstance(reason, str) else None}, None, ["settings"])
    row = next((r for r in settings if isinstance(r, dict) and r.get("name") == name), None)
    if row is None:
        found = [r.get("name") for r in settings if isinstance(r, dict) and r.get("name")]
        return None, (f"{name} is not present in settings list (collector should "
                      "include every spec setting - this indicates collection failure)",
                      {"code": "not_collected", "setting_name": name, "entry_status": "missing"},
                      {"settings_found": found, name: None}, ["settings", path])
    value = row.get("setting")
    vartype = row.get("vartype", "enum")
    readable_type = vartype in SHOW_EQUIVALENT_VARTYPES or (vartype == "string" and name in STRING_SETTINGS)
    if is_redacted(value):
        # Never evaluate an operator on the collector's redaction marker.
        facts = {"code": "redacted_secret_setting", "setting_name": name}
    elif row.get("sanitised") is True:
        facts = {"code": "sanitised", "setting_name": name}
    elif not isinstance(value, str) or row.get("unit") is not None or not readable_type:
        facts = {"code": "unit_or_non_text_value", "setting_name": name,
                 "unit": row.get("unit") if isinstance(row.get("unit"), str) else None,
                 "vartype": vartype if isinstance(vartype, str) else None}
    else:
        override = session_override(settings, name)
        if override is None:
            return value, None
        return None, (f"{name} is set per role, database or session (source '{override['source']}'), "
                      "not server-wide, so the collected value may not be the server's",
                      {"code": "session_override", **override}, {name: None},
                      [path, f"settings[name='{name}'].source"])
    return None, (f"{name} cannot be read as an exact SHOW value from this snapshot",
                  facts, {name: None}, [path])


def _condition_facts(condition: dict) -> dict:
    facts = {key: condition[key] for key in ("setting_name", "operator", "expected", "direction")
             if key in condition}
    facts["condition_quote"] = condition["condition_quote"]
    return facts


def _setting_rule(spec: dict, policy=None):
    spec_id, title, check = spec["spec_id"], spec["ref"]["title"], spec["check"]
    name, pg_major = check["setting_name"], spec["ref"]["pg_major"]
    path = f"settings[name='{name}'].setting"
    condition = spec.get("applies_when")

    def rule(snapshot: dict[str, Any]) -> Finding:
        expected = None
        if uses_policy(spec):
            entry = policy_entry(spec, policy)
            if entry is None:
                case = ("no_profile" if policy is None else
                        "profile_unapproved" if not policy.approved else "no_value_for_spec")
                facts = {"code": "policy_missing", "case": case}
                if policy is not None:
                    facts["profile_id"] = policy.profile_id
                return Finding(control_id=spec_id, status=FindingStatus.MANUAL_REVIEW, title=title,
                               rationale="policy_missing: no approved policy-profile value for this control",
                               evidence_found=None,
                               control_metadata=ControlMetadata(template_id="MANUAL_PROCEDURE", template_version=1,
                                                                is_automatable=False, risk_level="medium",
                                                                requires_dba_review=True),
                               is_gapped=False, cis=_cis(spec), explanation=facts)
            expected = entry["expected"]
        version = (snapshot.get("identity") or {}).get("server_version_num")
        if isinstance(version, int) and version // 10000 != pg_major:
            return _gap(spec, f"Spec applies to PostgreSQL {pg_major}; snapshot is "
                        f"PostgreSQL {version // 10000}",
                        {"code": "wrong_pg_major", "spec_pg_major": pg_major,
                         "snapshot_pg_major": version // 10000},
                        paths=["identity.server_version_num"])
        value, problem = _show_value(snapshot, name)
        if problem:
            rationale, facts, evidence, paths = problem
            return _gap(spec, rationale, {**facts, "evidence": "check"}, evidence, paths)
        if condition is not None:
            cname = condition["setting_name"]
            cpath = f"settings[name='{cname}'].setting"
            cvalue, problem = _show_value(snapshot, cname)
            if problem:
                rationale, facts, evidence, paths = problem
                cause = facts.pop("code")
                facts.pop("setting_name")
                return _gap(spec, f"Applicability unknown: {rationale}",
                            {"code": "condition_unknown", "cause": cause, "evidence": "condition",
                             **_condition_facts(condition), **facts}, evidence, paths)
            try:
                applies = evaluate(condition, cvalue)
            except (TypeError, ValueError):
                return _gap(spec, f"Applicability unknown: {cname} value '{cvalue}' cannot be interpreted",
                            {"code": "condition_unknown", "cause": "uninterpretable_value",
                             "evidence": "condition", **_condition_facts(condition), "actual": cvalue},
                            evidence={cname: cvalue}, paths=[cpath])
            if not applies:
                return Finding(control_id=spec_id, status=FindingStatus.NOT_APPLICABLE, title=title,
                               rationale=f"Not applicable: {cname} is '{cvalue}', the control applies only "
                                         f"when {cname} is {describe_expected(condition)}",
                               evidence_found={cname: cvalue, name: value}, control_metadata=None,
                               is_gapped=False, evidence_paths=[cpath, path], cis=_cis(spec),
                               explanation={"code": "condition_false", **_condition_facts(condition),
                                            "actual": cvalue})
        try:
            ok = evaluate(check, value, expected)
        except (TypeError, ValueError):
            facts = {"code": "uninterpretable_value", "evidence": "check", "setting_name": name,
                     "operator": check["operator"], "actual": value}
            if "direction" in check:
                facts["direction"] = check["direction"]
            return _gap(spec, f"{name} value '{value}' cannot be interpreted by the spec operator",
                        facts, evidence={name: value}, paths=[path])
        if ok:
            return Finding(control_id=spec_id, status=FindingStatus.PASS, title=title,
                           rationale=f"{name} is set to '{value}'", evidence_found={name: value},
                           control_metadata=None, is_gapped=False, evidence_paths=[path])
        return Finding(
            control_id=spec_id, status=FindingStatus.FAIL, title=title,
            rationale=f"{name} is set to '{value}', should be {describe_expected(check, expected)}",
            evidence_found={name: value},
            control_metadata=ControlMetadata(template_id="SET_CONFIG_PARAMETER", template_version=1,
                                             is_automatable=True, risk_level="low",
                                             requires_dba_review=True),
            is_gapped=False, evidence_paths=[path])
    return rule


def _manual_rule(spec: dict):
    spec_id, title = spec["spec_id"], spec["ref"]["title"]

    def rule(snapshot: dict[str, Any]) -> Finding:
        return Finding(control_id=spec_id, status=FindingStatus.MANUAL_REVIEW, title=title,
                       rationale=f"No automated check yet ({spec['tier']}): {spec['reason']}",
                       evidence_found=None,
                       control_metadata=ControlMetadata(template_id="MANUAL_PROCEDURE", template_version=1,
                                                        is_automatable=False, risk_level="medium",
                                                        requires_dba_review=True),
                       is_gapped=False)
    return rule


def load_spec_controls(definition_cls, benchmark_id: str = DEFAULT_BENCHMARK) -> dict:
    """Build ControlDefinitions for every installed spec; invalid specs fail loudly."""
    directory = ROOT / "catalog/specs" / benchmark_id
    records = RecordsIndex.load(ROOT / "catalog/benchmarks" / benchmark_id / "records.json")
    policy = load_default_profile(records)
    controls = {}
    for path in sorted(directory.glob("*.yaml")):
        spec = load_spec(path)
        errors = validate_spec(spec, records)
        if errors:
            raise ValueError(f"Invalid spec {path.name}: {'; '.join(errors)}")
        automated = (spec["tier"] in ("automated", "parameterised")
                     and spec.get("check", {}).get("kind") == "setting")
        ref = spec["ref"]
        controls[spec["spec_id"]] = definition_cls(
            control_id=spec["spec_id"],
            cis_title=f"{ref['recommendation']} {ref['title']}",
            description=f"{ref['benchmark']} v{ref['benchmark_version']} recommendation {ref['recommendation']}",
            severity=None,
            rule_func=(_catalog_rule(spec) if _is_catalog(spec)  # F6 block below
                       else _setting_rule(spec, policy) if automated else _manual_rule(spec)),
            template_id="SET_CONFIG_PARAMETER" if automated else "MANUAL_PROCEDURE",
            template_version=1,
            is_automatable=automated,
            risk_level="low" if automated else "medium",
            requires_dba_review=True,
        )
    if not controls:
        raise ValueError(f"No specs installed for {benchmark_id}")
    return controls


# ---- F6: catalog check kind -------------------------------------------------
# Kept in one block so it rebases cleanly. A catalog finding never maps to a fix
# template: control_metadata is always MANUAL_PROCEDURE, is_automatable False,
# for every status including FAIL.

_CATALOG_STATUS = {"PASS": FindingStatus.PASS, "FAIL": FindingStatus.FAIL,
                   "GAPPED": FindingStatus.GAPPED, "MANUAL": FindingStatus.MANUAL_REVIEW}
_CATALOG_RATIONALE = {
    "PASS": "The catalog check passed on the collected evidence.",
    "FAIL": "The catalog check failed on the collected evidence.",
    "GAPPED": "The evidence this check needs was not collected.",
    "MANUAL": "A person must review the listed evidence.",
}


def _is_catalog(spec: dict) -> bool:
    check = spec.get("check")
    return isinstance(check, dict) and check.get("kind") == "catalog"


def _catalog_rule(spec: dict):
    from app.services.spec_engine import catalog_checks

    spec_id, ref = spec["spec_id"], spec["ref"]

    def rule(snapshot: dict[str, Any]) -> Finding:
        # The offline ASSESS path passes a flat collector bundle (sections at the
        # top level, plus "envelope"); the evaluator expects v0.3.0's baseline.
        if isinstance(snapshot.get("baseline"), dict):
            native = snapshot
        else:
            native = {"envelope": snapshot.get("envelope") or {}, "baseline": snapshot}
        outcome = catalog_checks.evaluate(spec, native)
        result = outcome["result"]
        return Finding(
            control_id=spec_id, status=_CATALOG_STATUS[result], title=ref["title"],
            rationale=" ".join([_CATALOG_RATIONALE[result], *(n["text"] for n in outcome["notices"])]),
            evidence_found=outcome["evidence"],
            control_metadata=ControlMetadata(template_id="MANUAL_PROCEDURE", template_version=1,
                                             is_automatable=False, risk_level="medium",
                                             requires_dba_review=True),
            is_gapped=result == "GAPPED", evidence_paths=outcome["evidence_paths"],
            cis={"recommendation": ref["recommendation"], "title": ref["title"]},
            explanation=outcome["explanation"])
    return rule
