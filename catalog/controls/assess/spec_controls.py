"""Assessment controls generated from the reviewed spec catalog.

The spec YAML files in catalog/specs/<benchmark>/ are the single source of
truth for CIS rules. This module turns each spec into a ControlDefinition so
the offline ASSESS engine (/assessment, HERMES get_snapshot_assessment and
the legacy sandbox) uses exactly the same rule as the sandbox spec engine.

It evaluates a stored collector bundle (pg_settings rows) offline, applying
the spec's own operator and expected value. Evidence that cannot be read as
an exact SHOW value is GAPPED, never PASS.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.models import ControlMetadata, Finding, FindingStatus
from app.services.spec_engine import RecordsIndex, load_spec, validate_spec
from app.services.spec_engine.validate import OPERATORS

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BENCHMARK = "cis-pg17-v1.1.0"


def _expected_text(check: dict) -> str:
    expected, operator = check["expected"], check["operator"]
    if operator == "equals":
        return f"'{expected}'"
    if operator == "not_equals":
        return f"anything other than '{expected}'"
    return "one of " + ", ".join(f"'{value}'" for value in expected)


def _gap(spec_id: str, title: str, rationale: str, evidence=None, paths=None) -> Finding:
    return Finding(control_id=spec_id, status=FindingStatus.GAPPED, title=title,
                   rationale=rationale, evidence_found=evidence, control_metadata=None,
                   is_gapped=True, evidence_paths=paths)


def _setting_rule(spec: dict):
    spec_id, title, check = spec["spec_id"], spec["ref"]["title"], spec["check"]
    name, pg_major = check["setting_name"], spec["ref"]["pg_major"]
    path = f"settings[name='{name}'].setting"

    def rule(snapshot: dict[str, Any]) -> Finding:
        version = (snapshot.get("identity") or {}).get("server_version_num")
        if isinstance(version, int) and version // 10000 != pg_major:
            return _gap(spec_id, title, f"Spec applies to PostgreSQL {pg_major}; snapshot is "
                        f"PostgreSQL {version // 10000}", paths=["identity.server_version_num"])
        settings = snapshot.get("settings")
        if settings is None:
            reason = next((g.get("reason", "unknown") for g in snapshot.get("gaps") or []
                           if isinstance(g, dict) and g.get("section") == "settings"), None)
            detail = (f"gap: {reason}" if reason else
                      "section unavailable without gap record - collector contract violation")
            return _gap(spec_id, title, f"Collector could not retrieve settings ({detail})",
                        paths=["settings"])
        row = next((r for r in settings if isinstance(r, dict) and r.get("name") == name), None)
        if row is None:
            found = [r.get("name") for r in settings if isinstance(r, dict) and r.get("name")]
            return _gap(spec_id, title, f"{name} is not present in settings list (collector should "
                        "include every spec setting - this indicates collection failure)",
                        evidence={"settings_found": found, name: None}, paths=["settings", path])
        value = row.get("setting")
        # Only an unsanitised, unitless boolean/enum value equals the spec's SHOW output.
        if (not isinstance(value, str) or row.get("sanitised") is True
                or row.get("unit") is not None
                or row.get("vartype", "enum") not in ("bool", "enum")):
            return _gap(spec_id, title, f"{name} cannot be read as an exact SHOW value from this "
                        "snapshot", evidence={name: None}, paths=[path])
        if OPERATORS[check["operator"]](value, check["expected"]):
            return Finding(control_id=spec_id, status=FindingStatus.PASS, title=title,
                           rationale=f"{name} is set to '{value}'", evidence_found={name: value},
                           control_metadata=None, is_gapped=False, evidence_paths=[path])
        return Finding(
            control_id=spec_id, status=FindingStatus.FAIL, title=title,
            rationale=f"{name} is set to '{value}', should be {_expected_text(check)}",
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
    controls = {}
    for path in sorted(directory.glob("*.yaml")):
        spec = load_spec(path)
        errors = validate_spec(spec, records)
        if errors:
            raise ValueError(f"Invalid spec {path.name}: {'; '.join(errors)}")
        automated = spec["tier"] == "automated" and spec.get("check", {}).get("kind") == "setting"
        ref = spec["ref"]
        controls[spec["spec_id"]] = definition_cls(
            control_id=spec["spec_id"],
            cis_title=f"{ref['recommendation']} {ref['title']}",
            description=f"{ref['benchmark']} v{ref['benchmark_version']} recommendation {ref['recommendation']}",
            severity=None,
            rule_func=_setting_rule(spec) if automated else _manual_rule(spec),
            template_id="SET_CONFIG_PARAMETER" if automated else "MANUAL_PROCEDURE",
            template_version=1,
            is_automatable=automated,
            risk_level="low" if automated else "medium",
            requires_dba_review=True,
        )
    if not controls:
        raise ValueError(f"No specs installed for {benchmark_id}")
    return controls
