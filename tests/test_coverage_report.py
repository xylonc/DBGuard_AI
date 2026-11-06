"""Tests for scripts/coverage_report.py and the generated docs/COVERAGE.md + docs/coverage.json."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from app.services.spec_engine.catalog_checks import uses_policy_profile
from app.services.spec_engine.validate import uses_policy
from scripts import coverage_report as cr
from services.sandbox_poc.planning import FROM_PROFILE, POLICIES

REPO_ROOT = Path(__file__).resolve().parent.parent

RECORDS = json.loads(
    (REPO_ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json").read_text(encoding="utf-8")
)["records"]
SPECS = {
    s["ref"]["recommendation"]: s
    for s in (yaml.safe_load(p.read_text(encoding="utf-8"))
              for p in sorted((REPO_ROOT / "catalog/specs/cis-pg17-v1.1.0").glob("*.yaml")))
}
VALID_FIX = {"Yes", "After policy approval", "Guided steps", "Person decides", "Planned", "—"}


@pytest.fixture(scope="module")
def data():
    return cr.build()


@pytest.fixture(scope="module")
def rows(data):
    return {r["recommendation"]: r for r in data["rules"]}


def test_exactly_72_unique_rows_matching_records(data):
    recs = [r["recommendation"] for r in data["rules"]]
    assert len(recs) == 72
    assert len(set(recs)) == 72
    assert set(recs) == {r["recommendation"] for r in RECORDS}
    titles = {r["recommendation"]: r["title"] for r in RECORDS}
    assert all(r["title"] == titles[r["recommendation"]] for r in data["rules"])


def test_rows_are_numerically_sorted(data):
    recs = [r["recommendation"] for r in data["rules"]]
    assert recs == sorted(recs, key=lambda x: tuple(int(p) for p in x.split(".")))
    assert recs.index("3.1.10") == recs.index("3.1.9") + 1
    assert recs.index("4.10") == recs.index("4.9") + 1


def test_every_spec_has_a_status_consistent_with_tier_kind_and_policies(rows):
    assert len(SPECS) == sum(1 for r in rows.values() if r["has_spec"])
    for rec, spec in SPECS.items():
        row = rows[rec]
        check = spec.get("check") or {}
        assert row["has_spec"] and row["tier"] == spec["tier"], rec
        if spec["tier"] == "needs_capability":
            assert row["status_id"] == "needs_capability", rec
            assert row["fix"] == "Planned" and row["planned_week"], rec
        elif not check:
            assert row["status_id"] == "human_checklist", rec
            assert row["fix"] == "—", rec
        elif check["kind"] == "catalog":
            if rec in cr.CATALOG_SETTING_FIXES:
                if not all(n in POLICIES for n in cr.CATALOG_SETTING_FIXES[rec]):
                    assert row["status_id"] == "check_only", rec
                elif uses_policy_profile(spec):
                    assert row["status_id"] == "fixable_after_policy", rec
                    assert row["fix"] == "After policy approval", rec
                else:
                    assert row["status_id"] == "fixable", rec
                    assert row["fix"] == "Yes", rec
            elif rec in cr.GUIDED_FIX_CHECKS:
                assert row["status_id"] == "checked_guided", rec
                assert row["fix"] == "Guided steps", rec
            elif rec in cr.CATALOG_CHECKLISTS:
                assert row["status_id"] == "human_checklist", rec
                assert row["fix"] == "—", rec
            else:
                assert row["status_id"] == "report_only", rec
                assert row["fix"] == "Person decides", rec
        else:
            assert check["kind"] == "setting", rec
            name = check["setting_name"]
            if name not in POLICIES:
                assert row["status_id"] == "check_only", rec
            elif uses_policy(spec) or POLICIES[name][0] == FROM_PROFILE:
                assert row["status_id"] == "fixable_after_policy", rec
                assert row["fix"] == "After policy approval", rec
            else:
                assert row["status_id"] == "fixable", rec
                assert row["fix"] == "Yes", rec


def test_policy_specs_never_counted_as_fixed_value(rows):
    # A spec whose expected value comes from the policy profile, or whose reviewed fix
    # is FROM_PROFILE (5.2, site-specific), can only be fixed after the profile is approved.
    for rec, spec in SPECS.items():
        check = spec.get("check") or {}
        if uses_policy(spec) or POLICIES.get(check.get("setting_name"), ("",))[0] == FROM_PROFILE:
            assert rows[rec]["status_id"] == "fixable_after_policy", rec
    assert rows["5.2"]["status_id"] == "fixable_after_policy"
    assert rows["5.2"]["fix_value_from"] == "policy_profile"


def test_rules_without_a_spec_are_not_started_with_family_and_week(rows):
    for rec, row in rows.items():
        if rec in SPECS:
            continue
        assert row["status_id"] == "not_started", rec
        assert row["family"] in cr.FAMILY_PLAN, rec
        assert row["planned_week"] == cr.FAMILY_PLAN[row["family"]]["week"], rec
        assert row["fix"] == ("Planned" if row["family"] in ("F5", "F7") else "—"), rec


def test_known_examples(rows):
    assert rows["3.1.20"]["status_id"] == "fixable"
    assert rows["3.1.2"]["status_id"] == "fixable_after_policy"
    assert rows["7.4"]["status_id"] == "report_only"
    assert {rows[r]["status_id"] for r in ("3.1.12", "7.2")} == {"human_checklist"}
    assert rows["6.10"]["family"] == "F7"  # from the ROADMAP family table
    assert cr.FAMILY_OVERRIDES == {}
    for rec in ("4.3", "4.4", "4.5", "4.6", "4.9", "4.10", "5.5"):
        assert rows[rec]["per_object_fixes"], rec
        assert rows[rec]["status"].endswith("per-object fixes the DBA picks"), rec
    assert not rows["4.7"]["per_object_fixes"]
    assert not rows["7.1"]["per_object_fixes"]


def test_every_row_has_a_valid_fix_label_and_short_reason(data):
    labels = {label for _, label, _ in cr.CATEGORIES}
    for row in data["rules"]:
        assert row["fix"] in VALID_FIX, row["recommendation"]
        assert row["status"].split(";")[0] in labels, row["recommendation"]
        assert row["reason"].endswith(".") and len(row["reason"]) <= 160, row["recommendation"]


def test_counts_add_up(data):
    counts = {c["id"]: c["count"] for c in data["categories"]}
    assert sum(counts.values()) == data["total"] == 72
    for cid, n in counts.items():
        assert n == sum(1 for r in data["rules"] if r["status_id"] == cid), cid
    assert data["specced"] == len(SPECS) == 72 - counts["not_started"]


def test_markdown_table_and_summary(data):
    md = cr.render_markdown(data)
    table = [line for line in md.splitlines()
             if line.startswith("| ") and not line.startswith(("| No.", "| ---"))]
    assert len(table) == 72
    assert [line.split(" | ")[0][2:] for line in table] == [r["recommendation"] for r in data["rules"]]
    for c in data["categories"]:
        if c["count"]:
            assert f"{c['label']}" in md and "#" * c["count"] in md
    assert "## How this is generated" in md and "scripts/coverage_report.py" in md


def test_check_passes_on_committed_files():
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/coverage_report.py"), "--check"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr


def test_check_detects_stale_and_missing_files(tmp_path, data):
    md, js = tmp_path / "COVERAGE.md", tmp_path / "coverage.json"
    assert cr.stale_files(md, js, data) == [md, js]
    md.write_text(cr.render_markdown(data), encoding="utf-8")
    js.write_text(cr.render_json(data), encoding="utf-8")
    assert cr.stale_files(md, js, data) == []
    js.write_text(cr.render_json(data).replace('"Yes"', '"No"', 1), encoding="utf-8")
    assert cr.stale_files(md, js, data) == [js]


def test_committed_json_matches_build(data):
    committed = json.loads((REPO_ROOT / "docs/coverage.json").read_text(encoding="utf-8"))
    assert committed == data


def test_wave2b_rules(rows):
    """Gate W2B: 8 rules go live; 3.2 waits for the approved policy; guided and checklist rules."""
    assert {rows[r]["family"] for r in ("3.2", "4.8", "5.6", "6.11")} == {"F5"}
    assert {rows[r]["family"] for r in ("5.3", "5.4", "6.8", "6.10")} == {"F7"}
    assert uses_policy_profile(SPECS["3.2"]) and not uses_policy_profile(SPECS["5.6"])
    for rec in ("3.2", "5.6", "6.10"):
        settings = cr.CATALOG_SETTING_FIXES[rec]
        expected = ("check_only" if not all(n in POLICIES for n in settings)
                    else "fixable_after_policy" if rec == "3.2" else "fixable")
        assert rows[rec]["status_id"] == expected, rec
    assert rows["6.8"]["status_id"] == rows["4.8"]["status_id"] == "checked_guided"
    assert {rows[r]["status_id"] for r in ("6.11", "5.3", "5.4")} == {"human_checklist"}
    # No reason claims "accounts or permissions" outside the F6 accounts-and-permissions family.
    for rec, row in rows.items():
        if "accounts or permissions" in row["reason"]:
            assert row["family"] == "F6", rec
