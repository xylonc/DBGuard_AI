#!/usr/bin/env python3
"""One-page coverage status of all 72 CIS PostgreSQL 17 v1.1.0 recommendations.

Usage:
    python scripts/coverage_report.py           # write docs/COVERAGE.md and docs/coverage.json
    python scripts/coverage_report.py --check   # exit 1 if the committed files are out of date

Everything that can be derived is read from the repository:
- catalog/benchmarks/cis-pg17-v1.1.0/records.json: the 72 recommendations and their titles;
- catalog/specs/cis-pg17-v1.1.0/*.yaml: which rules have a spec, its tier and check kind;
- services/sandbox_poc/planning.py POLICIES: which setting specs have a reviewed fix, and
  whether its value is fixed or comes from the approved policy profile (FROM_PROFILE);
- docs/ROADMAP.md "Control families" table: the family of every recommendation.

Facts that cannot be derived (planned weeks, plain-language wording, Wave 2a work in
progress, the 6.10 family move) live in the small reviewed mappings below. The output has
no timestamps, so --check is deterministic.
"""

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.spec_engine.validate import uses_policy  # noqa: E402
from services.sandbox_poc.planning import FROM_PROFILE, POLICIES  # noqa: E402

RECORDS_PATH = REPO_ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json"
SPECS_DIR = REPO_ROOT / "catalog/specs/cis-pg17-v1.1.0"
ROADMAP_PATH = REPO_ROOT / "docs/ROADMAP.md"
PLANNING_PATH = REPO_ROOT / "services/sandbox_poc/planning.py"
MD_PATH = REPO_ROOT / "docs/COVERAGE.md"
JSON_PATH = REPO_ROOT / "docs/coverage.json"
SCRIPT_REL = "scripts/coverage_report.py"

# ---- Status categories (one per rule), in display order ----
# (id, label shown to the reader, default "Fix?" column)
CATEGORIES = [
    ("fixable", "Live: fixable", "Yes"),
    ("fixable_after_policy", "Live: fixable once company policy is approved", "After policy approval"),
    ("report_only", "Live: report-only, person decides", "Person decides"),
    ("human_checklist", "Live: human checklist", "—"),
    ("needs_capability", "Needs capability (planned)", "Planned"),
    ("not_started", "Not started", None),  # fix column depends on the family (FAMILY_PLAN)
    # Fallback, not expected today: a setting spec drafted before its POLICIES entry
    # is reviewed (step 1 of the CLAUDE.md recipe done, step 3 not yet).
    ("check_only", "Live: check only, fix not reviewed yet", "—"),
]
CATEGORY_LABEL = {cid: label for cid, label, _ in CATEGORIES}
CATEGORY_FIX = {cid: fix for cid, _, fix in CATEGORIES}
LIVE_CATEGORIES = ("fixable", "fixable_after_policy", "report_only", "human_checklist", "check_only")

# ---- Reviewed mappings (not derivable from the repository) ----

# docs/ROADMAP.md Status: "6.10 moved to F7" (the 6.10 spec reason also says "Planned
# with F7"), but the family table still lists it under F2. The table is not edited
# here; this override records the move. Remove it once the table is updated.
FAMILY_OVERRIDES = {"6.10": "F7"}

# Planned week and fix outlook per family, for rules without a working check yet.
# Weeks come from the ROADMAP Status/Schedule rows (F5 and F7: Wave 2, next week;
# F8 and F9: "assessed and reported with guided manual steps (no auto-fix)", 9-13 Nov).
FAMILY_PLAN = {
    "F5": {"week": "2–8 Nov", "fix": "Planned"},
    "F7": {"week": "2–8 Nov", "fix": "Planned"},
    "F8": {"week": "9–13 Nov", "fix": "—"},  # guided manual steps, no automatic fix
    "F9": {"week": "9–13 Nov", "fix": "—"},  # manual with sign-off, no automatic fix
}

# Plain-language family names for the reader (the ROADMAP names are technical).
FAMILY_PLAIN = {
    "F1": "fixed-value settings",
    "F2": "settings with richer comparisons",
    "F3": "settings set by company policy",
    "F4": "settings that need a restart",
    "F5": "database add-ons",
    "F6": "accounts and permissions",
    "F7": "login and encryption",
    "F8": "the server's operating system",
    "F9": "review and procedure",
}

# Wave 2a (Gate 2 approved 3 Nov): the DBA can pick a per-object fix for these
# report-only catalog checks; DBGuard rehearses it on a stand-in copy first.
PER_OBJECT_FIXES = {"4.3", "4.4", "4.5", "4.6", "4.9", "4.10", "5.5"}

# Per-rule plain reasons where the category sentence would be wrong or vague.
REASON_OVERRIDES = {
    "5.2": "DBGuard checks this setting; the fix needs this server's network address, "
           "taken from the approved company policy.",
    "7.4": "DBGuard reports whether copies of the database change log are archived; "
           "a person decides how to set that up.",
}

# Plain wording for applies_when conditions, keyed by (setting, expected item).
CONDITION_PLAIN = {("log_destination", "syslog"): "it only applies when logs are sent to syslog"}


def rec_key(rec: str) -> tuple:
    """Numeric sort key, so 3.1.10 sorts after 3.1.9."""
    return tuple(int(part) for part in rec.split("."))


def load_records() -> list[dict]:
    data = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    records = data["records"]
    if len(records) != data["record_count"]:
        raise SystemExit(f"records.json: {len(records)} records but record_count {data['record_count']}")
    return records


def load_specs() -> dict[str, dict]:
    specs = {}
    for path in sorted(SPECS_DIR.glob("*.yaml")):
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        rec = spec["ref"]["recommendation"]
        if rec in specs:
            raise SystemExit(f"two specs for {rec}")
        specs[rec] = spec
    return specs


def _expand(token: str, all_recs: list[str]) -> list[str]:
    """'3.1.16–3.1.23' -> every record between, with the same parent section."""
    parts = re.split(r"\s*[–-]\s*", token.strip())
    if len(parts) == 1:
        if parts[0] not in all_recs:
            raise SystemExit(f"ROADMAP family table names unknown recommendation {parts[0]}")
        return parts
    lo, hi = parts
    parent = lo.rsplit(".", 1)[0]
    if hi.rsplit(".", 1)[0] != parent:
        raise SystemExit(f"ROADMAP range {token} crosses sections")
    out = [r for r in all_recs
           if r.rsplit(".", 1)[0] == parent and rec_key(lo) <= rec_key(r) <= rec_key(hi)]
    if lo not in out or hi not in out:
        raise SystemExit(f"ROADMAP range {token} has an unknown endpoint")
    return out


def load_families(all_recs: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    """(recommendation -> family id, family id -> roadmap name) from the ROADMAP table."""
    text = ROADMAP_PATH.read_text(encoding="utf-8")
    section = text.split("## Control families", 1)[1].split("\n## ", 1)[0]
    rec_family, names = {}, {}
    for line in section.splitlines():
        m = re.match(r"\|\s*(F\d+)\s+([^|]+?)\s*\|\s*(\d+)\s*\|([^|]+)\|", line)
        if not m:
            continue
        fam, name, count, recs = m.group(1), m.group(2), int(m.group(3)), m.group(4)
        names[fam] = name
        members = [r for token in recs.split(",") for r in _expand(token, all_recs)]
        if len(members) != count:
            raise SystemExit(f"ROADMAP {fam}: count column says {count}, list has {len(members)}")
        for rec in members:
            if rec in rec_family:
                raise SystemExit(f"ROADMAP lists {rec} in both {rec_family[rec]} and {fam}")
            rec_family[rec] = fam
    missing = sorted(set(all_recs) - set(rec_family), key=rec_key)
    if missing:
        raise SystemExit(f"ROADMAP family table misses {missing}")
    for rec, fam in FAMILY_OVERRIDES.items():
        if fam not in names:
            raise SystemExit(f"FAMILY_OVERRIDES: unknown family {fam}")
        rec_family[rec] = fam
    return rec_family, names


def classify(spec: dict | None) -> str:
    if spec is None:
        return "not_started"
    if spec["tier"] == "needs_capability":
        return "needs_capability"
    check = spec.get("check")
    if not check:
        return "human_checklist"
    if check["kind"] == "catalog":
        return "report_only"
    if check["kind"] == "setting":
        name = check["setting_name"]
        if name not in POLICIES:
            return "check_only"
        if uses_policy(spec) or POLICIES[name][0] == FROM_PROFILE:
            return "fixable_after_policy"
        return "fixable"
    raise SystemExit(f"{spec['spec_id']}: unknown check kind {check['kind']!r}; add a reviewed category")


def _condition(spec: dict) -> str | None:
    cond = spec.get("applies_when")
    if not cond:
        return None
    expected = cond.get("expected")
    items = expected if isinstance(expected, list) else [expected]
    for item in items:
        plain = CONDITION_PLAIN.get((cond.get("setting_name"), item))
        if plain:
            return plain
    return "it only applies in some set-ups"


def reason_for(rec: str, status: str, spec: dict | None, family: str) -> str:
    if rec in REASON_OVERRIDES:
        return REASON_OVERRIDES[rec]
    plan = FAMILY_PLAN.get(family, {})
    if status == "fixable":
        base = "DBGuard checks this setting and can prove the CIS fix on a throwaway test copy"
    elif status == "fixable_after_policy":
        if uses_policy(spec):
            base = ("DBGuard compares this with the company policy and can test the fix "
                    "once a person approves that policy")
        else:
            base = ("DBGuard checks this setting; the fix needs a value for this particular "
                    "server, taken from the approved company policy")
    elif status == "report_only":
        if rec in PER_OBJECT_FIXES:
            return ("DBGuard lists the accounts or permissions involved; the DBA can pick a fix "
                    "for one object, which DBGuard tests on a throwaway copy first.")
        return "DBGuard lists the accounts or permissions involved; a person decides what to change."
    elif status == "human_checklist":
        return "CIS gives no exact value DBGuard can check, so a person confirms it from a checklist."
    elif status == "needs_capability":
        return (f"Needs a new kind of check, planned with the {FAMILY_PLAIN[family]} work "
                f"({plan['week']}).")
    elif status == "not_started":
        if family == "F8":
            return ("Concerns the server's operating system, not the database; to be assessed "
                    f"with guided manual steps ({plan['week']}).")
        if family == "F9":
            return ("Needs a person's review and sign-off; to be assessed with guided manual "
                    f"steps ({plan['week']}).")
        return f"Not built yet; planned with the {FAMILY_PLAIN[family]} work ({plan['week']})."
    elif status == "check_only":
        return "DBGuard checks this setting; a fix has not been reviewed yet."
    else:
        raise AssertionError(status)
    condition = _condition(spec)
    return f"{base}; {condition}." if condition else f"{base}."


def build() -> dict:
    records = sorted(load_records(), key=lambda r: rec_key(r["recommendation"]))
    all_recs = [r["recommendation"] for r in records]
    if len(set(all_recs)) != len(all_recs):
        raise SystemExit("records.json has duplicate recommendations")
    specs = load_specs()
    unknown = sorted(set(specs) - set(all_recs), key=rec_key)
    if unknown:
        raise SystemExit(f"specs for recommendations not in records.json: {unknown}")
    for rec in PER_OBJECT_FIXES:
        if classify(specs.get(rec)) != "report_only":
            raise SystemExit(f"PER_OBJECT_FIXES: {rec} is not a report-only catalog check")
    rec_family, family_names = load_families(all_recs)

    rows = []
    for record in records:
        rec = record["recommendation"]
        spec = specs.get(rec)
        family = rec_family[rec]
        status = classify(spec)
        if status in ("not_started", "needs_capability") and family not in FAMILY_PLAN:
            raise SystemExit(f"{rec}: {status} in {family}, which has no planned week in FAMILY_PLAN")
        fix = FAMILY_PLAN[family]["fix"] if status == "not_started" else CATEGORY_FIX[status]
        label = CATEGORY_LABEL[status]
        per_object = rec in PER_OBJECT_FIXES
        check = (spec or {}).get("check") or {}
        rows.append({
            "recommendation": rec,
            "title": record["title"],
            "cis_assessment": record["assessment_status"],
            "family": family,
            "family_name": family_names[family],
            "status_id": status,
            "status": label + ("; per-object fixes the DBA picks" if per_object else ""),
            "fix": fix,
            "reason": reason_for(rec, status, spec, family),
            "has_spec": spec is not None,
            "tier": spec["tier"] if spec else None,
            "check_kind": check.get("kind"),
            "setting_name": check.get("setting_name"),
            "fix_value_from": (
                None if status not in ("fixable", "fixable_after_policy")
                else "reviewed_policy" if status == "fixable" else "policy_profile"),
            "per_object_fixes": per_object,
            "planned_week": (FAMILY_PLAN[family]["week"]
                             if status in ("not_started", "needs_capability") else None),
        })

    counts = {cid: sum(1 for r in rows if r["status_id"] == cid) for cid, _, _ in CATEGORIES}
    return {
        "generated_by": SCRIPT_REL,
        "benchmark": "CIS PostgreSQL 17 Benchmark",
        "benchmark_version": "1.1.0",
        "inputs": [
            {"path": str(RECORDS_PATH.relative_to(REPO_ROOT)), "what": "the 72 CIS rules and titles"},
            {"path": str(SPECS_DIR.relative_to(REPO_ROOT)) + "/*.yaml",
             "what": "control specs (tier and check kind)"},
            {"path": str(PLANNING_PATH.relative_to(REPO_ROOT)),
             "what": "POLICIES (reviewed fixes; fixed value or from the policy profile)"},
            {"path": str(ROADMAP_PATH.relative_to(REPO_ROOT)), "what": "the Control families table"},
        ],
        "total": len(rows),
        "specced": sum(1 for r in rows if r["has_spec"]),
        "categories": [
            {"id": cid, "label": label, "count": counts[cid]} for cid, label, _ in CATEGORIES
        ],
        "rules": rows,
    }


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|")


def render_markdown(data: dict) -> str:
    counts = {c["id"]: c["count"] for c in data["categories"]}
    total, specced = data["total"], data["specced"]
    live = sum(counts[c] for c in LIVE_CATEGORIES)
    fixable = counts["fixable"] + counts["fixable_after_policy"]
    per_object = sum(1 for r in data["rules"] if r["per_object_fixes"])
    shown = [c for c in data["categories"] if c["count"] or c["id"] != "check_only"]
    width = max(len(c["label"]) for c in shown)

    out = [
        "# CIS PostgreSQL 17 coverage",
        "",
        "<!-- Generated by scripts/coverage_report.py. Do not edit by hand; run the script. -->",
        "",
        f"The CIS PostgreSQL 17 Benchmark (version {data['benchmark_version']}) has {total} security "
        "rules. This page shows, for each rule, what DBGuard can do with it today.",
        "",
        f"- **{live} of {total}** rules are live: DBGuard checks them against evidence from the "
        "database (or gives a person a checklist).",
        f"- **{fixable}** of those have a fix DBGuard can test on a throwaway copy of the database: "
        f"{counts['fixable']} straight away and {counts['fixable_after_policy']} once the company "
        "policy is approved. DBGuard never changes the real database; a database administrator "
        "applies the tested fix.",
        f"- **{counts['report_only']}** are report-only: DBGuard shows the accounts or settings "
        f"involved and a person decides. For {per_object} of them the DBA can pick a fix for one account, table or function, which DBGuard tests first.",
        f"- **{total - specced}** are not started yet and **{counts['needs_capability']}** needs a "
        "new kind of check; each has a planned week below.",
        "",
        "## Summary",
        "",
        "```",
    ]
    for c in shown:
        out.append(f"{c['label']:<{width}}  {c['count']:>2}  {'#' * c['count']}")
    out += [
        f"{'Total':<{width}}  {total:>2}",
        "```",
        "",
        "## All rules",
        "",
        "| No. | Rule | Family | Status | Fix? | Why |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in data["rules"]:
        out.append("| " + " | ".join(_md_cell(x) for x in (
            r["recommendation"], r["title"], f"{r['family']} {r['family_name']}",
            r["status"], r["fix"], r["reason"])) + " |")
    out += [
        "",
        "## How this is generated",
        "",
        f"This page and `docs/coverage.json` are generated by `{data['generated_by']}` from:",
        "",
    ]
    out += [f"- `{i['path']}`: {i['what']}" for i in data["inputs"]]
    out += [
        "",
        "Planned weeks, plain-language wording, the per-object fix rules and the 6.10 family "
        "move are small reviewed mappings in the script. Regenerate with "
        f"`python {data['generated_by']}`; CI-style check: `python {data['generated_by']} --check`.",
        "",
    ]
    return "\n".join(out)


def render_json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def stale_files(md_path: Path, json_path: Path, data: dict) -> list[Path]:
    """Files whose committed content differs from a fresh render."""
    expected = {md_path: render_markdown(data), json_path: render_json(data)}
    return [p for p, text in expected.items()
            if not p.exists() or p.read_text(encoding="utf-8") != text]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="exit 1 if docs/COVERAGE.md or docs/coverage.json is out of date")
    args = parser.parse_args(argv)
    data = build()
    if args.check:
        stale = stale_files(MD_PATH, JSON_PATH, data)
        for path in stale:
            print(f"out of date: {path.relative_to(REPO_ROOT)} (run python {SCRIPT_REL})",
                  file=sys.stderr)
        return 1 if stale else 0
    MD_PATH.write_text(render_markdown(data), encoding="utf-8")
    JSON_PATH.write_text(render_json(data), encoding="utf-8")
    print(f"wrote {MD_PATH.relative_to(REPO_ROOT)} and {JSON_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
