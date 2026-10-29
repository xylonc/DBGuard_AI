"""Collection/assessment seam shared by the demo target and every sandbox.

Runs the upstream manifest collector and Phase 1 assessor unchanged. The UI
findings map is a projection; the full authoritative report is retained.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from app.services.spec_engine import RecordsIndex, load_spec, spec_sha256, validate_spec
from app.services.spec_engine.assess import assess as assess_specs
from app.services.spec_engine.manifest import manifest_from_specs, manifest_text
from app.services.spec_engine.policy import profile_value_errors

ROOT = Path(__file__).resolve().parents[2]


# F6 sandbox scope (Melvin, 28 Oct: "Skip now, skeleton next week"): the sandbox
# never recreates a target's roles, functions, grants or archiving, so catalog
# checks are outside its findings map entirely: no-GAPPED guards, regressions and
# reproduction/rollback equality ignore them. They stay in upstream_report, the
# assessment and the UI. True would compare them again (for the planned
# password-free skeleton of accounts, permissions and function stubs).
SANDBOX_COMPARES_CATALOG = False


# Collector sections that only catalog evaluators read (added for F6). A gap in
# one of them cannot affect setting reconstruction or a setting check, so with
# SANDBOX_COMPARES_CATALOG False it does not block the sandbox. Gaps in every
# other section still do.
CATALOG_ONLY_SECTIONS = frozenset({"functions", "archiving"})


def blocking_gaps(snapshot: dict) -> list:
    """baseline.gaps records that block the sandbox."""
    gaps = snapshot["baseline"].get("gaps") or []
    if SANDBOX_COMPARES_CATALOG:
        return list(gaps)
    return [g for g in gaps if not (isinstance(g, dict) and g.get("section") in CATALOG_ONLY_SECTIONS)]


class ContractError(ValueError):
    """Invalid or unsupported input; retrying cannot repair it."""


def is_regression(before: str, after: str) -> bool:
    """A finding that got worse after a fix (UI statuses, see SpecEngine.assess).

    PASS -> anything else, and NOT_APPLICABLE -> anything but NOT_APPLICABLE/PASS:
    a fix that changes a setting another spec uses as its applies_when condition
    (e.g. log_destination) must not turn an inapplicable control into an unnoticed
    FAIL. GAPPED after a fix is handled by each caller as before.
    """
    if before == "PASS":
        return after != "PASS"
    if before == "NOT_APPLICABLE":
        return after not in ("NOT_APPLICABLE", "PASS")
    return False


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def validate_contract(value: dict, name: str) -> None:
    schema = json.loads((ROOT / "catalog/specs/contracts" / name).read_text())
    Draft202012Validator(schema).validate(value)


class SpecEngine:
    def __init__(self, specs: list[dict], records: RecordsIndex, policy=None):
        self.records = records
        self._specs = copy.deepcopy(specs)
        if not specs or len({s["spec_id"] for s in specs}) != len(specs):
            raise ContractError("Spec set must be nonempty with unique IDs")
        for spec in self._specs:
            errors = validate_spec(spec, records)
            if errors:
                raise ContractError("; ".join(errors))
            if spec["ref"]["pg_major"] != 17:
                raise ContractError("This milestone supports PostgreSQL 17 only")
        # The policy profile is chosen per assessment and resolved server-side from the
        # profile store by its hash (services/sandbox_poc/profiles.py); a handoff carries
        # only that hash, never values. Default: no profile, so every policy control is
        # MANUAL (policy_missing) and no site-specific fix exists. Never PASS.
        self.policy = policy
        if self.policy is not None:
            errors = profile_value_errors(self.policy, self._specs)
            if errors:
                raise ContractError("; ".join(errors))
        self.manifest = manifest_from_specs(self._specs, records)
        self.manifest_text = manifest_text(self.manifest)
        self.manifest_hash = hashlib.sha256(self.manifest_text.encode()).hexdigest()
        self.hashes = {s["spec_id"]: spec_sha256(s) for s in self._specs}
        self.catalog_ids = frozenset(s["spec_id"] for s in self._specs
                                     if (s.get("check") or {}).get("kind") == "catalog")
        self.spec_set_hash = digest(self.hashes)
        self.baseline_sql = (ROOT / "collector/collect.sql").read_text()
        self.collector_hash = hashlib.sha256(self.baseline_sql.encode()).hexdigest()

    @classmethod
    def load(cls, directory: Path, records_path: Path, policy=None):
        return cls([load_spec(p) for p in sorted(directory.glob("*.yaml"))],
                   RecordsIndex.load(records_path), policy)

    @property
    def policy_pin(self) -> dict | None:
        """{profile_id, sha256, approved_by, approved_at} of the active profile, or None."""
        return self.policy.pin() if self.policy is not None else None

    @property
    def specs(self) -> list[dict]:
        return copy.deepcopy(self._specs)

    def collect(self, runtime) -> dict:
        from .collector_runner import collect_owned_target
        snapshot = collect_owned_target(runtime, self)
        validate_contract(snapshot, "snapshot-v0.3.0.json")
        return snapshot

    def assess(self, snapshot: dict) -> dict:
        """Run Xylon's assessor; findings is a compatibility projection for the UI."""
        validate_contract(snapshot, "snapshot-v0.3.0.json")
        envelope = snapshot["envelope"]
        manifest = envelope["manifest"]
        expected = {check["spec_id"]: check for check in self.manifest["checks"]}
        if set(snapshot["checks"]) != set(expected):
            raise ContractError("Snapshot must contain exactly the pinned automated spec set")
        if (envelope["collector_sha256"] != self.collector_hash
                or manifest["sha256"] != self.manifest_hash
                or manifest["benchmark_id"] != self.records.benchmark_id
                or manifest["check_count"] != len(expected)):
            raise ContractError("Collector/manifest provenance does not match installed collector and exact specs")
        for sid, entry in snapshot["checks"].items():
            if entry["spec_hash"] != expected[sid]["spec_hash"]:
                raise ContractError(f"Spec hash mismatch: {sid}")
            if entry["query"] != expected[sid]["query"]:
                raise ContractError(f"Collection query mismatch: {sid}")
        report = assess_specs(self.specs, snapshot, self.records, self.policy)
        if report["target"]["server_major"] != 17:
            raise ContractError("Snapshot PostgreSQL major does not match specs")
        if not report["flags"]["integrity_ok"] or report["flags"]["orphan_checks"]:
            raise ContractError("Assessment integrity checks failed")
        # Anything not listed (NOT_COLLECTED, STALE, ERROR) is GAPPED. NOT_APPLICABLE is
        # explicit: it is only given on clean evidence where the condition is false.
        statuses = {"PASS": "PASS", "FAIL": "FAIL", "MANUAL": "MANUAL_REVIEW",
                    "NEEDS_CAPABILITY": "MANUAL_REVIEW", "NOT_APPLICABLE": "NOT_APPLICABLE"}
        # cis/explanation pass through unchanged for N/A, GAPPED and policy_missing findings.
        # Catalog rows keep theirs in upstream_report only: their facts (role counts,
        # archiver times) differ between source and sandbox and must not be compared.
        findings = {row["spec_id"]: {"status": statuses.get(row["result"], "GAPPED"),
                                    "spec_hash": self.hashes[row["spec_id"]],
                                    **{key: row[key] for key in ("cis", "explanation")
                                       if key in row and row["spec_id"] not in self.catalog_ids}}
                    for row in report["results"]
                    if SANDBOX_COMPARES_CATALOG or row["spec_id"] not in self.catalog_ids}
        return {"snapshot_hash": digest(snapshot), "spec_set_hash": self.spec_set_hash,
                "findings": findings, "upstream_report": report}

    def gapped_settings(self, findings: dict) -> list[str]:
        """GAPPED non-catalog findings; the sandbox's no-GAPPED guards look at these only."""
        return sorted(sid for sid, f in findings.items()
                      if sid not in self.catalog_ids and f["status"] == "GAPPED")

    def bind_assessment(self, snapshot: dict, supplied: dict | None = None) -> dict:
        calculated = self.assess(snapshot)
        if supplied is not None and supplied not in (calculated, calculated["upstream_report"]):
            raise ContractError("Upstream assessment does not match the exact snapshot and specs")
        return calculated
