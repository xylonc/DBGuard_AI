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

ROOT = Path(__file__).resolve().parents[2]


class ContractError(ValueError):
    """Invalid or unsupported input; retrying cannot repair it."""


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def validate_contract(value: dict, name: str) -> None:
    schema = json.loads((ROOT / "catalog/specs/contracts" / name).read_text())
    Draft202012Validator(schema).validate(value)


class SpecEngine:
    def __init__(self, specs: list[dict], records: RecordsIndex):
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
        self.manifest = manifest_from_specs(self._specs, records)
        self.manifest_text = manifest_text(self.manifest)
        self.manifest_hash = hashlib.sha256(self.manifest_text.encode()).hexdigest()
        self.hashes = {s["spec_id"]: spec_sha256(s) for s in self._specs}
        self.spec_set_hash = digest(self.hashes)
        self.baseline_sql = (ROOT / "collector/collect.sql").read_text()
        self.collector_hash = hashlib.sha256(self.baseline_sql.encode()).hexdigest()

    @classmethod
    def load(cls, directory: Path, records_path: Path):
        return cls([load_spec(p) for p in sorted(directory.glob("*.yaml"))],
                   RecordsIndex.load(records_path))

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
        report = assess_specs(self.specs, snapshot, self.records)
        if report["target"]["server_major"] != 17:
            raise ContractError("Snapshot PostgreSQL major does not match specs")
        if not report["flags"]["integrity_ok"] or report["flags"]["orphan_checks"]:
            raise ContractError("Assessment integrity checks failed")
        statuses = {"PASS": "PASS", "FAIL": "FAIL", "MANUAL": "MANUAL_REVIEW",
                    "NEEDS_CAPABILITY": "MANUAL_REVIEW"}
        findings = {row["spec_id"]: {"status": statuses.get(row["result"], "GAPPED"),
                                    "spec_hash": self.hashes[row["spec_id"]]} for row in report["results"]}
        return {"snapshot_hash": digest(snapshot), "spec_set_hash": self.spec_set_hash,
                "findings": findings, "upstream_report": report}

    def bind_assessment(self, snapshot: dict, supplied: dict | None = None) -> dict:
        calculated = self.assess(snapshot)
        if supplied is not None and supplied not in (calculated, calculated["upstream_report"]):
            raise ContractError("Upstream assessment does not match the exact snapshot and specs")
        return calculated
