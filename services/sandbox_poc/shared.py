"""Collection/assessment seam shared by the demo target and every sandbox.

Xylon can replace this adapter without changing the remediation graph. It runs
the existing baseline SQL, plus exact spec queries, and uses existing operators.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Protocol

from jsonschema import Draft202012Validator

from app.services.spec_engine import RecordsIndex, load_spec, spec_sha256, validate_spec
from app.services.spec_engine.validate import OPERATORS

ROOT = Path(__file__).resolve().parents[2]


class ContractError(ValueError):
    """Invalid or unsupported input; retrying cannot repair it."""


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode()).hexdigest()


def validate_contract(value: dict, name: str) -> None:
    schema = json.loads((ROOT / "catalog/specs/contracts" / name).read_text())
    Draft202012Validator(schema).validate(value)


class SQLSession(Protocol):
    def sql(self, script: str) -> str: ...


class SpecEngine:
    def __init__(self, specs: list[dict], records: RecordsIndex):
        self._specs = copy.deepcopy(specs)
        if not specs or len({s["spec_id"] for s in specs}) != len(specs):
            raise ContractError("Spec set must be nonempty with unique IDs")
        for spec in self._specs:
            errors = validate_spec(spec, records)
            if errors:
                raise ContractError("; ".join(errors))
            if spec["ref"]["pg_major"] != 17:
                raise ContractError("This milestone supports PostgreSQL 17 only")
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

    def collect(self, session: SQLSession) -> dict:
        # The baseline uses a psql variable; the executor supplies a run-owned ID.
        baseline = json.loads(session.sql(self.baseline_sql))
        envelope = baseline.pop("envelope")
        checks = {}
        for spec in self._specs:
            sid = spec["spec_id"]
            check = spec.get("check")
            entry = {"spec_hash": self.hashes[sid],
                     "query": check["query"] if check else "not applicable",
                     "status": "not_collected"}
            if check:
                try:
                    entry.update(status="ok", result=session.sql(check["query"]).strip())
                except RuntimeError as exc:
                    entry.update(status="error", error=str(exc))
            checks[sid] = entry
        # Include provenance even for default-valued spec settings that the
        # fixed baseline did not select. Names have passed spec validation.
        names = [s["check"]["setting_name"] for s in self._specs if "check" in s]
        if names:
            literals = ",".join("'" + n + "'" for n in names)
            extra = json.loads(session.sql(
                "SELECT coalesce(json_agg(s), '[]'::json) FROM "
                f"(SELECT * FROM pg_settings WHERE name IN ({literals})) s;"))
            settings = {s["name"]: s for s in baseline.get("settings") or []}
            # Do not overwrite the baseline's sanitised fields.
            for setting in extra:
                settings.setdefault(setting["name"], setting)
            baseline["settings"] = list(settings.values())
        snapshot = {"envelope": envelope, "baseline": baseline, "checks": checks}
        validate_contract(snapshot, "snapshot-v0.3.0.json")
        return snapshot

    def assess(self, snapshot: dict) -> dict:
        validate_contract(snapshot, "snapshot-v0.3.0.json")
        if set(snapshot["checks"]) != set(self.hashes):
            raise ContractError("Snapshot must contain exactly the pinned spec set")
        version = snapshot["baseline"].get("identity", {}).get("server_version_num", 0)
        if int(version) // 10000 != 17:
            raise ContractError("Snapshot PostgreSQL major does not match specs")
        findings = {}
        for spec in self._specs:
            sid = spec["spec_id"]
            entry = snapshot["checks"][sid]
            check = spec.get("check")
            if entry["spec_hash"] != self.hashes[sid]:
                raise ContractError(f"Spec hash mismatch: {sid}")
            if check and entry["query"] != check["query"]:
                raise ContractError(f"Collection query mismatch: {sid}")
            if not check:
                status = "MANUAL_REVIEW"
            elif entry["status"] != "ok" or not isinstance(entry.get("result"), str):
                status = "GAPPED"
            else:
                passed = OPERATORS[check["operator"]](entry["result"], check["expected"])
                status = "PASS" if passed else "FAIL"
            findings[sid] = {"status": status, "spec_hash": self.hashes[sid]}
        return {"snapshot_hash": digest(snapshot), "spec_set_hash": self.spec_set_hash,
                "findings": findings}
