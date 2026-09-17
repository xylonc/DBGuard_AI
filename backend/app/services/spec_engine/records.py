"""Records index for benchmark data."""

import hashlib
import json
from pathlib import Path
from typing import Any


class RecordsIntegrityError(Exception):
    """Raised when records.json integrity check fails."""
    pass


class RecordsIndex:
    """Index of benchmark records with lookup by recommendation."""

    def __init__(self, records: list[dict[str, Any]], benchmark: str, benchmark_version: str):
        self.records = records
        self.benchmark = benchmark
        self.benchmark_version = benchmark_version
        self._by_recommendation: dict[str, dict[str, Any]] = {}
        for r in records:
            rec = r["recommendation"]
            if rec in self._by_recommendation:
                raise RecordsIntegrityError(f"Duplicate recommendation: {rec}")
            self._by_recommendation[rec] = r

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, recommendation: str) -> dict[str, Any]:
        return self._by_recommendation[recommendation]

    def __contains__(self, recommendation: str) -> bool:
        return recommendation in self._by_recommendation

    @classmethod
    def load(cls, path: Path) -> "RecordsIndex":
        """Load records from JSON file and validate integrity."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Validate required top-level fields
        required = ["benchmark", "benchmark_version", "record_count", "sheet", "records"]
        for field in required:
            if field not in data:
                raise RecordsIntegrityError(f"Missing required field: {field}")

        # Validate record_count matches actual count
        if data["record_count"] != len(data["records"]):
            raise RecordsIntegrityError(
                f"record_count ({data['record_count']}) != len(records) ({len(data['records'])})"
            )

        # Validate each record's source_sha256
        for r in data["records"]:
            canonical = {
                "recommendation": r["recommendation"],
                "title": r["title"],
                "assessment_status": r["assessment_status"],
                "audit_procedure": r["audit_procedure"],
                "remediation_procedure": r["remediation_procedure"],
            }
            sha_str = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            expected_sha = hashlib.sha256(sha_str.encode("utf-8")).hexdigest()
            if r.get("source_sha256") != expected_sha:
                raise RecordsIntegrityError(
                    f"source_sha256 mismatch for recommendation {r['recommendation']}: "
                    f"expected {expected_sha}, got {r.get('source_sha256')}"
                )

        return cls(
            records=data["records"],
            benchmark=data["benchmark"],
            benchmark_version=data["benchmark_version"],
        )
