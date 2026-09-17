#!/usr/bin/env python3
import sys
sys.path.insert(0, "/workspace/DBGuardAI")
sys.path.insert(0, "/workspace/DBGuardAI/backend")

from app.services.spec_engine import RecordsIndex, validate_spec

records = RecordsIndex.load("/workspace/DBGuardAI/catalog/benchmarks/cis-pg17-v1.1.0/records.json")

# Base valid spec
base_spec = {
    "spec_id": "CIS-PostgreSQL-17-Benchmark:3.1.20",
    "schema_version": 1,
    "authored_by": "human",
    "ref": {
        "benchmark": "CIS PostgreSQL 17 Benchmark",
        "benchmark_version": "1.1.0",
        "pg_major": 17,
        "recommendation": "3.1.20",
        "title": "Ensure 'log_connections' is enabled",
        "source_sha256": "4e2afdf9a6c40bba3b2dfd7c36f5929b9260cae9e0d6af243f4f79bd4db7c3c0",
    },
    "tier": "automated",
    "reason": None,
    "check": {
        "kind": "setting",
        "setting_name": "log_connections",
        "query": "SHOW log_connections",
        "operator": "equals",
        "expected": "on",
        "pass_condition_quote": "If not configured to `on`, this is a fail.",
    },
    "proof": {
        "break": {"setting_name": "log_connections", "value": "off"},
        "fix": {"setting_name": "log_connections", "value": "on"},
    },
}

# Test break value that already satisfies check
spec2 = dict(base_spec)
spec2["proof"]["break"]["value"] = "on"
errors2 = validate_spec(spec2, records)
print("Break value errors:", errors2)

# Test fix value that does not satisfy check
spec3 = dict(base_spec)
spec3["proof"]["fix"]["value"] = "off"
errors3 = validate_spec(spec3, records)
print("Fix value errors:", errors3)
