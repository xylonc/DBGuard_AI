#!/usr/bin/env python3
"""Validate specs against the benchmark records.

Usage:
  python scripts/validate_specs.py <file-or-directory>
  
Exits 0 only if everything is valid.
"""

import sys
import hashlib
import json
import re
from pathlib import Path

import yaml

# Get repo root (parent of scripts directory)
SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent


class DuplicateKeyLoader(yaml.SafeLoader):
    """YAML loader that raises an error on duplicate keys."""
    pass


def construct_mapping(loader, node):
    """Construct mapping with duplicate key detection."""
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in mapping:
            raise yaml.YAMLError(f"Duplicate key: {key}")
        value = loader.construct_object(value_node, deep=False)
        mapping[key] = value
    return mapping


DuplicateKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_mapping
)


def load_spec(path: Path) -> dict:
    """Load a spec from YAML file with duplicate key rejection."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    return yaml.load(content, Loader=DuplicateKeyLoader)


def spec_sha256(spec: dict) -> str:
    """Compute canonical-JSON SHA-256 hash of a spec."""
    sha_str = json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(sha_str.encode("utf-8")).hexdigest()


def _normalize_whitespace(text: str) -> str:
    """Normalize whitespace runs to single spaces."""
    return re.sub(r"\s+", " ", text).strip()


class RecordsIndex:
    """Index of benchmark records with lookup by recommendation."""

    def __init__(self, records: list[dict], benchmark: str, benchmark_version: str):
        self.records = records
        self.benchmark = benchmark
        self.benchmark_version = benchmark_version
        self._by_recommendation: dict[str, dict] = {}
        for r in records:
            rec = r["recommendation"]
            if rec in self._by_recommendation:
                raise RecordsIntegrityError(f"Duplicate recommendation: {rec}")
            self._by_recommendation[rec] = r

    def __len__(self) -> int:
        return len(self.records)

    def __getitem__(self, recommendation: str) -> dict:
        return self._by_recommendation[recommendation]

    def __contains__(self, recommendation: str) -> bool:
        return recommendation in self._by_recommendation

    @classmethod
    def load(cls, path: Path) -> "RecordsIndex":
        """Load records from JSON file and validate integrity."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        required = ["benchmark", "benchmark_version", "record_count", "sheet", "records"]
        for field in required:
            if field not in data:
                raise RecordsIntegrityError(f"Missing required field: {field}")

        if data["record_count"] != len(data["records"]):
            raise RecordsIntegrityError(
                f"record_count ({data['record_count']}) != len(records) ({len(data['records'])})"
            )

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


class RecordsIntegrityError(Exception):
    """Raised when records.json integrity check fails."""
    pass


def equals(actual: str, expected: str) -> bool:
    """Check if actual equals expected (exact string comparison)."""
    return actual == expected


def not_equals(actual: str, expected: str) -> bool:
    """Check if actual does not equal expected (exact string comparison)."""
    return actual != expected


def in_(actual: str, expected: list[str]) -> bool:
    """Check if actual is a member of expected list."""
    return actual in expected


def validate_spec(spec: dict, records: RecordsIndex) -> list[str]:
    """
    Validate a spec against the records index.
    
    Returns a list of error messages. Empty list means valid.
    """
    errors = []
    
    required_keys = ["spec_id", "schema_version", "authored_by", "ref", "tier", "reason", "check", "proof"]
    for key in required_keys:
        if key not in spec:
            errors.append(f"Missing required top-level key: {key}")
    
    for key in spec:
        if key not in required_keys:
            errors.append(f"Unknown top-level key: {key}")
    
    if "schema_version" in spec:
        if spec["schema_version"] != 1:
            errors.append(f"schema_version must be 1, got {spec['schema_version']!r}")
    
    if "authored_by" in spec:
        if spec["authored_by"] not in ("human", "agent"):
            errors.append(f"authored_by must be 'human' or 'agent', got {spec['authored_by']!r}")
    
    if "spec_id" in spec:
        spec_id = spec["spec_id"]
        if not re.match(r"^[\w\s\-]+:[0-9]+(\.[0-9]+)+$", spec_id):
            errors.append(f"spec_id must be in format 'benchmark-name:recommendation', got {spec_id!r}")
    
    ref = spec.get("ref")
    if isinstance(ref, dict):
        ref_required = ["benchmark", "benchmark_version", "pg_major", "recommendation", "title", "source_sha256"]
        for key in ref_required:
            if key not in ref:
                errors.append(f"Missing required ref key: {key}")
        
        for key in ref:
            if key not in ref_required:
                errors.append(f"Unknown ref key: {key}")
        
        # Note: spec_id uses a slug format, so we don't check for a mismatch with the benchmark name.
        
        if "benchmark" in ref and "benchmark_version" in ref:
            if ref["benchmark"] != records.benchmark:
                errors.append(
                    f"ref.benchmark mismatch: expected {records.benchmark!r}, got {ref['benchmark']!r}"
                )
            if ref["benchmark_version"] != records.benchmark_version:
                errors.append(
                    f"ref.benchmark_version mismatch: expected {records.benchmark_version!r}, "
                    f"got {ref['benchmark_version']!r}"
                )
        
        if "recommendation" in ref:
            rec = ref["recommendation"]
            if rec not in records:
                errors.append(f"Recommendation {rec!r} not found in records")
            else:
                record = records[rec]
                if "title" in ref and ref["title"] != record["title"]:
                    errors.append(
                        f"ref.title mismatch: expected {record['title']!r}, got {ref['title']!r}"
                    )
                if "source_sha256" in ref and ref["source_sha256"] != record["source_sha256"]:
                    errors.append(
                        f"ref.source_sha256 mismatch for {rec}: expected {record['source_sha256']!r}, "
                        f"got {ref['source_sha256']!r}"
                    )
    
    valid_tiers = ("automated", "parameterised", "manual_checklist", "needs_capability")
    if "tier" in spec:
        if spec["tier"] not in valid_tiers:
            errors.append(f"tier must be one of {valid_tiers}, got {spec['tier']!r}")
    
    if "reason" in spec:
        tier = spec.get("tier", "")
        if tier == "automated":
            if spec["reason"] is not None:
                errors.append("tier 'automated' requires reason to be null")
        else:
            if not isinstance(spec["reason"], str) or spec["reason"] == "":
                errors.append(f"tier {tier!r} requires reason to be a non-empty string")
    
    check = spec.get("check")
    if check is not None:
        if "kind" not in check:
            errors.append("Missing required check key: kind")
        else:
            if check["kind"] != "setting":
                errors.append(f"check.kind must be 'setting', got {check['kind']!r}")
        
        if isinstance(check, dict):
            check_required = ["kind", "setting_name", "query", "operator", "expected", "pass_condition_quote"]
            for key in check_required:
                if key not in check:
                    errors.append(f"Missing required check key: {key}")
            
            for key in check:
                if key not in check_required:
                    errors.append(f"Unknown check key: {key}")
            
            if "setting_name" in check:
                setting_name = check["setting_name"]
                if not re.match(r"^[a-z_][a-z0-9_.]*$", setting_name):
                    errors.append(
                        f"check.setting_name must match pattern ^[a-z_][a-z0-9_.]*$, got {setting_name!r}"
                    )
            
            if "setting_name" in check and "query" in check:
                expected_query = "SHOW " + check["setting_name"]
                if check["query"] != expected_query:
                    errors.append(
                        f"check.query must be '{expected_query}', got {check['query']!r}"
                    )
            
            if "operator" in check:
                if check["operator"] not in ("equals", "not_equals", "in"):
                    errors.append(
                        f"check.operator must be one of ('equals', 'not_equals', 'in'), "
                        f"got {check['operator']!r}"
                    )
            
            if "expected" in check:
                expected = check["expected"]
                if check.get("operator") == "in":
                    if not isinstance(expected, list) or len(expected) == 0:
                        errors.append("check.expected must be a non-empty list when operator is 'in'")
                elif not isinstance(expected, str):
                    errors.append(f"check.expected must be a string, got {type(expected).__name__}")
            
            # Validate pass_condition_quote
            if "pass_condition_quote" in check and "setting_name" in check:
                pass_quote = check["pass_condition_quote"]
                setting_name = check["setting_name"]
                
                # Get the record using ref.recommendation, not setting_name
                rec_ref = spec.get("ref", {})
                rec_key = rec_ref.get("recommendation", "")
                if rec_key in records:
                    record = records[rec_key]
                    audit = record.get("audit_procedure", "")
                    audit_normalized = _normalize_whitespace(audit)
                    if pass_quote not in audit_normalized:
                        errors.append(
                            f"pass_condition_quote not found in audit_procedure for {rec_key!r}"
                        )
                    
                    if "operator" in check and "expected" in check:
                        if check["operator"] == "equals":
                            expected_vals = [check["expected"]]
                        elif check["operator"] == "in":
                            expected_vals = check["expected"]
                        else:
                            expected_vals = []
                        
                        for val in expected_vals:
                            if not re.search(r"\b" + re.escape(val) + r"\b", pass_quote):
                                errors.append(
                                    f"expected value {val!r} is not a whole token in pass_condition_quote"
                                )
    
    # Validate proof
    if isinstance(spec.get("proof"), dict):
        proof = spec["proof"]
        proof_required = ["break", "fix"]
        for key in proof_required:
            if key not in proof:
                errors.append(f"Missing required proof key: {key}")
        
        if "break" in proof and isinstance(proof["break"], dict):
            break_obj = proof["break"]
            for key in ["setting_name", "value"]:
                if key not in break_obj:
                    errors.append(f"Missing required proof.break key: {key}")
            
            if "setting_name" in break_obj:
                if "check" in spec and isinstance(spec["check"], dict):
                    if "setting_name" in spec["check"]:
                        if break_obj["setting_name"] != spec["check"]["setting_name"]:
                            errors.append(
                                f"proof.break.setting_name ({break_obj['setting_name']!r}) does not "
                                f"match check.setting_name ({spec['check']['setting_name']!r})"
                            )
            
            # Check break.value does not satisfy the check
            if "setting_name" in break_obj and "value" in break_obj:
                setting_name = break_obj["setting_name"]
                break_value = break_obj["value"]
                # The break/fix validation is about logical operator behavior, not looking up records
                if "check" in spec and isinstance(spec["check"], dict):
                    check_obj = spec["check"]
                    if check_obj.get("kind") == "setting":
                        actual = break_value
                        if check_obj.get("operator") == "equals":
                            expected = check_obj.get("expected", "")
                            if equals(actual, expected):
                                errors.append(
                                    f"proof.break.value ({break_value!r}) already satisfies "
                                    f"check (operator: {check_obj.get('operator')})"
                                )
                        elif check_obj.get("operator") == "not_equals":
                            expected = check_obj.get("expected", "")
                            if not_equals(actual, expected):
                                errors.append(
                                    f"proof.break.value ({break_value!r}) already satisfies "
                                    f"check (operator: {check_obj.get('operator')})"
                                )
                        elif check_obj.get("operator") == "in":
                            expected = check_obj.get("expected", [])
                            if in_(actual, expected):
                                errors.append(
                                    f"proof.break.value ({break_value!r}) already satisfies "
                                    f"check (operator: {check_obj.get('operator')})"
                                )
        
        if "fix" in proof and isinstance(proof["fix"], dict):
            fix_obj = proof["fix"]
            for key in ["setting_name", "value"]:
                if key not in fix_obj:
                    errors.append(f"Missing required proof.fix key: {key}")
            
            if "setting_name" in fix_obj:
                if "check" in spec and isinstance(spec["check"], dict):
                    if "setting_name" in spec["check"]:
                        if fix_obj["setting_name"] != spec["check"]["setting_name"]:
                            errors.append(
                                f"proof.fix.setting_name ({fix_obj['setting_name']!r}) does not "
                                f"match check.setting_name ({spec['check']['setting_name']!r})"
                            )
            
            # Check fix.value satisfies the check
            if "setting_name" in fix_obj and "value" in fix_obj:
                setting_name = fix_obj["setting_name"]
                fix_value = fix_obj["value"]
                # The break/fix validation is about logical operator behavior, not looking up records
                if "check" in spec and isinstance(spec["check"], dict):
                    check_obj = spec["check"]
                    if check_obj.get("kind") == "setting":
                        actual = fix_value
                        if check_obj.get("operator") == "equals":
                            expected = check_obj.get("expected", "")
                            if not equals(actual, expected):
                                errors.append(
                                    f"proof.fix.value ({fix_value!r}) does not satisfy "
                                    f"check (operator: {check_obj.get('operator')})"
                                )
                        elif check_obj.get("operator") == "not_equals":
                            expected = check_obj.get("expected", "")
                            if not_equals(actual, expected):
                                errors.append(
                                    f"proof.fix.value ({fix_value!r}) already satisfies "
                                    f"check (operator: {check_obj.get('operator')})"
                                )
                        elif check_obj.get("operator") == "in":
                            expected = check_obj.get("expected", [])
                            if not in_(actual, expected):
                                errors.append(
                                    f"proof.fix.value ({fix_value!r}) does not satisfy "
                                    f"check (operator: {check_obj.get('operator')})"
                                )
    
    return errors


def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/validate_specs.py <file-or-directory>", file=sys.stderr)
        sys.exit(1)
    
    input_path = Path(sys.argv[1])
    
    if not input_path.exists():
        print(f"Error: Path does not exist: {input_path}", file=sys.stderr)
        sys.exit(1)
    
    records_path = REPO_ROOT / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json"
    try:
        records = RecordsIndex.load(records_path)
    except Exception as e:
        print(f"Error loading records: {e}", file=sys.stderr)
        sys.exit(1)
    
    if input_path.is_file():
        files = [input_path]
    elif input_path.is_dir():
        files = sorted(input_path.glob("*.yaml"))
    else:
        print(f"Error: Invalid path: {input_path}", file=sys.stderr)
        sys.exit(1)
    
    all_valid = True
    for file_path in files:
        try:
            spec = load_spec(file_path)
        except Exception as e:
            print(f"FAIL {file_path}: Failed to load spec: {e}")
            all_valid = False
            continue
        
        errors = validate_spec(spec, records)
        if errors:
            print(f"FAIL {file_path}:")
            for err in errors:
                print(f"  - {err}")
            all_valid = False
        else:
            print(f"OK {file_path}")
    
    sys.exit(0 if all_valid else 1)


if __name__ == "__main__":
    main()
