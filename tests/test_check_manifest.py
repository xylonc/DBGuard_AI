"""Tests for the check manifest builder.

Conventions:
- Marked tier_a for automated test suite.
- Tests verify the 6 committed specs produce 5 checks (3.1.14 is needs_capability).
- Golden file at tests/fixtures/phase1/checks-cis-pg17-v1.1.0.json is the source of truth.
"""
import copy
import json
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))
sys.path.insert(0, str(REPO_ROOT))

from app.services.spec_engine import RecordsIndex, load_spec, spec_sha256, build_manifest

RECORDS_PATH = REPO_ROOT / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json"
SPEC_DIR = REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0"
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "phase1" / "checks-cis-pg17-v1.1.0.json"
SCHEMA_PATH = REPO_ROOT / "catalog" / "specs" / "contracts" / "check-manifest-v1.json"


def load_schema():
    """Load the check-manifest-v1.json schema."""
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validate_against_schema(manifest, schema):
    """Simple JSON Schema validation for check-manifest-v1.json."""
    # Top-level required fields
    for field in ["manifest_version", "benchmark_id", "checks"]:
        assert field in manifest, f"Missing top-level field: {field}"

    assert manifest["manifest_version"] == 1, f"manifest_version must be 1, got {manifest['manifest_version']}"

    # Each check
    for check in manifest["checks"]:
        for field in ["spec_id", "spec_hash", "kind", "setting_name", "query"]:
            assert field in check, f"Missing check field: {field}"
        assert check["kind"] == "setting", f"kind must be 'setting', got {check['kind']}"
        assert isinstance(check["spec_hash"], str), "spec_hash must be a string"
        assert len(check["spec_hash"]) == 64, "spec_hash must be 64 chars"
        assert all(c in "0123456789abcdef" for c in check["spec_hash"]), "spec_hash must be hex"


class TestCheckManifest:
    """Test rules for the check manifest contract."""

    def test_six_specs_give_exactly_five_checks_and_3114_is_absent(self):
        """The 6 committed specs give exactly 5 checks, and 3.1.14 is absent."""
        records = RecordsIndex.load(RECORDS_PATH)
        manifest = build_manifest(SPEC_DIR, records)

        assert manifest["manifest_version"] == 1
        assert manifest["benchmark_id"] == "cis-pg17-v1.1.0"
        assert len(manifest["checks"]) == 5

        # 3.1.14 is needs_capability, not automated, so it should be absent
        spec_ids = [c["spec_id"] for c in manifest["checks"]]
        assert "cis-pg17-v1.1.0:3.1.14" not in spec_ids

        # Expected automated specs
        expected = [
            "cis-pg17-v1.1.0:3.1.16",
            "cis-pg17-v1.1.0:3.1.20",
            "cis-pg17-v1.1.0:3.1.21",
            "cis-pg17-v1.1.0:3.1.25",
            "cis-pg17-v1.1.0:6.9",
        ]
        assert spec_ids == expected

    def test_each_spec_hash_equals_spec_sha256_of_its_spec_file(self):
        """Each spec_hash equals spec_sha256 of its spec file."""
        records = RecordsIndex.load(RECORDS_PATH)
        manifest = build_manifest(SPEC_DIR, records)

        for check in manifest["checks"]:
            spec_path = SPEC_DIR / f"{check['spec_id'].split(':')[-1]}.yaml"
            spec = load_spec(spec_path)
            expected_hash = spec_sha256(spec)
            assert check["spec_hash"] == expected_hash, (
                f"spec_hash mismatch for {check['spec_id']}: "
                f"manifest has {check['spec_hash']}, spec_sha256 gave {expected_hash}"
            )

    def test_building_twice_gives_byte_identical_output(self):
        """Building twice gives byte-identical output."""
        records = RecordsIndex.load(RECORDS_PATH)
        manifest1 = build_manifest(SPEC_DIR, records)
        manifest2 = build_manifest(SPEC_DIR, records)

        # Convert to JSON strings with same parameters
        json1 = json.dumps(manifest1, sort_keys=True, indent=2, ensure_ascii=False)
        json2 = json.dumps(manifest2, sort_keys=True, indent=2, ensure_ascii=False)

        assert json1 == json2, "Double build should produce identical output"

        # Check byte-for-byte equality of actual files
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            out1 = tmp_path / "manifest1.json"
            out2 = tmp_path / "manifest2.json"
            out1.write_text(json1 + "\n", encoding="utf-8")
            out2.write_text(json2 + "\n", encoding="utf-8")
            assert out1.read_bytes() == out2.read_bytes(), "Files should be byte-identical"

    def test_output_validates_against_check_manifest_v1_schema(self):
        """The output validates against check-manifest-v1.json."""
        records = RecordsIndex.load(RECORDS_PATH)
        manifest = build_manifest(SPEC_DIR, records)
        schema = load_schema()
        validate_against_schema(manifest, schema)

    def test_fresh_build_equals_golden_file(self):
        """A fresh build equals the golden file."""
        records = RecordsIndex.load(RECORDS_PATH)
        manifest = build_manifest(SPEC_DIR, records)
        golden = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))

        # Compare as JSON to avoid whitespace differences
        assert json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) == json.dumps(
            golden, sort_keys=True, indent=2, ensure_ascii=False
        ), "Fresh build should equal golden file"

    def test_directory_with_one_invalid_spec_raises_and_names_file(self):
        """A directory containing one invalid spec raises, and the error names that file."""
        import tempfile
        records = RecordsIndex.load(RECORDS_PATH)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # Write a valid spec first
            valid_spec = {
                "spec_id": "cis-pg17-v1.1.0:3.1.20",
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
            valid_yaml = tmp_path / "3.1.20.yaml"
            valid_yaml.write_text(yaml.dump(valid_spec, allow_unicode=True), encoding="utf-8")

            # Write an invalid spec with unknown top-level key
            invalid_spec = copy.deepcopy(valid_spec)
            invalid_spec["unknown_key"] = "value"
            invalid_yaml = tmp_path / "3.1.21.yaml"
            invalid_yaml.write_text(yaml.dump(invalid_spec, allow_unicode=True), encoding="utf-8")

            with pytest.raises(ValueError) as exc_info:
                build_manifest(tmp_path, records)

            # Error should mention the invalid file
            assert "3.1.21.yaml" in str(exc_info.value)
            assert "unknown_key" in str(exc_info.value)

    def test_spec_with_check_kind_other_than_setting_is_rejected(self):
        """A spec with a check.kind other than setting is rejected during build."""
        import tempfile
        records = RecordsIndex.load(RECORDS_PATH)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)

            # Write a spec with invalid check.kind
            bad_spec = {
                "spec_id": "cis-pg17-v1.1.0:99.99.99",
                "schema_version": 1,
                "authored_by": "human",
                "ref": {
                    "benchmark": "CIS PostgreSQL 17 Benchmark",
                    "benchmark_version": "1.1.0",
                    "pg_major": 17,
                    "recommendation": "99.99.99",
                    "title": "Test",
                    "source_sha256": "0" * 64,
                },
                "tier": "automated",
                "reason": None,
                "check": {
                    "kind": "invalid_kind",  # Not in ("setting",)
                    "setting_name": "some_setting",
                    "query": "SHOW some_setting",
                    "operator": "equals",
                    "expected": "on",
                    "pass_condition_quote": "Test",
                },
                "proof": {
                    "break": {"setting_name": "some_setting", "value": "off"},
                    "fix": {"setting_name": "some_setting", "value": "on"},
                },
            }
            bad_yaml = tmp_path / "99.99.99.yaml"
            bad_yaml.write_text(yaml.dump(bad_spec, allow_unicode=True), encoding="utf-8")

            with pytest.raises(ValueError) as exc_info:
                build_manifest(tmp_path, records)

            # Error should mention the invalid kind
            assert "invalid_kind" in str(exc_info.value)
            assert "check.kind" in str(exc_info.value)
    def test_empty_directory_raises(self):
        """An empty directory raises ValueError with message about no .yaml files."""
        import tempfile
        records = RecordsIndex.load(RECORDS_PATH)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            # Empty directory - no .yaml files
            with pytest.raises(ValueError) as exc_info:
                build_manifest(tmp_path, records)

            assert "no .yaml spec files" in str(exc_info.value).lower()

    def test_cli_writes_byte_identical_to_golden_and_exits_zero(self):
        """The CLI, run as subprocess, writes file byte-identical to golden and exits 0."""
        import subprocess

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            out_file = tmp_path / "manifest.json"

            result = subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "build_check_manifest.py"),
                 "--specs", str(SPEC_DIR), "--out", str(out_file)],
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

            assert result.returncode == 0, f"CLI failed: {result.stderr}"
            assert out_file.exists(), "Output file should exist"

            # Compare bytes
            golden_bytes = FIXTURE_PATH.read_bytes()
            new_bytes = out_file.read_bytes()
            assert golden_bytes == new_bytes, "CLI output should be byte-identical to golden"

    def test_cli_missing_specs_exits_nonzero_with_stderr_message(self):
        """The CLI given missing --specs directory exits non-zero with message on stderr."""
        import subprocess

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            fake_dir = tmp_path / "nonexistent"

            result = subprocess.run(
                [sys.executable, str(REPO_ROOT / "scripts" / "build_check_manifest.py"),
                 "--specs", str(fake_dir), "--out", str(tmp_path / "out.json")],
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

            assert result.returncode != 0, "CLI should exit non-zero for missing directory"
            assert result.stderr, "Error message should be on stderr"
            assert "does not exist" in result.stderr.lower() or "FAIL" in result.stderr

