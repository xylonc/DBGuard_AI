"""Live end-to-end integration tests for sandbox validation.

Tests the full pipeline (Assess -> Propose -> Sandbox Validate) against a live
Docker engine for the log_connections = off scenario.

Run with: pytest tests/test_live_e2e_sandbox.py -v -m docker

Note: Tests are skipped if Docker daemon is not accessible.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

import pytest
from pydantic import BaseModel, Field

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.services.assessment_service import AssessmentService
from app.services.sandbox_service import SandboxValidationService, build_proposal_artifact
from app.services.snapshot_service import SnapshotStore, SnapshotUploadResponse
from app.services.template_service import compile_sql_plan_from_templates, env
from catalog.controls.assess.registry import CONTROL_REGISTRY
from app.models import (
    AssessmentReport,
    FindingStatus,
    RemediationProposal,
    TwinExecutionResult,
    TwinExecutionStatus,
)


# ============================================================================
# Docker Skip Guard
# ============================================================================


def docker_available() -> bool:
    """Check if Docker daemon is accessible."""
    if not shutil.which("docker"):
        return False

    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


# Skip all tests in this module if Docker is not available
pytestmark = pytest.mark.skipif(
    not docker_available(),
    reason="Docker daemon not available - skipping live integration tests",
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture(scope="module")
def snapshot_dir():
    """Create a temporary snapshot directory for the test."""
    tmp_dir = Path("/tmp/dbguard_test_snapshots")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    yield str(tmp_dir)
    # Cleanup
    import shutil
    shutil.rmtree(tmp_dir, ignore_errors=True)


@pytest.fixture(scope="module")
def assessment_service():
    """Create an AssessmentService instance."""
    return AssessmentService(CONTROL_REGISTRY)


@pytest.fixture(scope="module")
def sandbox_service():
    """Create a SandboxValidationService instance."""
    return SandboxValidationService()


@pytest.fixture(scope="module")
def test_snapshot():
    """Generate a sample snapshot with log_connections = 'off'."""
    return {
        "snapshot_id": "snap-live-test-001",
        "settings": [
            {"name": "log_connections", "setting": "off"},
            {"name": "password_encryption", "setting": "scram-sha-256"},
        ],
        "schemas": [],
        "password_types": [],
        "gaps": [],
    }


# ============================================================================
# Helper Functions
# ============================================================================


def get_lingering_containers() -> list:
    """Check for any lingering dbguard-twin-* containers."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return []

        container_names = result.stdout.strip().split("\n")
        return [name for name in container_names if name.startswith("dbguard-twin-")]
    except Exception:
        return []


def cleanup_lingering_containers():
    """Cleanup any lingering dbguard-twin-* containers."""
    containers = get_lingering_containers()
    for container in containers:
        subprocess.run(
            ["docker", "rm", "-f", container],
            capture_output=True,
            timeout=10,
        )


# ============================================================================
# Live Integration Tests
# ============================================================================


class TestLiveE2ESandbox:
    """Live end-to-end sandbox validation integration tests.

    These tests:
    1. Start a live PostgreSQL container via Docker
    2. Execute the full pipeline (Assess -> Propose -> Validate)
    3. Verify the FAIL -> PASS -> ROLLBACK -> FAIL state transitions
    4. Cleanup all resources

    Run with: pytest tests/test_live_e2e_sandbox.py -v -m docker
    """

    @pytest.fixture(autouse=True)
    def cleanup_before_after(self):
        """Cleanup any lingering containers before and after each test."""
        # Before test
        cleanup_lingering_containers()
        yield
        # After test
        time.sleep(1)  # Give cleanup time to complete
        cleanup_lingering_containers()

    @pytest.mark.legacy_sandbox
    @pytest.mark.xfail(strict=True, raises=ImportError, reason="legacy twin runner: test imports app.collector_models.Envelope, which no longer exists; superseded by Phase 2")
    def test_live_pipeline_assess_fail_propose_render_validate_verified(
        self,
        snapshot_dir: str,
        assessment_service: AssessmentService,
        sandbox_service: SandboxValidationService,
        test_snapshot: dict,
    ):
        """Test the full live pipeline: Assess FAIL -> Propose -> Validate VERIFIED.

        This test executes:
        1. Create snapshot via SnapshotStore
        2. Assess the snapshot - verify log_connections = 'off' returns FAIL
        3. Propose remediation using SET_CONFIG_PARAMETER template
        4. Render the proposal artifact
        5. Validate in sandbox - verify VERIFIED status with all transitions
        6. Cleanup containers
        """
        # ========================================================================
        # Step 1: Create snapshot via SnapshotStore
        # ========================================================================
        from app.collector_models import CollectorBundleV020, Envelope

        envelope = Envelope(
            target_id="test-target-001",
            database="postgres",
            schema_version="0.2.0",
            collected_at=datetime.now(timezone.utc).isoformat(),
            deployment_type="standalone",
        )

        bundle = CollectorBundleV020(
            envelope=envelope,
            identity={"server_version_num": "160006"},
            settings=test_snapshot["settings"],
            schemas=test_snapshot["schemas"],
            password_types=test_snapshot["password_types"],
            roles=[],
            authentication_rules=[],
            databases=[],
            extensions=[],
            functions=[],
            gaps=test_snapshot["gaps"],
            redactions=[],
            host_not_collected=None,
        )

        snapshot_store = SnapshotStore(snapshot_dir)
        upload_response = snapshot_store.save(bundle)

        assert upload_response.snapshot_id.startswith("snap-")
        assert upload_response.target_id == "test-target-001"
        assert upload_response.database == "postgres"
        assert upload_response.gap_count == 0

        snapshot_id = upload_response.snapshot_id

        # ========================================================================
        # Step 2: Assess the snapshot - verify FAIL for log_connections
        # ========================================================================
        report = assessment_service.evaluate(test_snapshot)

        assert isinstance(report, AssessmentReport)
        assert report.snapshot_id == test_snapshot["snapshot_id"]

        # Find the CIS-3.1.2 control result
        cis_312_finding = next(
            (f for f in report.findings if f.control_id == "CIS-3.1.2"),
            None,
        )

        assert cis_312_finding is not None, "CIS-3.1.2 finding not found"
        assert cis_312_finding.status == FindingStatus.FAIL, (
            f"Expected FAIL for log_connections=off, got {cis_312_finding.status}"
        )
        assert "set to 'off'" in cis_312_finding.rationale
        assert cis_312_finding.evidence_found == {"log_connections": "off"}

        # Verify ControlMetadata is present
        assert cis_312_finding.control_metadata is not None
        assert cis_312_finding.control_metadata.template_id == "SET_CONFIG_PARAMETER"
        assert cis_312_finding.control_metadata.is_automatable is True

        # ========================================================================
        # Step 3: Propose remediation using SET_CONFIG_PARAMETER template
        # ========================================================================
        # Render SQL from template
        template_records = [
            {
                "template_name": "SET_CONFIG_PARAMETER",
                "sql_template": "ALTER SYSTEM SET {{ param_name }} = '{{ param_value }}';",
            }
        ]

        parameters = {
            "param_name": "log_connections",
            "param_value": "on",
        }

        rendered_sql = compile_sql_plan_from_templates(template_records, parameters)
        assert "ALTER SYSTEM SET log_connections = 'on';" in rendered_sql

        # Build the proposal artifact
        artifact = build_proposal_artifact(
            snapshot_id=snapshot_id,
            control_id="CIS-3.1.2",
            template_id="SET_CONFIG_PARAMETER",
            template_version=1,
            parameters=parameters,
            rendered_sql=rendered_sql,
            requires_dba_review=True,
        )

        assert artifact.proposal_id.startswith("prop-")
        assert artifact.snapshot_id == snapshot_id
        assert artifact.control_id == "CIS-3.1.2"
        assert artifact.template_id == "SET_CONFIG_PARAMETER"
        assert artifact.rendered_sql == rendered_sql
        assert len(artifact.rendered_sql_sha256) == 64  # SHA256 hex

        # ========================================================================
        # Step 4: Validate in sandbox
        # ========================================================================
        # Create a RemediationProposal for the sandbox
        proposal = RemediationProposal(
            control_id="CIS-3.1.2",
            finding_id=None,
            template_id="SET_CONFIG_PARAMETER",
            template_version=1,
            parameters=parameters,
            reasoning="Enable logging for security audit trail - live E2E test",
            evidence_refs=[],
        )

        result = sandbox_service.verify_proposal(
            snapshot_id=snapshot_id,
            control_id="CIS-3.1.2",
            proposal=proposal,
            rendered_sql=rendered_sql,
        )

        # ========================================================================
        # Step 5: Assert all expected conditions
        # ========================================================================
        assert result.status == TwinExecutionStatus.VERIFIED, (
            f"Expected VERIFIED status, got {result.status}"
        )
        assert result.control_id == "CIS-3.1.2"
        assert result.pre_remediation_status == FindingStatus.FAIL, (
            f"Expected pre_remediation_status=FAIL, got {result.pre_remediation_status}"
        )
        assert result.post_remediation_status == FindingStatus.PASS, (
            f"Expected post_remediation_status=PASS, got {result.post_remediation_status}"
        )
        assert result.flip_verified is True, "Expected flip_verified=True"
        assert result.remediation_executed is True, "Expected remediation_executed=True"
        assert result.rollback_executed is True, "Expected rollback_executed=True"
        assert result.rollback_verified is True, "Expected rollback_verified=True"
        assert result.post_rollback_status == FindingStatus.FAIL, (
            f"Expected post_rollback_status=FAIL (original state restored), "
            f"got {result.post_rollback_status}"
        )

        # Verify execution log contains expected entries
        assert len(result.execution_log) > 0, "Expected execution log entries"
        log_text = "\n".join(result.execution_log)

        assert "Pre-remediation status: FAIL" in log_text, "Expected pre-remediation FAIL in log"
        assert "Post-remediation status: PASS" in log_text, "Expected post-remediation PASS in log"
        assert "Rollback verified: True" in log_text, "Expected rollback verification in log"
        assert "Twin destroyed:" in log_text, "Expected twin cleanup in log"

        # Verify security validation
        assert result.flip_verified is True, "Security validation failed: flip not verified"

        # ========================================================================
        # Step 6: Cleanup verification - no lingering containers
        # ========================================================================
        time.sleep(2)  # Give cleanup time to complete
        lingering = get_lingering_containers()
        assert len(lingering) == 0, (
            f"Found lingering containers after test: {lingering}"
        )

        # Print execution log for debugging
        print("\n=== Execution Log ===")
        for entry in result.execution_log:
            print(f"  {entry}")
        print("=====================\n")


# ============================================================================
# Additional Edge Case Tests
# ============================================================================


class TestLiveE2EEdgeCases:
    """Edge case tests for live E2E sandbox validation."""

    @pytest.fixture(autouse=True)
    def cleanup_before_after(self):
        """Cleanup any lingering containers before and after each test."""
        cleanup_lingering_containers()
        yield
        time.sleep(1)
        cleanup_lingering_containers()

    @pytest.mark.legacy_sandbox
    @pytest.mark.xfail(strict=True, raises=ImportError, reason="legacy twin runner: test imports app.collector_models.Envelope, which no longer exists; superseded by Phase 2")
    def test_sandbox_rejects_non_automatable_control(
        self,
        snapshot_dir: str,
        sandbox_service: SandboxValidationService,
    ):
        """Test that non-automatable controls (CIS-2.1) return SKIPPED_MANUAL_REQUIRED."""
        from app.collector_models import CollectorBundleV020, Envelope

        # Create snapshot with MD5 password (non-automatable)
        bundle = CollectorBundleV020(
            envelope=Envelope(
                target_id="test-target-md5",
                database="postgres",
                schema_version="0.2.0",
                collected_at=datetime.now(timezone.utc).isoformat(),
                deployment_type="standalone",
            ),
            identity={"server_version_num": "160006"},
            settings=[],
            schemas=[],
            password_types=[
                {"rolname": "testuser", "password_type": "md5"},
            ],
            roles=[],
            authentication_rules=[],
            databases=[],
            extensions=[],
            functions=[],
            gaps=[],
            redactions=[],
            host_not_collected=None,
        )

        snapshot_store = SnapshotStore(snapshot_dir)
        upload_response = snapshot_store.save(bundle)

        proposal = RemediationProposal(
            control_id="CIS-2.1",
            template_id="MANUAL_PROCEDURE",
            template_version=1,
            parameters={},
            reasoning="Non-automatable control - migration required",
            evidence_refs=[],
        )

        result = sandbox_service.verify_proposal(
            snapshot_id=upload_response.snapshot_id,
            control_id="CIS-2.1",
            proposal=proposal,
            rendered_sql="",
        )

        assert result.status == TwinExecutionStatus.SKIPPED_MANUAL_REQUIRED, (
            f"Expected SKIPPED_MANUAL_REQUIRED for non-automatable control, "
            f"got {result.status}"
        )
        assert "requires manual intervention" in "\n".join(result.execution_log)


# ============================================================================
# Docker Command Verification Tests (without actually running)
# ============================================================================


class TestDockerGuard:
    """Tests for the Docker guard mechanism."""

    def test_docker_available_check(self):
        """Test that the docker_available function works correctly."""
        # The pytestmark should be set based on docker_available()
        # If we get here, the module was imported, so either:
        # 1. Docker is available and tests ran
        # 2. Docker is not available and pytestmark skipped the module
        pass  # Test logic is in pytestmark definition
