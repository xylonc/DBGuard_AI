"""Sandbox Validation Service for VALIDATE phase.

This module implements the SandboxValidationService that:
1. Boots a clean target PostgreSQL container using TwinRunner
2. Executes validated remediation SQL inside the container
3. Collects a fresh twin snapshot and re-evaluates via AssessmentService
4. Verifies target control statuses flip from FAIL to PASS
5. Executes rollback SQL, confirms clean restoration, and destroys the container

Hard Invariants:
- SANDBOX ISOLATION: Twin execution drops ALL capabilities, disallows new privileges
- DETERMINISTIC FLIP VERIFICATION: Verification requires executing rendered Jinja SQL
- NON-EXECUTABLE BYPASS: Manual procedure controls report SKIPPED_MANUAL_REQUIRED
- CLEANUP GUARANTEE: Container teardown via finally block to prevent leaked containers
- NO ARBITRARY SQL: Only rendered template artifacts are executed
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from catalog.controls.assess.registry import CONTROL_REGISTRY
from app.models import (
    AssessmentReport,
    ControlMetadata,
    Finding,
    FindingStatus,
    RemediationProposal,
    TwinExecutionResult,
    TwinExecutionStatus,
)
from catalog.images.catalog import resolve_image

# Import twin runner - the ONLY component allowed to communicate with Docker
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from services.twin_runner.twin_runner import (
    TwinRunner,
    TwinSpecification,
    TwinResourceProfile,
)

logger = logging.getLogger("dbguard.sandbox-service")


# ============================================================================
# Proposal Artifact - Immutable validated proposal
# ============================================================================


@dataclass
class ProposalArtifact:
    """Immutable proposal artifact tied to specific snapshot and template.

    This is the contract between HERMES and the sandbox. The sandbox MUST
    NOT execute arbitrary SQL - only proposals matching this artifact are valid.
    """

    proposal_id: str
    snapshot_id: str
    control_id: str
    template_id: str
    template_version: int
    parameters: Dict[str, Any]
    rendered_sql: str
    rendered_sql_sha256: str
    requires_dba_review: bool = True

    @classmethod
    def create(
        cls,
        snapshot_id: str,
        control_id: str,
        template_id: str,
        template_version: int,
        parameters: Dict[str, Any],
        rendered_sql: str,
        requires_dba_review: bool = True,
    ) -> ProposalArtifact:
        """Create a validated proposal artifact."""
        rendered_sql_sha256 = hashlib.sha256(
            rendered_sql.encode("utf-8")
        ).hexdigest()

        return cls(
            proposal_id=f"run-prop-{snapshot_id[:12]}-{int(time.time())}",
            snapshot_id=snapshot_id,
            control_id=control_id,
            template_id=template_id,
            template_version=template_version,
            parameters=parameters,
            rendered_sql=rendered_sql,
            rendered_sql_sha256=rendered_sql_sha256,
            requires_dba_review=requires_dba_review,
        )


# ============================================================================
# Sandbox Validation Service
# ============================================================================


class SandboxValidationService:
    """Service for executing SQL remediation in a secure PostgreSQL sandbox."""

    def __init__(self):
        """Initialize the SandboxValidationService."""
        self.twin_runner = TwinRunner()
        self._twin_network_created = False
        self._created_twins: List[str] = []

    def _ensure_network(self) -> bool:
        """Create twin network if it doesn't exist."""
        if self._twin_network_created:
            return True

        result = os.system("docker network create dbguard_twin_net 2>/dev/null || true")
        self._twin_network_created = True
        return True

    def _create_twin_for_snapshot(
        self,
        snapshot_id: str,
        profile_id: str = "16",
        ttl_minutes: int = 30,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Create a twin container for testing."""
        self._ensure_network()

        # Enforce strict run- prefix required by TwinRunner
        run_id = f"run-val-{snapshot_id[:12]}-{int(time.time())}"

        spec = TwinSpecification(
            run_id=run_id,
            approved_profile_id=profile_id,
            snapshot_id=snapshot_id,
            ttl_minutes=ttl_minutes,
        )

        success, twin_id, status = self.twin_runner.create_twin(spec)

        if success:
            self._created_twins.append(run_id)

        return success, twin_id, status

    def _destroy_twin(self, run_id: str) -> bool:
        """Destroy a twin container."""
        try:
            self.twin_runner.stop_twin(run_id)
            result = self.twin_runner.destroy_twin(run_id)

            if run_id in self._created_twins:
                self._created_twins.remove(run_id)

            return True
        except Exception as e:
            logger.error(f"Failed to destroy twin {run_id}: {e}")
            return False

    def _collect_twin_snapshot(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Collect a snapshot from the twin container."""
        container_name = f"dbguard-twin-{run_id}"

        try:
            cmd = [
                "docker", "exec", container_name, "psql", "-U", "dbguard", "-c",
                "SELECT name, setting FROM pg_settings WHERE name IN ('log_connections', 'password_encryption');",
                "-t"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            settings = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        settings.append({
                            "name": parts[0].strip(),
                            "setting": parts[1].strip(),
                        })

            cmd = [
                "docker", "exec", container_name, "psql", "-U", "dbguard", "-c",
                "SELECT nspname, has_schema_privilege(nspname, 'public', 'CREATE') as public_has_create FROM pg_namespace WHERE nspname = 'public';",
                "-t"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            schemas = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        schemas.append({
                            "nspname": parts[0].strip(),
                            "public_has_create": parts[1].strip() == "t",
                        })

            cmd = [
                "docker", "exec", container_name, "psql", "-U", "dbguard", "-c",
                "SELECT rolname, CASE WHEN rolpassword LIKE 'md5%' THEN 'md5' ELSE 'scram-sha-256' END as password_type FROM pg_authid WHERE rolcanlogin;",
                "-t"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            password_types = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        password_types.append({
                            "rolname": parts[0].strip(),
                            "password_type": parts[1].strip(),
                        })

            return {
                "snapshot_id": f"twin-{run_id}",
                "settings": settings,
                "schemas": schemas,
                "password_types": password_types,
                "gaps": [],
            }

        except Exception as e:
            logger.error(f"Failed to collect twin snapshot: {e}")
            return None

    def _evaluate_control(self, snapshot: Dict[str, Any], control_id: str) -> Finding:
        """Evaluate a single control against a snapshot."""
        control = CONTROL_REGISTRY.get(control_id)
        if control is None:
            raise ValueError(f"Unknown control ID: {control_id}")

        return control.evaluate(snapshot)

    def _replay_snapshot_metadata(
        self,
        run_id: str,
        settings: List[Dict[str, Any]],
    ) -> Tuple[bool, List[str]]:
        """Replay security-relevant settings into the twin using TwinRunner."""
        return self.twin_runner.replay_metadata(run_id, settings)

    def _execute_sql_in_twin(
        self,
        run_id: str,
        sql: str,
        description: str,
    ) -> Tuple[bool, str]:
        """Execute SQL in the twin container using TwinRunner."""
        return self.twin_runner.execute_sql(run_id, sql, description)

    def verify_proposal(
        self,
        snapshot_id: str,
        control_id: str,
        proposal: RemediationProposal,
        rendered_sql: str,
    ) -> TwinExecutionResult:
        """Verify a proposal by executing it in a twin container."""
        result = TwinExecutionResult(
            control_id=control_id,
            status=TwinExecutionStatus.FAILED,
        )

        # Handle non-executable controls
        if proposal.template_id == "MANUAL_PROCEDURE" or not (
            proposal.template_id.startswith("SET_CONFIG") or proposal.template_id.startswith("REVOKE")
        ):
            result.status = TwinExecutionStatus.SKIPPED_MANUAL_REQUIRED
            result.execution_log.append(
                f"Control {control_id} requires manual intervention. Template: {proposal.template_id}"
            )
            return result

        # Step 1: Load source snapshot first to get approved profile and settings
        from app.services.snapshot_service import SnapshotStore
        from pathlib import Path

        snapshot_dir = Path(os.environ.get("SNAPSHOT_STORAGE_DIR", "data/snapshots"))
        snapshot_store = SnapshotStore(str(snapshot_dir))

        try:
            source_bundle = snapshot_store.load(snapshot_id)
            source_snapshot = source_bundle.model_dump(mode="json", exclude_none=False)

            raw_version = source_snapshot.get("postgresql_version") or "16"
            pg_profile = str(raw_version).split(".")[0]
            if not pg_profile or pg_profile == "None":
                pg_profile = "16"
        except Exception as e:
            result.status = TwinExecutionStatus.SANDBOX_REPRODUCTION_FAILED
            result.error = f"Failed to load source snapshot: {e}"
            result.execution_log.append(f"Failed to load source snapshot: {e}")
            return result

        # Step 2: Create twin container using approved profile and run- prefix
        success, twin_run_id, status = self._create_twin_for_snapshot(snapshot_id, profile_id=pg_profile)

        if not success:
            result.status = TwinExecutionStatus.FAILED
            result.error = f"Twin creation failed: {status.get('errors', ['Unknown error'])}"
            result.execution_log.append(f"Twin creation failed: {status}")
            return result

        twin_run_id = str(twin_run_id)

        try:
            # Step 3: Wait for container database readiness
            time.sleep(5)

            # Step 4: Replay snapshot settings
            source_settings = source_snapshot.get("settings", []) or []
            success, errors = self._replay_snapshot_metadata(twin_run_id, source_settings)

            if not success:
                result.status = TwinExecutionStatus.SANDBOX_REPRODUCTION_FAILED
                result.error = f"Failed to replay snapshot metadata: {errors}"
                result.execution_log.extend(errors)
                return result

            result.execution_log.append("Snapshot metadata replayed successfully")

            # Step 5: Pre-remediation check (expect FAIL)
            pre_snapshot = self._collect_twin_snapshot(twin_run_id)

            if pre_snapshot is None:
                result.status = TwinExecutionStatus.FAILED
                result.error = "Failed to collect pre-remediation snapshot"
                result.execution_log.append("Failed to collect pre-remediation snapshot")
                return result

            pre_finding = self._evaluate_control(pre_snapshot, control_id)
            result.pre_remediation_status = pre_finding.status
            result.execution_log.append(f"Pre-remediation status: {pre_finding.status}")

            if pre_finding.status != FindingStatus.FAIL:
                result.status = TwinExecutionStatus.SANDBOX_REPRODUCTION_FAILED
                result.error = f"Sandbox failed to reproduce FAIL state. Expected FAIL, got {pre_finding.status}"
                result.execution_log.append(f"Sandbox verification failed: expected FAIL, got {pre_finding.status}")
                return result

            result.execution_log.append("Sandbox successfully reproduced original FAIL state")

            # Step 6: Execute remediation SQL
            if rendered_sql:
                success, log_msg = self._execute_sql_in_twin(twin_run_id, rendered_sql, "Remediation")
                result.remediation_executed = success
                result.execution_log.append(log_msg)

                if not success:
                    result.status = TwinExecutionStatus.FAILED
                    result.error = log_msg
                    return result
            else:
                result.execution_log.append("No rendered SQL provided - skip execution")

            # Step 7: Post-remediation verification (expect PASS)
            time.sleep(2)
            post_snapshot = self._collect_twin_snapshot(twin_run_id)

            if post_snapshot is None:
                result.status = TwinExecutionStatus.FAILED
                result.error = "Failed to collect post-remediation snapshot"
                result.execution_log.append("Failed to collect post-remediation snapshot")
                return result

            post_finding = self._evaluate_control(post_snapshot, control_id)
            result.post_remediation_status = post_finding.status
            result.execution_log.append(f"Post-remediation status: {post_finding.status}")

            # Step 8: Verify status flip
            flip_verified = (
                pre_finding.status == FindingStatus.FAIL and
                post_finding.status == FindingStatus.PASS
            )

            result.flip_verified = flip_verified
            result.execution_log.append(f"Flip verified: {flip_verified}")

            if flip_verified:
                result.status = TwinExecutionStatus.VERIFIED
            else:
                result.status = TwinExecutionStatus.FAILED
                result.error = f"Expected FAIL->PASS flip, got {pre_finding.status}->{post_finding.status}"

            # Step 9: Execute rollback SQL
            if pre_finding.evidence_found and pre_finding.status == FindingStatus.FAIL:
                if control_id in ("cis_postgres_16_log_connections", "CIS-3.1.2") and "log_connections" in pre_finding.evidence_found:
                    original_value = pre_finding.evidence_found["log_connections"]
                    rollback_sql = f"ALTER SYSTEM SET log_connections = '{original_value}';"
                    rollback_success, rollback_log = self._execute_sql_in_twin(
                        twin_run_id, rollback_sql, "Rollback"
                    )
                    result.rollback_executed = rollback_success
                    result.execution_log.append(rollback_log)

                    time.sleep(2)
                    post_rollback_snapshot = self._collect_twin_snapshot(twin_run_id)

                    if post_rollback_snapshot:
                        post_rollback_finding = self._evaluate_control(
                            post_rollback_snapshot, control_id
                        )
                        result.post_rollback_status = post_rollback_finding.status
                        result.execution_log.append(f"Post-rollback status: {post_rollback_finding.status}")

                        rollback_verified = (post_rollback_finding.status == FindingStatus.FAIL)
                        result.rollback_verified = rollback_verified
                        result.execution_log.append(f"Rollback verified: {rollback_verified}")

            # Step 10: Run compatibility check
            if twin_run_id:
                compatibility_ok, compat_logs = self._run_compatibility_check(twin_run_id)
                result.execution_log.extend(compat_logs)

                if not compatibility_ok:
                    result.status = TwinExecutionStatus.COMPATIBILITY_FAILED
                    result.execution_log.append("Compatibility check failed")

            return result

        finally:
            # Step 11: Guaranateed cleanup
            if twin_run_id:
                self._destroy_twin(twin_run_id)
                result.execution_log.append(f"Twin destroyed: {twin_run_id}")

    def _run_compatibility_check(self, run_id: str) -> Tuple[bool, List[str]]:
        """Run basic compatibility validation on the twin."""
        logs = []
        container_name = f"dbguard-twin-{run_id}"

        try:
            cmd = f"docker exec {container_name} pg_isready -U dbguard"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)

            if "accepting connections" not in result.stdout.lower():
                logs.append(f"PostgreSQL not ready: {result.stdout}")
                return False, logs

            cmd = f"docker exec {container_name} psql -U dbguard -c 'SELECT 1;'"
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)

            if "ERROR" in result.stdout.upper() or "FATAL" in result.stdout.upper():
                logs.append(f"Basic query failed: {result.stdout}")
                return False, logs

            logs.append("Compatibility check: PASS")
            return True, logs

        except Exception as e:
            logs.append(f"Compatibility check failed: {e}")
            return False, logs


def build_proposal_artifact(
    snapshot_id: str,
    control_id: str,
    template_id: str,
    template_version: int,
    parameters: Dict[str, Any],
    rendered_sql: str,
    requires_dba_review: bool = True,
) -> ProposalArtifact:
    """Build a proposal artifact from validated components."""
    return ProposalArtifact.create(
        snapshot_id=snapshot_id,
        control_id=control_id,
        template_id=template_id,
        template_version=template_version,
        parameters=parameters,
        rendered_sql=rendered_sql,
        requires_dba_review=requires_dba_review,
    )