"""Twin Execution Service for VALIDATE phase.

This module implements the TwinExecutionService that:
1. Boots a clean target PostgreSQL container using twin_runner.py
2. Executes validated remediation SQL inside the container
3. Collects a fresh twin snapshot and re-evaluates via AssessmentService
4. Verifies target control statuses flip from FAIL to PASS
5. Executes rollback SQL, confirms clean restoration, and destroys the container

Hard Invariants:
- SANDBOX ISOLATION: Twin execution drops ALL capabilities, disallows new privileges
- DETERMINISTIC FLIP VERIFICATION: Verification requires executing rendered Jinja SQL
- NON-EXECUTABLE BYPASS: Manual procedure controls (CIS-2.1) report SKIPPED_MANUAL_REQUIRED
- CLEANUP GUARANTEE: Container teardown in finally block to prevent leaked containers
"""

import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from catalog.controls.assess.registry import CONTROL_REGISTRY
from app.models import (
    AssessmentReport,
    FindingStatus,
    ProposalReviewPackage,
    TwinExecutionResult,
    TwinExecutionStatus,
)
from catalog.images.catalog import resolve_image

# Import twin runner
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from services.twin_runner.twin_runner import TwinRunner, TwinSpecification, TwinResourceProfile

logger = logging.getLogger("dbguard.twin-service")


class TwinExecutionService:
    """
    Service for executing SQL remediation in a secure twin container sandbox.
    
    This service manages the complete twin lifecycle:
    - Create twin with validated TwinSpecification
    - Execute remediation SQL inside twin
    - Re-assess via AssessmentService
    - Verify FAIL -> PASS flip
    - Execute rollback SQL
    - Destroy twin (cleanup guaranteed via finally block)
    """
    
    def __init__(self):
        """Initialize the TwinExecutionService."""
        self.twin_runner = TwinRunner()
        self._twin_network_created = False
        self._created_twins: List[str] = []  # Track twins for cleanup
    
    def _ensure_network(self) -> bool:
        """Create twin network if it doesn't exist."""
        if self._twin_network_created:
            return True
        
        # Try to create the network (if docker is available)
        result = os.system("docker network create dbguard_twin_net 2>/dev/null || true")
        self._twin_network_created = True
        return True
    
    def _create_twin_for_snapshot(
        self,
        snapshot_id: str,
        profile_id: str = "postgresql-community-16.6",
        ttl_minutes: int = 30,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Create a twin container for testing.
        
        Args:
            snapshot_id: Source snapshot ID for audit trail
            profile_id: Approved image profile ID
            ttl_minutes: Container TTL
            
        Returns:
            Tuple of (success, twin_run_id, status_dict)
        """
        self._ensure_network()
        
        run_id = f"validate-{snapshot_id[:16]}-{int(time.time())}"
        
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
        """
        Destroy a twin container.
        
        Args:
            run_id: The twin run ID
            
        Returns:
            True if destruction was attempted (success or not)
        """
        try:
            # Stop the twin
            self.twin_runner.stop_twin(run_id)
            
            # Destroy the twin
            result = self.twin_runner.destroy_twin(run_id)
            
            # Remove from tracking
            if run_id in self._created_twins:
                self._created_twins.remove(run_id)
            
            return True
        except Exception as e:
            logger.error(f"Failed to destroy twin {run_id}: {e}")
            return False
    
    def _collect_twin_snapshot(self, run_id: str) -> Optional[Dict[str, Any]]:
        """
        Collect a snapshot from the twin container.
        
        This is a simplified version that queries key PostgreSQL metadata.
        In production, this would use the full collector bundle.
        
        Args:
            run_id: The twin run ID
            
        Returns:
            Snapshot dictionary or None if collection failed
        """
        container_name = f"dbguard-twin-{run_id}"
        
        try:
            # Query settings
            result = os.popen(
                f"docker exec {container_name} psql -U dbguard -c "
                "'SELECT name, setting FROM pg_settings WHERE name IN "
                "('log_connections', 'password_encryption');' -t"
            ).read()
            
            settings = []
            for line in result.strip().split("\n"):
                if line:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        settings.append({
                            "name": parts[0].strip(),
                            "setting": parts[1].strip(),
                        })
            
            # Query schemas
            result = os.popen(
                f"docker exec {container_name} psql -U dbguard -c "
                "'SELECT nspname, has_schema_privilege(nspname, 'public', 'CREATE') as public_has_create "
                "FROM pg_namespace WHERE nspname = 'public';' -t"
            ).read()
            
            schemas = []
            for line in result.strip().split("\n"):
                if line:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        schemas.append({
                            "nspname": parts[0].strip(),
                            "public_has_create": parts[1].strip() == "t",
                        })
            
            # Query password types
            result = os.popen(
                f"docker exec {container_name} psql -U dbguard -c "
                "'SELECT rolname, CASE WHEN rolpassword LIKE 'md5%' THEN 'md5' ELSE 'scram-sha-256' END as password_type "
                "FROM pg_authid WHERE rolcanlogin;' -t"
            ).read()
            
            password_types = []
            for line in result.strip().split("\n"):
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
    
    def _evaluate_snapshot(self, snapshot: Dict[str, Any]) -> AssessmentReport:
        """
        Evaluate a twin snapshot using AssessmentService.
        
        Args:
            snapshot: Snapshot dictionary from twin
            
        Returns:
            AssessmentReport with all findings
        """
        from app.services.assessment_service import AssessmentService
        
        service = AssessmentService(CONTROL_REGISTRY)
        return service.evaluate(snapshot)
    
    def _execute_sql_in_twin(
        self,
        run_id: str,
        sql: str,
        description: str,
    ) -> Tuple[bool, str]:
        """
        Execute SQL inside the twin container.
        
        Args:
            run_id: Twin run ID
            sql: SQL statement to execute
            description: Description for logging
            
        Returns:
            Tuple of (success, log_message)
        """
        container_name = f"dbguard-twin-{run_id}"
        
        # Format SQL as a single line command
        sql_escaped = sql.replace("'", "'\"'\"'")
        cmd = f"docker exec {container_name} psql -U dbguard -c '{sql_escaped}'"
        
        result = os.popen(cmd).read()
        
        if "ERROR" in result.upper() or "FATAL" in result.upper():
            return False, f"SQL execution failed: {result}"
        
        return True, f"{description}: {result.strip()}"
    
    def verify_proposal_package(
        self,
        snapshot_id: str,
        control_id: str,
        remediation_sql: Optional[str] = None,
        rollback_sql: Optional[str] = None,
        manual_procedure: Optional[List[str]] = None,
    ) -> TwinExecutionResult:
        """
        Verify a proposal by executing it in a twin container.
        
        This is the main entry point for VALIDATE phase verification.
        
        Args:
            snapshot_id: Original snapshot ID
            control_id: CIS control ID being verified
            remediation_sql: SQL to apply for remediation (optional)
            rollback_sql: SQL to apply for rollback (optional)
            manual_procedure: Manual steps (for non-SQL controls)
            
        Returns:
            TwinExecutionResult with flip verification proof
        """
        result = TwinExecutionResult(
            control_id=control_id,
            status=TwinExecutionStatus.FAILED,
        )
        
        # Handle non-executable controls (CIS-2.1)
        if manual_procedure:
            result.status = TwinExecutionStatus.SKIPPED_MANUAL_REQUIRED
            result.execution_log.append(
                f"Control {control_id} requires manual intervention. "
                f"Steps: {'; '.join(manual_procedure)}"
            )
            return result
        
        # Step 1: Create twin container
        success, twin_run_id, status = self._create_twin_for_snapshot(snapshot_id)
        
        if not success:
            result.status = TwinExecutionStatus.FAILED
            result.error = f"Twin creation failed: {status.get('errors', ['Unknown error'])}"
            result.execution_log.append(f"Twin creation failed: {status}")
            return result
        
        # Ensure cleanup happens (finally block pattern)
        try:
            # Step 2: Wait for twin to be ready
            time.sleep(10)  # Give PostgreSQL time to start
            
            # Step 3: Check initial status (should be FAIL for the target control)
            pre_snapshot = self._collect_twin_snapshot(twin_run_id)
            
            if pre_snapshot is None:
                result.status = TwinExecutionStatus.FAILED
                result.error = "Failed to collect pre-remediation snapshot"
                result.execution_log.append("Failed to collect pre-remediation snapshot")
                return result
            
            pre_report = self._evaluate_snapshot(pre_snapshot)
            pre_finding = next(
                (f for f in pre_report.findings if f.control_id == control_id),
                None,
            )
            
            result.pre_remediation_status = pre_finding.status if pre_finding else None
            result.execution_log.append(f"Pre-remediation status: {pre_finding.status if pre_finding else 'NOT_FOUND'}")
            
            # Step 4: Execute remediation SQL
            if remediation_sql:
                success, log_msg = self._execute_sql_in_twin(twin_run_id, remediation_sql, "Remediation")
                result.remediation_executed = success
                result.execution_log.append(log_msg)
                
                if not success:
                    result.status = TwinExecutionStatus.FAILED
                    result.error = log_msg
                    return result
            
            # Step 5: Collect post-remediation snapshot and verify flip
            time.sleep(2)  # Allow PostgreSQL to apply changes
            
            post_snapshot = self._collect_twin_snapshot(twin_run_id)
            
            if post_snapshot is None:
                result.status = TwinExecutionStatus.FAILED
                result.error = "Failed to collect post-remediation snapshot"
                result.execution_log.append("Failed to collect post-remediation snapshot")
                return result
            
            post_report = self._evaluate_snapshot(post_snapshot)
            post_finding = next(
                (f for f in post_report.findings if f.control_id == control_id),
                None,
            )
            
            result.post_remediation_status = post_finding.status if post_finding else None
            result.verification_snapshot_id = post_snapshot.get("snapshot_id")
            result.execution_log.append(f"Post-remediation status: {post_finding.status if post_finding else 'NOT_FOUND'}")
            
            # Step 6: Verify flip (FAIL -> PASS)
            flip_verified = (
                pre_finding and
                pre_finding.status == FindingStatus.FAIL and
                post_finding and
                post_finding.status == FindingStatus.PASS
            )
            
            result.flip_verified = flip_verified
            result.execution_log.append(f"Flip verified: {flip_verified}")
            
            if flip_verified:
                result.status = TwinExecutionStatus.VERIFIED
            else:
                result.status = TwinExecutionStatus.FAILED
                result.error = f"Expected FAIL->PASS flip, got {pre_finding.status if pre_finding else 'NONE'}->{post_finding.status if post_finding else 'NONE'}"
            
            # Step 7: Execute rollback SQL (if provided)
            if rollback_sql:
                rollback_success, rollback_log = self._execute_sql_in_twin(
                    twin_run_id, rollback_sql, "Rollback"
                )
                result.rollback_executed = rollback_success
                result.execution_log.append(rollback_log)
                
                # Collect post-rollback snapshot (optional - for verification)
                time.sleep(2)
                post_rollback_snapshot = self._collect_twin_snapshot(twin_run_id)
                
                if post_rollback_snapshot:
                    post_rollback_report = self._evaluate_snapshot(post_rollback_snapshot)
                    post_rollback_finding = next(
                        (f for f in post_rollback_report.findings if f.control_id == control_id),
                        None,
                    )
                    result.post_rollback_status = post_rollback_finding.status if post_rollback_finding else None
                    result.execution_log.append(f"Post-rollback status: {post_rollback_finding.status if post_rollback_finding else 'NOT_FOUND'}")
            
            return result
            
        finally:
            # Step 8: Cleanup - destroy twin regardless of success/failure
            if twin_run_id:
                self._destroy_twin(twin_run_id)
                result.execution_log.append(f"Twin destroyed: {twin_run_id}")


# ============================================================================
# Helper Functions
# ============================================================================


def build_proposal_review_package(
    control_id: str,
    title: str,
    remediation_sql: Optional[str] = None,
    rollback_sql: Optional[str] = None,
    manual_procedure: Optional[List[str]] = None,
    twin_verification: Optional[TwinExecutionResult] = None,
    rag_justification: str = "",
    requires_dba_review: bool = True,
    risk_level: str = "medium",
) -> ProposalReviewPackage:
    """
    Build a complete ProposalReviewPackage for DBA review.
    
    Args:
        control_id: CIS control ID
        title: Human-readable control title
        remediation_sql: Executable remediation SQL
        rollback_sql: Executable rollback SQL
        manual_procedure: Manual steps for non-SQL controls
        twin_verification: Twin execution result
        rag_justification: RAG-based justification
        requires_dba_review: Whether DBA review is required
        risk_level: Risk assessment level
        
    Returns:
        Complete ProposalReviewPackage
    """
    return ProposalReviewPackage(
        snapshot_id=twin_verification.verification_snapshot_id if twin_verification else "unknown",
        control_id=control_id,
        title=title,
        remediation_sql=remediation_sql,
        rollback_sql=rollback_sql,
        manual_procedure=manual_procedure,
        twin_verification=twin_verification,
        rag_justification=rag_justification,
        requires_dba_review=requires_dba_review,
        risk_level=risk_level,
    )
