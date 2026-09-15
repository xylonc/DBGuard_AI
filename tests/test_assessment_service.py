"""Unit tests for ASSESS evaluation engine.

Tests cover:
- PASS findings for all 3 target controls
- FAIL findings with correct TypedAction generation
- GAPPED findings (null evidence + gap record)
- MANUAL_REVIEW for non-SQL controls (CIS-2.1)

The ASSESS engine is purely OFFLINE. It evaluates snapshot JSON files stored
in DBGuard. It never connects to a target database or runs live queries.

ABSENT vs. EMPTY invariant:
- [] = collected and empty (verified absence of data)
- null with a matching entry in gaps = could not collect (unknown evidence)
A gapped control MUST evaluate to GAPPED / MANUAL_REVIEW, NEVER a false PASS.
"""

import pytest
from app.models import (
    AssessmentReport,
    AssessmentSummary,
    Finding,
    FindingStatus,
    ManualProcedureAction,
    RevokeSchemaPrivilegeAction,
    SetConfigParameterAction,
)
from app.services.assessment_service import AssessmentService
from catalog.controls.assess.registry import CONTROL_REGISTRY


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def assessment_service():
    """Create an AssessmentService with the control registry."""
    return AssessmentService(CONTROL_REGISTRY)


@pytest.fixture
def base_snapshot():
    """Base snapshot with minimal required fields."""
    return {
        "snapshot_id": "snap-test-001",
        "settings": [],
        "schemas": [],
        "password_types": [],
        "gaps": [],
    }


# ============================================================================
# CIS-3.1.2 Tests: log_connections parameter state
# ============================================================================


class TestCIS312LogConnections:
    """Tests for CIS-3.1.2: log_connections parameter state."""

    def test_pass_when_log_connections_is_on(self, assessment_service, base_snapshot):
        """Test PASS when log_connections is set to 'on'."""
        base_snapshot["settings"] = [
            {"name": "log_connections", "setting": "on"},
            {"name": "password_encryption", "setting": "scram-sha-256"},
        ]

        report = assessment_service.evaluate(base_snapshot)

        assert isinstance(report, AssessmentReport)
        assert report.summary.total == 3

        cis_312_finding = next(
            f for f in report.findings if f.control_id == "CIS-3.1.2"
        )

        assert cis_312_finding.status == FindingStatus.PASS
        assert cis_312_finding.title == "Ensure log_connections is enabled"
        assert "set to 'on'" in cis_312_finding.rationale
        assert cis_312_finding.evidence_found == {"log_connections": "on"}
        assert cis_312_finding.typed_action is None
        assert cis_312_finding.is_gapped is False

    def test_pass_when_log_connections_not_present(self, assessment_service, base_snapshot):
        """Test PASS when log_connections is not present in settings (defaults)."""
        base_snapshot["settings"] = [
            {"name": "password_encryption", "setting": "scram-sha-256"},
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_312_finding = next(
            f for f in report.findings if f.control_id == "CIS-3.1.2"
        )

        assert cis_312_finding.status == FindingStatus.PASS
        assert cis_312_finding.rationale == "log_connections is not present in settings (defaults to off but not required to be on)"
        assert cis_312_finding.evidence_found == {"log_connections": None}

    def test_fail_when_log_connections_is_off(self, assessment_service, base_snapshot):
        """Test FAIL when log_connections is set to 'off'."""
        base_snapshot["settings"] = [
            {"name": "log_connections", "setting": "off"},
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_312_finding = next(
            f for f in report.findings if f.control_id == "CIS-3.1.2"
        )

        assert cis_312_finding.status == FindingStatus.FAIL
        assert "set to 'off', should be 'on'" in cis_312_finding.rationale
        assert cis_312_finding.evidence_found == {"log_connections": "off"}

        # Verify TypedAction is correctly generated
        assert cis_312_finding.typed_action is not None
        assert isinstance(cis_312_finding.typed_action, SetConfigParameterAction)
        assert cis_312_finding.typed_action.name == "log_connections"
        assert cis_312_finding.typed_action.value == "on"
        assert cis_312_finding.typed_action.description == "Enable connection logging for security auditing"
        assert cis_312_finding.typed_action.action_type == "SET_CONFIG_PARAMETER"

    def test_gapped_when_settings_is_null_with_gap_record(self, assessment_service, base_snapshot):
        """Test GAPPED when settings section is null and gap record exists."""
        base_snapshot["settings"] = None
        base_snapshot["gaps"] = [
            {
                "section": "settings",
                "reason": "insufficient_privilege",
                "remediation": "GRANT pg_read_all_settings",
            }
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_312_finding = next(
            f for f in report.findings if f.control_id == "CIS-3.1.2"
        )

        assert cis_312_finding.status == FindingStatus.GAPPED
        assert cis_312_finding.rationale == "Collector could not retrieve settings (settings section is null)"
        assert cis_312_finding.evidence_found is None
        assert cis_312_finding.typed_action is None
        assert cis_312_finding.is_gapped is True


# ============================================================================
# CIS-4.1.1 Tests: Revoke PUBLIC schema CREATE grant
# ============================================================================


class TestCIS411PublicSchemaCreate:
    """Tests for CIS-4.1.1: Revoke PUBLIC schema CREATE grant."""

    def test_pass_when_public_has_no_create(self, assessment_service, base_snapshot):
        """Test PASS when PUBLIC does not have CREATE privilege."""
        base_snapshot["schemas"] = [
            {
                "nspname": "public",
                "owner": "postgres",
                "nspacl": [],
                "public_has_create": False,
                "public_has_usage": True,
            }
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_411_finding = next(
            f for f in report.findings if f.control_id == "CIS-4.1.1"
        )

        assert cis_411_finding.status == FindingStatus.PASS
        assert "PUBLIC does not have CREATE privilege" in cis_411_finding.rationale
        assert cis_411_finding.evidence_found == {"public_has_create": False, "schema": "public"}
        assert cis_411_finding.typed_action is None

    def test_fail_when_public_has_create(self, assessment_service, base_snapshot):
        """Test FAIL when PUBLIC has CREATE privilege on public schema."""
        base_snapshot["schemas"] = [
            {
                "nspname": "public",
                "owner": "postgres",
                "nspacl": [],
                "public_has_create": True,
                "public_has_usage": True,
            }
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_411_finding = next(
            f for f in report.findings if f.control_id == "CIS-4.1.1"
        )

        assert cis_411_finding.status == FindingStatus.FAIL
        assert "PUBLIC has CREATE privilege" in cis_411_finding.rationale
        assert cis_411_finding.evidence_found == {"public_has_create": True, "schema": "public"}

        # Verify TypedAction is correctly generated
        assert cis_411_finding.typed_action is not None
        assert isinstance(cis_411_finding.typed_action, RevokeSchemaPrivilegeAction)
        assert cis_411_finding.typed_action.schema_name == "public"
        assert cis_411_finding.typed_action.privilege == "CREATE"
        assert cis_411_finding.typed_action.grantee == "PUBLIC"
        assert cis_411_finding.typed_action.action_type == "REVOKE_SCHEMA_PRIVILEGE"

    def test_gapped_when_schemas_is_null_with_gap_record(self, assessment_service, base_snapshot):
        """Test GAPPED when schemas section is null and gap record exists."""
        base_snapshot["schemas"] = None
        base_snapshot["gaps"] = [
            {
                "section": "schemas",
                "reason": "insufficient_privilege",
                "remediation": "grant explicit read access",
            }
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_411_finding = next(
            f for f in report.findings if f.control_id == "CIS-4.1.1"
        )

        assert cis_411_finding.status == FindingStatus.GAPPED
        assert "Collector could not retrieve schema information" in cis_411_finding.rationale
        assert cis_411_finding.evidence_found is None
        assert cis_411_finding.typed_action is None
        assert cis_411_finding.is_gapped is True


# ============================================================================
# CIS-2.1 Tests: Migrate md5 passwords to scram-sha-256
# ============================================================================


class TestCIS21PasswordEncryption:
    """Tests for CIS-2.1: Migrate md5 passwords to scram-sha-256."""

    def test_pass_when_no_md5_passwords(self, assessment_service, base_snapshot):
        """Test PASS when no users use MD5 password encryption."""
        base_snapshot["password_types"] = [
            {"rolname": "admin", "password_type": "scram-sha-256", "rolvaliduntil": None},
            {"rolname": "app_user", "password_type": "scram-sha-256", "rolvaliduntil": None},
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_21_finding = next(
            f for f in report.findings if f.control_id == "CIS-2.1"
        )

        assert cis_21_finding.status == FindingStatus.PASS
        assert "All users use SCRAM-SHA-256" in cis_21_finding.rationale
        assert cis_21_finding.evidence_found == {"md5_password_count": 0}
        assert cis_21_finding.typed_action is None

    def test_manual_review_when_md5_passwords_exist(self, assessment_service, base_snapshot):
        """Test MANUAL_REVIEW when users use MD5 password encryption."""
        base_snapshot["password_types"] = [
            {"rolname": "legacy_user", "password_type": "md5", "rolvaliduntil": None},
            {"rolname": "admin", "password_type": "scram-sha-256", "rolvaliduntil": None},
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_21_finding = next(
            f for f in report.findings if f.control_id == "CIS-2.1"
        )

        assert cis_21_finding.status == FindingStatus.MANUAL_REVIEW
        assert "1 user(s) still using MD5 password encryption" in cis_21_finding.rationale
        assert cis_21_finding.evidence_found == {"md5_password_count": 1}

        # Verify TypedAction is MANUAL_PROCEDURE with correct steps
        assert cis_21_finding.typed_action is not None
        assert cis_21_finding.typed_action.action_type == "MANUAL_PROCEDURE"
        assert isinstance(cis_21_finding.typed_action, ManualProcedureAction)
        assert hasattr(cis_21_finding.typed_action, "steps")

    def test_manual_review_when_password_types_null_with_gap_record(self, assessment_service, base_snapshot):
        """Test MANUAL_REVIEW when password_types is null and gap record exists."""
        base_snapshot["password_types"] = None
        base_snapshot["gaps"] = [
            {
                "section": "password_types",
                "reason": "insufficient_privilege",
                "remediation": "Run grant_collector_role.sql, or grant the collector membership of a role that can read pg_authid.",
            }
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_21_finding = next(
            f for f in report.findings if f.control_id == "CIS-2.1"
        )

        assert cis_21_finding.status == FindingStatus.MANUAL_REVIEW
        assert "Collector could not retrieve password types" in cis_21_finding.rationale
        assert cis_21_finding.evidence_found is None

        # Verify TypedAction is MANUAL_PROCEDURE
        assert cis_21_finding.typed_action is not None
        assert cis_21_finding.typed_action.action_type == "MANUAL_PROCEDURE"
        assert cis_21_finding.is_gapped is True

    def test_manual_review_when_password_types_null_without_gap_record(self, assessment_service, base_snapshot):
        """Test MANUAL_REVIEW when password_types is null without gap record."""
        base_snapshot["password_types"] = None
        base_snapshot["gaps"] = []  # No matching gap record

        report = assessment_service.evaluate(base_snapshot)

        cis_21_finding = next(
            f for f in report.findings if f.control_id == "CIS-2.1"
        )

        assert cis_21_finding.status == FindingStatus.MANUAL_REVIEW
        assert "Collector could not retrieve password types" in cis_21_finding.rationale
        assert cis_21_finding.evidence_found is None
        assert cis_21_finding.is_gapped is False


# ============================================================================
# Summary Tests
# ============================================================================


class TestAssessmentSummary:
    """Tests for AssessmentSummary counts."""

    def test_summary_counts_when_all_pass(self, assessment_service, base_snapshot):
        """Test summary counts when all controls pass."""
        base_snapshot["settings"] = [{"name": "log_connections", "setting": "on"}]
        base_snapshot["schemas"] = [{"nspname": "public", "public_has_create": False}]
        base_snapshot["password_types"] = [
            {"rolname": "user1", "password_type": "scram-sha-256"}
        ]

        report = assessment_service.evaluate(base_snapshot)

        assert report.summary.total == 3
        assert report.summary.pass_count == 3
        assert report.summary.fail_count == 0
        assert report.summary.gapped_count == 0
        assert report.summary.manual_review_count == 0

    def test_summary_counts_mixed_results(self, assessment_service, base_snapshot):
        """Test summary counts with mixed PASS/FAIL/MANUAL_REVIEW results."""
        base_snapshot["settings"] = [{"name": "log_connections", "setting": "off"}]  # FAIL
        base_snapshot["schemas"] = [{"nspname": "public", "public_has_create": False}]  # PASS
        base_snapshot["password_types"] = [{"rolname": "user1", "password_type": "md5"}]  # MANUAL_REVIEW

        report = assessment_service.evaluate(base_snapshot)

        assert report.summary.total == 3
        assert report.summary.pass_count == 1
        assert report.summary.fail_count == 1
        assert report.summary.gapped_count == 0
        assert report.summary.manual_review_count == 1

    def test_summary_counts_gapped_results(self, assessment_service, base_snapshot):
        """Test summary counts with GAPPED findings."""
        base_snapshot["settings"] = None
        base_snapshot["schemas"] = None
        base_snapshot["password_types"] = None
        base_snapshot["gaps"] = [
            {"section": "settings", "reason": "insufficient_privilege"},
            {"section": "schemas", "reason": "insufficient_privilege"},
            {"section": "password_types", "reason": "insufficient_privilege"},
        ]

        report = assessment_service.evaluate(base_snapshot)

        # Note: CIS-2.1 is always MANUAL_REVIEW (non-SQL manual procedure)
        # even when data cannot be collected
        assert report.summary.total == 3
        assert report.summary.pass_count == 0
        assert report.summary.fail_count == 0
        assert report.summary.gapped_count == 2  # CIS-3.1.2 and CIS-4.1.1
        assert report.summary.manual_review_count == 1  # CIS-2.1


# ============================================================================
# Gapped Control Invariant Tests
# ============================================================================


class TestGappedControlInvariant:
    """Tests enforcing the GAPPED control invariant.

    A gapped control MUST evaluate to GAPPED / MANUAL_REVIEW, NEVER a false PASS.
    """

    def test_gapped_control_never_false_pass(self, assessment_service, base_snapshot):
        """Verify that gapped controls never produce PASS results."""
        base_snapshot["settings"] = None
        base_snapshot["schemas"] = None
        base_snapshot["password_types"] = None
        base_snapshot["gaps"] = [
            {"section": "settings", "reason": "insufficient_privilege"},
            {"section": "schemas", "reason": "insufficient_privilege"},
            {"section": "password_types", "reason": "insufficient_privilege"},
        ]

        report = assessment_service.evaluate(base_snapshot)
        for finding in report.findings:
            # Gapped controls must not be PASS
            assert finding.status != FindingStatus.PASS, (
                f"Control {finding.control_id} was gapped but returned PASS - "
                "this violates the GAPPED invariant"
            )

    def test_findings_have_is_gapped_flag(self, assessment_service, base_snapshot):
        """Verify that findings have the is_gapped flag set correctly."""
        base_snapshot["settings"] = None
        base_snapshot["schemas"] = [{"nspname": "public", "public_has_create": False}]
        base_snapshot["password_types"] = None
        base_snapshot["gaps"] = [
            {"section": "settings", "reason": "insufficient_privilege"},
            {"section": "password_types", "reason": "insufficient_privilege"},
        ]

        report = assessment_service.evaluate(base_snapshot)
        findings_by_id = {f.control_id: f for f in report.findings}

        # CIS-3.1.2 is gapped
        assert findings_by_id["CIS-3.1.2"].is_gapped is True

        # CIS-4.1.1 is not gapped (schemas present)
        assert findings_by_id["CIS-4.1.1"].is_gapped is False

        # CIS-2.1 is gapped
        assert findings_by_id["CIS-2.1"].is_gapped is True
