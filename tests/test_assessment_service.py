"""Unit tests for ASSESS evaluation engine.

Tests cover:
- PASS findings for the spec-derived CIS controls and DBGuard supplementary checks
- FAIL findings with correct template mapping
- GAPPED findings (null evidence + gap record)
- MANUAL_REVIEW for non-SQL controls (DBGUARD-MD5-PASSWORDS) and specs without a check

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
    ControlMetadata,
    Finding,
    FindingStatus,
)
from app.services.assessment_service import AssessmentService
from catalog.controls.assess.registry import CONTROL_REGISTRY, LEGACY_CONTROL_IDS, get_control

LOG_CONNECTIONS = "cis-pg17-v1.1.0:3.1.20"
PUBLIC_SCHEMA = "DBGUARD-PUBLIC-SCHEMA-CREATE"
MD5 = "DBGUARD-MD5-PASSWORDS"
# 15 installed CIS PG17 specs (12 automated, 1 needs_capability, 2 manual_checklist)
# + 2 supplementary checks.
TOTAL_CONTROLS = 17
# Specs without an automated check: 3.1.14 (needs_capability), 3.1.12 and 7.2 (manual_checklist).
NON_AUTOMATED_SPECS = 3
# Passing values for every automated spec setting.
PASSING_SETTINGS = [
    {"name": "log_connections", "setting": "on"},
    {"name": "log_disconnections", "setting": "on"},
    {"name": "debug_print_parse", "setting": "off"},
    {"name": "log_statement", "setting": "ddl"},
    {"name": "ssl_min_protocol_version", "setting": "TLSv1.2"},
    {"name": "log_truncate_on_rotation", "setting": "on"},
    {"name": "syslog_sequence_numbers", "setting": "on"},
    {"name": "debug_print_rewritten", "setting": "off"},
    {"name": "debug_print_plan", "setting": "off"},
    {"name": "debug_pretty_print", "setting": "on"},
    {"name": "log_error_verbosity", "setting": "verbose"},
    {"name": "log_hostname", "setting": "off"},
]


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
# CIS PG17 3.1.20 (spec-derived): log_connections parameter state
# ============================================================================


class TestLogConnectionsSpec:
    """Tests for cis-pg17-v1.1.0:3.1.20: log_connections parameter state."""

    def test_pass_when_log_connections_is_on(self, assessment_service, base_snapshot):
        """Test PASS when log_connections is set to 'on'."""
        base_snapshot["settings"] = [
            {"name": "log_connections", "setting": "on"},
            {"name": "password_encryption", "setting": "scram-sha-256"},
        ]

        report = assessment_service.evaluate(base_snapshot)

        assert isinstance(report, AssessmentReport)
        assert report.summary.total == TOTAL_CONTROLS

        cis_312_finding = next(
            f for f in report.findings if f.control_id == LOG_CONNECTIONS
        )

        assert cis_312_finding.status == FindingStatus.PASS
        assert cis_312_finding.title == "Ensure 'log_connections' is enabled"
        assert "set to 'on'" in cis_312_finding.rationale
        assert cis_312_finding.evidence_found == {"log_connections": "on"}
        assert cis_312_finding.control_metadata is None
        assert cis_312_finding.is_gapped is False

    def test_gapped_when_log_connections_not_present(self, assessment_service, base_snapshot):
        """Test GAPPED when log_connections is not present in settings (should always be collected)."""
        base_snapshot["settings"] = [
            {"name": "password_encryption", "setting": "scram-sha-256"},
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_312_finding = next(
            f for f in report.findings if f.control_id == LOG_CONNECTIONS
        )

        assert cis_312_finding.status == FindingStatus.GAPPED
        assert "log_connections is not present in settings list" in cis_312_finding.rationale
        assert "settings_found" in cis_312_finding.evidence_found
        assert cis_312_finding.evidence_found["log_connections"] is None
        assert cis_312_finding.is_gapped is True

    def test_fail_when_log_connections_is_off(self, assessment_service, base_snapshot):
        """Test FAIL when log_connections is set to 'off'."""
        base_snapshot["settings"] = [
            {"name": "log_connections", "setting": "off"},
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_312_finding = next(
            f for f in report.findings if f.control_id == LOG_CONNECTIONS
        )

        assert cis_312_finding.status == FindingStatus.FAIL
        assert "set to 'off', should be 'on'" in cis_312_finding.rationale
        assert cis_312_finding.evidence_found == {"log_connections": "off"}

        # Verify ControlMetadata with template_id is correctly generated
        assert cis_312_finding.control_metadata is not None
        assert isinstance(cis_312_finding.control_metadata, ControlMetadata)
        assert cis_312_finding.control_metadata.template_id == "SET_CONFIG_PARAMETER"
        assert cis_312_finding.control_metadata.template_version == 1
        assert cis_312_finding.control_metadata.is_automatable is True
        assert cis_312_finding.control_metadata.risk_level == "low"
        assert cis_312_finding.control_metadata.requires_dba_review is True

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
            f for f in report.findings if f.control_id == LOG_CONNECTIONS
        )

        assert cis_312_finding.status == FindingStatus.GAPPED
        assert "Collector could not retrieve settings (gap: insufficient_privilege)" in cis_312_finding.rationale
        assert cis_312_finding.evidence_found is None
        assert cis_312_finding.control_metadata is None
        assert cis_312_finding.is_gapped is True


# ============================================================================
# DBGuard supplementary check (not CIS): Revoke PUBLIC schema CREATE grant
# ============================================================================


class TestPublicSchemaCreate:
    """Tests for DBGUARD-PUBLIC-SCHEMA-CREATE: Revoke PUBLIC schema CREATE grant."""

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
            f for f in report.findings if f.control_id == PUBLIC_SCHEMA
        )

        assert cis_411_finding.status == FindingStatus.PASS
        assert "PUBLIC does not have CREATE privilege" in cis_411_finding.rationale
        assert cis_411_finding.evidence_found == {"public_has_create": False, "schema": "public"}
        assert cis_411_finding.control_metadata is None

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
            f for f in report.findings if f.control_id == PUBLIC_SCHEMA
        )

        assert cis_411_finding.status == FindingStatus.FAIL
        assert "PUBLIC has CREATE privilege" in cis_411_finding.rationale
        assert cis_411_finding.evidence_found == {"public_has_create": True, "schema": "public"}

        # Verify ControlMetadata with template_id is correctly generated
        assert cis_411_finding.control_metadata is not None
        assert isinstance(cis_411_finding.control_metadata, ControlMetadata)
        assert cis_411_finding.control_metadata.template_id == "REVOKE_SCHEMA_PRIVILEGE"
        assert cis_411_finding.control_metadata.template_version == 1
        assert cis_411_finding.control_metadata.is_automatable is True
        assert cis_411_finding.control_metadata.risk_level == "low"
        assert cis_411_finding.control_metadata.requires_dba_review is True

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
            f for f in report.findings if f.control_id == PUBLIC_SCHEMA
        )

        assert cis_411_finding.status == FindingStatus.GAPPED
        assert "Collector could not retrieve schema information" in cis_411_finding.rationale
        assert cis_411_finding.evidence_found is None
        assert cis_411_finding.control_metadata is None
        assert cis_411_finding.is_gapped is True


# ============================================================================
# DBGuard supplementary check (not CIS): Migrate md5 passwords to scram-sha-256
# ============================================================================


class TestMd5Passwords:
    """Tests for DBGUARD-MD5-PASSWORDS: Migrate md5 passwords to scram-sha-256."""

    def test_pass_when_no_md5_passwords(self, assessment_service, base_snapshot):
        """Test PASS when no users use MD5 password encryption."""
        base_snapshot["password_types"] = [
            {"rolname": "admin", "password_type": "scram-sha-256", "rolvaliduntil": None},
            {"rolname": "app_user", "password_type": "scram-sha-256", "rolvaliduntil": None},
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_21_finding = next(
            f for f in report.findings if f.control_id == MD5
        )

        assert cis_21_finding.status == FindingStatus.PASS
        assert "All login roles use SCRAM-SHA-256" in cis_21_finding.rationale
        assert cis_21_finding.evidence_found["md5_password_count"] == 0
        assert cis_21_finding.evidence_found["scram_password_count"] == 2
        assert cis_21_finding.control_metadata is None

    def test_manual_review_when_md5_passwords_exist(self, assessment_service, base_snapshot):
        """Test MANUAL_REVIEW when users use MD5 password encryption."""
        base_snapshot["password_types"] = [
            {"rolname": "legacy_user", "password_type": "md5", "rolvaliduntil": None},
            {"rolname": "admin", "password_type": "scram-sha-256", "rolvaliduntil": None},
        ]

        report = assessment_service.evaluate(base_snapshot)

        cis_21_finding = next(
            f for f in report.findings if f.control_id == MD5
        )

        assert cis_21_finding.status == FindingStatus.MANUAL_REVIEW
        assert "1 user(s) still using MD5 password encryption" in cis_21_finding.rationale
        assert cis_21_finding.evidence_found["md5_password_count"] == 1
        assert cis_21_finding.evidence_found["scram_password_count"] == 1

        # Verify ControlMetadata with template_id for MANUAL_PROCEDURE
        assert cis_21_finding.control_metadata is not None
        assert isinstance(cis_21_finding.control_metadata, ControlMetadata)
        assert cis_21_finding.control_metadata.template_id == "MANUAL_PROCEDURE"
        assert cis_21_finding.control_metadata.template_version == 1
        assert cis_21_finding.control_metadata.is_automatable is False
        assert cis_21_finding.control_metadata.risk_level == "high"
        assert cis_21_finding.control_metadata.requires_dba_review is True

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
            f for f in report.findings if f.control_id == MD5
        )

        assert cis_21_finding.status == FindingStatus.MANUAL_REVIEW
        assert "Collector could not retrieve password types" in cis_21_finding.rationale
        assert cis_21_finding.evidence_found is None

        # Verify ControlMetadata with template_id for MANUAL_PROCEDURE
        assert cis_21_finding.control_metadata is not None
        assert isinstance(cis_21_finding.control_metadata, ControlMetadata)
        assert cis_21_finding.control_metadata.template_id == "MANUAL_PROCEDURE"
        assert cis_21_finding.control_metadata.template_version == 1
        assert cis_21_finding.control_metadata.is_automatable is False
        assert cis_21_finding.control_metadata.risk_level == "high"
        assert cis_21_finding.control_metadata.requires_dba_review is True
        assert cis_21_finding.is_gapped is True

    def test_manual_review_when_password_types_null_without_gap_record(self, assessment_service, base_snapshot):
        """Test MANUAL_REVIEW when password_types is null without gap record."""
        base_snapshot["password_types"] = None
        base_snapshot["gaps"] = []  # No matching gap record

        report = assessment_service.evaluate(base_snapshot)

        cis_21_finding = next(
            f for f in report.findings if f.control_id == MD5
        )

        assert cis_21_finding.status == FindingStatus.MANUAL_REVIEW
        assert "Collector could not retrieve password types" in cis_21_finding.rationale
        assert cis_21_finding.evidence_found is None
        assert cis_21_finding.is_gapped is False

        # Verify ControlMetadata with template_id for MANUAL_PROCEDURE
        assert cis_21_finding.control_metadata is not None
        assert isinstance(cis_21_finding.control_metadata, ControlMetadata)
        assert cis_21_finding.control_metadata.template_id == "MANUAL_PROCEDURE"
        assert cis_21_finding.control_metadata.template_version == 1
        assert cis_21_finding.control_metadata.is_automatable is False
        assert cis_21_finding.control_metadata.risk_level == "high"
        assert cis_21_finding.control_metadata.requires_dba_review is True


# ============================================================================
# Summary Tests
# ============================================================================


class TestAssessmentSummary:
    """Tests for AssessmentSummary counts."""

    def test_summary_counts_when_all_pass(self, assessment_service, base_snapshot):
        """Test summary counts when all controls pass."""
        base_snapshot["settings"] = PASSING_SETTINGS
        base_snapshot["schemas"] = [{"nspname": "public", "public_has_create": False}]
        base_snapshot["password_types"] = [
            {"rolname": "user1", "password_type": "scram-sha-256"}
        ]

        report = assessment_service.evaluate(base_snapshot)

        assert report.summary.total == TOTAL_CONTROLS
        assert report.summary.pass_count == 14  # 12 automated specs + public schema + md5
        assert report.summary.fail_count == 0
        assert report.summary.gapped_count == 0
        # 3.1.14 has no automated check yet (needs an ordered comparison);
        # 3.1.12 and 7.2 are manual_checklist.
        assert report.summary.manual_review_count == NON_AUTOMATED_SPECS

    def test_summary_counts_mixed_results(self, assessment_service, base_snapshot):
        """Test summary counts with mixed PASS/FAIL/MANUAL_REVIEW results."""
        base_snapshot["settings"] = [dict(row) for row in PASSING_SETTINGS]
        base_snapshot["settings"][0]["setting"] = "off"  # log_connections FAIL
        base_snapshot["schemas"] = [{"nspname": "public", "public_has_create": False}]  # PASS
        base_snapshot["password_types"] = [{"rolname": "user1", "password_type": "md5"}]  # MANUAL_REVIEW

        report = assessment_service.evaluate(base_snapshot)

        assert report.summary.total == TOTAL_CONTROLS
        assert report.summary.pass_count == 12  # 11 automated specs + public schema
        assert report.summary.fail_count == 1
        assert report.summary.gapped_count == 0
        assert report.summary.manual_review_count == 4  # md5 passwords + 3.1.14, 3.1.12, 7.2

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

        # Note: DBGUARD-MD5-PASSWORDS is always MANUAL_REVIEW (non-SQL manual procedure)
        # even when data cannot be collected; so is spec 3.1.14 (no automated check yet).
        assert report.summary.total == TOTAL_CONTROLS
        assert report.summary.pass_count == 0
        assert report.summary.fail_count == 0
        assert report.summary.gapped_count == 13  # 12 automated specs + public schema
        assert report.summary.manual_review_count == 4  # md5 + 3.1.14, 3.1.12, 7.2


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

        # log_connections (3.1.20) is gapped
        assert findings_by_id[LOG_CONNECTIONS].is_gapped is True

        # The public schema check is not gapped (schemas present)
        assert findings_by_id[PUBLIC_SCHEMA].is_gapped is False

        # The md5 password check is gapped
        assert findings_by_id[MD5].is_gapped is True


# ============================================================================
# One rulebook: CIS findings come from the spec catalog
# ============================================================================


class TestSingleRulebook:
    """The ASSESS registry's CIS rules are generated from catalog/specs."""

    def test_every_installed_spec_is_a_control(self):
        from pathlib import Path
        specs = Path(__file__).resolve().parents[1] / "catalog/specs/cis-pg17-v1.1.0"
        spec_ids = {f"cis-pg17-v1.1.0:{p.stem}" for p in specs.glob("*.yaml")}
        assert spec_ids <= set(CONTROL_REGISTRY)
        assert set(CONTROL_REGISTRY) - spec_ids == {PUBLIC_SCHEMA, MD5}

    def test_no_mislabelled_cis_ids_remain(self):
        assert not [cid for cid in CONTROL_REGISTRY if cid.startswith("CIS-")]

    def test_legacy_ids_resolve_to_current_controls(self):
        assert get_control("CIS-3.1.2").control_id == LOG_CONNECTIONS
        assert get_control("CIS-4.1.1").control_id == PUBLIC_SCHEMA
        assert get_control("CIS-2.1").control_id == MD5
        assert set(LEGACY_CONTROL_IDS.values()) <= set(CONTROL_REGISTRY)

    def test_spec_operator_is_used(self, assessment_service, base_snapshot):
        """3.1.25 uses not_equals 'none'; 6.9 uses 'in' TLSv1.2/TLSv1.3."""
        base_snapshot["settings"] = [{"name": "log_statement", "setting": "none"},
                                     {"name": "ssl_min_protocol_version", "setting": "TLSv1.1"}]
        findings = {f.control_id: f for f in assessment_service.evaluate(base_snapshot).findings}
        assert findings["cis-pg17-v1.1.0:3.1.25"].status == FindingStatus.FAIL
        assert findings["cis-pg17-v1.1.0:6.9"].status == FindingStatus.FAIL
        base_snapshot["settings"] = [{"name": "log_statement", "setting": "mod"},
                                     {"name": "ssl_min_protocol_version", "setting": "TLSv1.3"}]
        findings = {f.control_id: f for f in assessment_service.evaluate(base_snapshot).findings}
        assert findings["cis-pg17-v1.1.0:3.1.25"].status == FindingStatus.PASS
        assert findings["cis-pg17-v1.1.0:6.9"].status == FindingStatus.PASS

    @pytest.mark.parametrize("row", [
        {"name": "log_connections", "setting": "on", "sanitised": True},
        {"name": "log_connections", "setting": "on", "unit": "ms"},
        {"name": "log_connections", "setting": "on", "vartype": "integer"},
        {"name": "log_connections", "setting": None},
    ])
    def test_unreadable_evidence_is_gapped_not_pass(self, assessment_service, base_snapshot, row):
        base_snapshot["settings"] = [row]
        findings = {f.control_id: f for f in assessment_service.evaluate(base_snapshot).findings}
        assert findings[LOG_CONNECTIONS].status == FindingStatus.GAPPED

    def test_wrong_postgres_major_is_gapped(self, assessment_service, base_snapshot):
        base_snapshot["identity"] = {"server_version_num": 160004}
        base_snapshot["settings"] = PASSING_SETTINGS
        findings = {f.control_id: f for f in assessment_service.evaluate(base_snapshot).findings}
        assert findings[LOG_CONNECTIONS].status == FindingStatus.GAPPED
        assert "PostgreSQL 17" in findings[LOG_CONNECTIONS].rationale

    def test_needs_capability_spec_is_manual_review(self, assessment_service, base_snapshot):
        findings = {f.control_id: f for f in assessment_service.evaluate(base_snapshot).findings}
        assert findings["cis-pg17-v1.1.0:3.1.14"].status == FindingStatus.MANUAL_REVIEW
