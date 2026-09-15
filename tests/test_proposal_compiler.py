"""Unit tests for Proposal Compiler.

Tests cover:
- Compilation of SetConfigParameterAction -> exact remediation & rollback SQL
- Compilation of RevokeSchemaPrivilegeAction -> exact privilege revoke & grant rollback
- Compilation of ManualProcedureAction -> is_executable_sql == False, SQL is None
- Full AssessmentReport compilation into ProposalPackage
- Verification that passing findings produce no remediation proposals

The Proposal Compiler is deterministic - SQL is generated programmatically
from validated TypedAction objects, never via free-form LLM string interpolation.
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
from app.proposal_compiler import (
    ProposalCompiler,
    _quote_identifier,
    _quote_value,
    generate_revoke_schema_privilege_sql,
    generate_set_config_parameter_sql,
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def compiler():
    """Create a ProposalCompiler instance."""
    return ProposalCompiler()


@pytest.fixture
def base_snapshot():
    """Base snapshot for testing."""
    return {
        "snapshot_id": "snap-test-001",
    }


# ============================================================================
# SQL Generator Tests
# ============================================================================


class TestSQLGenerators:
    """Tests for deterministic SQL generators."""

    class TestQuoteIdentifier:
        """Tests for _quote_identifier function."""

        def test_simple_identifier(self):
            """Test quoting a simple identifier."""
            assert _quote_identifier("public") == '"public"'

        def test_identifier_with_special_chars(self):
            """Test quoting an identifier with special characters."""
            assert _quote_identifier("my_schema") == '"my_schema"'

        def test_identifier_with_quotes(self):
            """Test escaping internal quotes."""
            assert _quote_identifier('my"table') == '"my""table"'

        def test_empty_identifier(self):
            """Test quoting an empty identifier."""
            assert _quote_identifier("") == '""'

    class TestQuoteValue:
        """Tests for _quote_value function."""

        def test_simple_value(self):
            """Test quoting a simple value."""
            assert _quote_value("on") == "'on'"

        def test_value_with_quotes(self):
            """Test escaping internal quotes."""
            assert _quote_value("value'with'quotes") == "'value''with''quotes'"

        def test_empty_value(self):
            """Test quoting an empty value."""
            assert _quote_value("") == "''"

    class TestGenerateSetConfigParameterSQL:
        """Tests for generate_set_config_parameter_sql."""

        def test_enable_log_connections(self):
            """Test SQL generation for enabling log_connections."""
            action = SetConfigParameterAction(
                name="log_connections",
                value="on",
                description="Enable connection logging",
            )
            remediation_sql, rollback_sql = generate_set_config_parameter_sql(action)

            assert "ALTER SYSTEM SET \"log_connections\" = 'on'" in remediation_sql
            assert "SELECT pg_reload_conf();" in remediation_sql
            assert "ALTER SYSTEM SET \"log_connections\" = 'off'" in rollback_sql

        def test_disable_log_checkpoints(self):
            """Test SQL generation for disabling log_checkpoints."""
            action = SetConfigParameterAction(
                name="log_checkpoints",
                value="off",
                description="Disable checkpoint logging",
            )
            remediation_sql, rollback_sql = generate_set_config_parameter_sql(action)

            assert "ALTER SYSTEM SET \"log_checkpoints\" = 'off'" in remediation_sql
            assert "ALTER SYSTEM SET \"log_checkpoints\" = 'on'" in rollback_sql

        def test_custom_parameter(self):
            """Test SQL generation for a custom parameter."""
            action = SetConfigParameterAction(
                name="max_connections",
                value="200",
                description="Increase max connections",
            )
            remediation_sql, rollback_sql = generate_set_config_parameter_sql(action)

            assert "ALTER SYSTEM SET \"max_connections\" = '200'" in remediation_sql
            assert "<original_max_connections>" in rollback_sql

    class TestGenerateRevokeSchemaPrivilegeSQL:
        """Tests for generate_revoke_schema_privilege_sql."""

        def test_revoke_create_on_public_schema(self):
            """Test SQL generation for revoking CREATE on public schema."""
            action = RevokeSchemaPrivilegeAction(
                schema_name="public",
                privilege="CREATE",
                grantee="PUBLIC",
                description="Revoke CREATE privilege",
            )
            remediation_sql, rollback_sql = generate_revoke_schema_privilege_sql(action)

            assert "REVOKE CREATE ON SCHEMA \"public\" FROM \"PUBLIC\";" == remediation_sql
            assert "GRANT CREATE ON SCHEMA \"public\" TO \"PUBLIC\";" == rollback_sql

        def test_revoke_usage_on_schema(self):
            """Test SQL generation for revoking USAGE on a schema."""
            action = RevokeSchemaPrivilegeAction(
                schema_name="app_data",
                privilege="USAGE",
                grantee="anonymous",
                description="Revoke USAGE privilege",
            )
            remediation_sql, rollback_sql = generate_revoke_schema_privilege_sql(action)

            assert "REVOKE USAGE ON SCHEMA \"app_data\" FROM \"anonymous\";" == remediation_sql
            assert "GRANT USAGE ON SCHEMA \"app_data\" TO \"anonymous\";" == rollback_sql

        def test_invalid_privilege_raises_error(self):
            """Test that invalid privilege types raise an error."""
            action = RevokeSchemaPrivilegeAction(
                schema_name="public",
                privilege="INVALID_PRIV",
                grantee="PUBLIC",
                description="Invalid privilege",
            )

            with pytest.raises(ValueError, match="Invalid privilege type"):
                generate_revoke_schema_privilege_sql(action)


# ============================================================================
# Proposal Compiler Tests
# ============================================================================


class TestProposalCompiler:
    """Tests for ProposalCompiler service."""

    class TestCompileFinding:
        """Tests for compile_finding method."""

        def test_compile_fail_finding_with_set_config_parameter_action(self, compiler):
            """Test compilation of FAIL finding with SetConfigParameterAction."""
            finding = Finding(
                control_id="CIS-3.1.2",
                status=FindingStatus.FAIL,
                title="Ensure log_connections is enabled",
                rationale="log_connections is off",
                evidence_found={"log_connections": "off"},
                typed_action=SetConfigParameterAction(
                    name="log_connections",
                    value="on",
                    description="Enable connection logging",
                ),
                is_gapped=False,
                severity="2B",
            )

            proposal = compiler.compile_finding(finding)

            assert proposal is not None
            assert proposal.control_id == "CIS-3.1.2"
            assert proposal.title == "Ensure log_connections is enabled"
            assert proposal.is_executable_sql is True
            assert "ALTER SYSTEM SET \"log_connections\" = 'on'" in proposal.remediation_sql
            assert "ALTER SYSTEM SET \"log_connections\" = 'off'" in proposal.rollback_sql
            assert proposal.manual_steps is None
            assert proposal.requires_dba_review is True

        def test_compile_fail_finding_with_revoke_schema_privilege_action(self, compiler):
            """Test compilation of FAIL finding with RevokeSchemaPrivilegeAction."""
            finding = Finding(
                control_id="CIS-4.1.1",
                status=FindingStatus.FAIL,
                title="Ensure PUBLIC schema CREATE privilege is revoked",
                rationale="PUBLIC has CREATE privilege",
                evidence_found={"public_has_create": True},
                typed_action=RevokeSchemaPrivilegeAction(
                    schema_name="public",
                    privilege="CREATE",
                    grantee="PUBLIC",
                    description="Revoke CREATE privilege",
                ),
                is_gapped=False,
                severity="2A",
            )

            proposal = compiler.compile_finding(finding)

            assert proposal is not None
            assert proposal.control_id == "CIS-4.1.1"
            assert proposal.is_executable_sql is True
            assert "REVOKE CREATE ON SCHEMA \"public\" FROM \"PUBLIC\";" == proposal.remediation_sql
            assert "GRANT CREATE ON SCHEMA \"public\" TO \"PUBLIC\";" == proposal.rollback_sql
            assert proposal.risk_level == "high"

        def test_compile_manual_review_finding_with_manual_procedure_action(self, compiler):
            """Test compilation of MANUAL_REVIEW finding with ManualProcedureAction."""
            finding = Finding(
                control_id="CIS-2.1",
                status=FindingStatus.MANUAL_REVIEW,
                title="Ensure password encryption uses SCRAM-SHA-256",
                rationale="Users still using MD5",
                evidence_found={"md5_password_count": 2},
                typed_action=ManualProcedureAction(
                    steps=[
                        "Set password_encryption='scram-sha-256' in postgresql.conf",
                        "Rotate all user credentials with new passwords",
                        "Update application connection strings to support SCRAM",
                        "Verify client driver compatibility",
                    ],
                    description="Migrate password encryption from MD5 to SCRAM",
                ),
                is_gapped=False,
                severity="1",
            )

            proposal = compiler.compile_finding(finding)

            assert proposal is not None
            assert proposal.control_id == "CIS-2.1"
            assert proposal.is_executable_sql is False
            assert proposal.remediation_sql is None
            assert proposal.rollback_sql is None
            assert proposal.manual_steps is not None
            assert len(proposal.manual_steps) == 4
            assert "Set password_encryption='scram-sha-256'" in proposal.manual_steps[0]
            assert proposal.risk_level == "high"

        def test_compile_pass_finding_returns_none(self, compiler):
            """Test that PASS findings return None (no proposal needed)."""
            finding = Finding(
                control_id="CIS-3.1.2",
                status=FindingStatus.PASS,
                title="Ensure log_connections is enabled",
                rationale="log_connections is on",
                evidence_found={"log_connections": "on"},
                typed_action=None,
                is_gapped=False,
                severity="2B",
            )

            proposal = compiler.compile_finding(finding)

            assert proposal is None

        def test_compile_gapped_finding_returns_none(self, compiler):
            """Test that GAPPED findings return None (no data to remediate)."""
            finding = Finding(
                control_id="CIS-3.1.2",
                status=FindingStatus.GAPPED,
                title="Ensure log_connections is enabled",
                rationale="Collector could not retrieve settings",
                evidence_found=None,
                typed_action=None,
                is_gapped=True,
                severity="2B",
            )

            proposal = compiler.compile_finding(finding)

            assert proposal is None

        def test_compile_finding_without_typed_action_returns_none(self, compiler):
            """Test that findings without typed_action return None."""
            finding = Finding(
                control_id="CIS-3.1.2",
                status=FindingStatus.FAIL,
                title="Ensure log_connections is enabled",
                rationale="Unknown issue",
                evidence_found=None,
                typed_action=None,
                is_gapped=False,
                severity="2B",
            )

            proposal = compiler.compile_finding(finding)

            assert proposal is None

    class TestCompileReport:
        """Tests for compile_report method."""

        def test_compile_report_with_all_pass(self, compiler, base_snapshot):
            """Test compilation of a report where all controls pass."""
            report = AssessmentReport(
                snapshot_id="snap-001",
                findings=[
                    Finding(
                        control_id="CIS-3.1.2",
                        status=FindingStatus.PASS,
                        title="Ensure log_connections is enabled",
                        rationale="log_connections is on",
                        evidence_found={"log_connections": "on"},
                        typed_action=None,
                        is_gapped=False,
                    ),
                    Finding(
                        control_id="CIS-4.1.1",
                        status=FindingStatus.PASS,
                        title="Ensure PUBLIC schema CREATE privilege is revoked",
                        rationale="PUBLIC does not have CREATE",
                        evidence_found={"public_has_create": False},
                        typed_action=None,
                        is_gapped=False,
                    ),
                    Finding(
                        control_id="CIS-2.1",
                        status=FindingStatus.PASS,
                        title="Ensure password encryption uses SCRAM-SHA-256",
                        rationale="All users use SCRAM",
                        evidence_found={"md5_password_count": 0},
                        typed_action=None,
                        is_gapped=False,
                    ),
                ],
                summary=AssessmentSummary(
                    total=3,
                    pass_count=3,
                    fail_count=0,
                    gapped_count=0,
                    manual_review_count=0,
                ),
            )

            package = compiler.compile_report(report)

            assert package.snapshot_id == "snap-001"
            assert len(package.proposals) == 0
            assert package.summary["total_proposals"] == 0
            assert package.summary["executable_count"] == 0
            assert package.summary["manual_count"] == 0

        def test_compile_report_with_mixed_results(self, compiler, base_snapshot):
            """Test compilation of a report with PASS, FAIL, and MANUAL_REVIEW findings."""
            report = AssessmentReport(
                snapshot_id="snap-002",
                findings=[
                    # FAIL - should produce proposal
                    Finding(
                        control_id="CIS-3.1.2",
                        status=FindingStatus.FAIL,
                        title="Ensure log_connections is enabled",
                        rationale="log_connections is off",
                        evidence_found={"log_connections": "off"},
                        typed_action=SetConfigParameterAction(
                            name="log_connections",
                            value="on",
                            description="Enable connection logging",
                        ),
                        is_gapped=False,
                    ),
                    # PASS - should not produce proposal
                    Finding(
                        control_id="CIS-4.1.1",
                        status=FindingStatus.PASS,
                        title="Ensure PUBLIC schema CREATE privilege is revoked",
                        rationale="PUBLIC does not have CREATE",
                        evidence_found={"public_has_create": False},
                        typed_action=None,
                        is_gapped=False,
                    ),
                    # MANUAL_REVIEW - should produce proposal
                    Finding(
                        control_id="CIS-2.1",
                        status=FindingStatus.MANUAL_REVIEW,
                        title="Ensure password encryption uses SCRAM-SHA-256",
                        rationale="Users still using MD5",
                        evidence_found={"md5_password_count": 1},
                        typed_action=ManualProcedureAction(
                            steps=[
                                "Set password_encryption='scram-sha-256'",
                                "Rotate credentials",
                            ],
                            description="Migrate password encryption",
                        ),
                        is_gapped=False,
                    ),
                ],
                summary=AssessmentSummary(
                    total=3,
                    pass_count=1,
                    fail_count=1,
                    gapped_count=0,
                    manual_review_count=1,
                ),
            )

            package = compiler.compile_report(report)

            assert package.snapshot_id == "snap-002"
            assert len(package.proposals) == 2
            assert package.summary["total_proposals"] == 2
            assert package.summary["executable_count"] == 1  # CIS-3.1.2
            assert package.summary["manual_count"] == 1  # CIS-2.1

            # Verify proposals are in correct order
            proposals_by_id = {p.control_id: p for p in package.proposals}
            assert "CIS-3.1.2" in proposals_by_id
            assert "CIS-2.1" in proposals_by_id
            assert proposals_by_id["CIS-3.1.2"].is_executable_sql is True
            assert proposals_by_id["CIS-2.1"].is_executable_sql is False

        def test_compile_report_with_gapped_findings(self, compiler, base_snapshot):
            """Test that GAPPED findings don't produce proposals."""
            report = AssessmentReport(
                snapshot_id="snap-003",
                findings=[
                    # GAPPED - should not produce proposal
                    Finding(
                        control_id="CIS-3.1.2",
                        status=FindingStatus.GAPPED,
                        title="Ensure log_connections is enabled",
                        rationale="Collector could not retrieve settings",
                        evidence_found=None,
                        typed_action=None,
                        is_gapped=True,
                    ),
                    # PASS - should not produce proposal
                    Finding(
                        control_id="CIS-4.1.1",
                        status=FindingStatus.PASS,
                        title="Ensure PUBLIC schema CREATE privilege is revoked",
                        rationale="PUBLIC does not have CREATE",
                        evidence_found={"public_has_create": False},
                        typed_action=None,
                        is_gapped=False,
                    ),
                ],
                summary=AssessmentSummary(
                    total=2,
                    pass_count=1,
                    fail_count=0,
                    gapped_count=1,
                    manual_review_count=0,
                ),
            )

            package = compiler.compile_report(report)

            assert len(package.proposals) == 0
            assert package.summary["total_proposals"] == 0


# ============================================================================
# Integration Tests: End-to-End Compilation
# ============================================================================


class TestEndToEndCompilation:
    """End-to-end tests for the complete proposal compilation flow."""

    def test_full_assessment_report_to_proposal_package(self):
        """Test the complete flow from AssessmentReport to ProposalPackage."""
        # Create a realistic assessment report with all three control types
        report = AssessmentReport(
            snapshot_id="prod-assessment-2024-09-15",
            findings=[
                # FAIL: CIS-3.1.2
                Finding(
                    control_id="CIS-3.1.2",
                    status=FindingStatus.FAIL,
                    title="Ensure log_connections is enabled",
                    rationale="log_connections is set to 'off'",
                    evidence_found={"name": "log_connections", "setting": "off"},
                    typed_action=SetConfigParameterAction(
                        name="log_connections",
                        value="on",
                        description="Enable connection logging for security auditing",
                    ),
                    is_gapped=False,
                    severity="2B",
                ),
                # FAIL: CIS-4.1.1
                Finding(
                    control_id="CIS-4.1.1",
                    status=FindingStatus.FAIL,
                    title="Ensure PUBLIC schema CREATE privilege is revoked",
                    rationale="PUBLIC has CREATE privilege on public schema",
                    evidence_found={"nspname": "public", "public_has_create": True},
                    typed_action=RevokeSchemaPrivilegeAction(
                        schema_name="public",
                        privilege="CREATE",
                        grantee="PUBLIC",
                        description="Revoke CREATE privilege on public schema from PUBLIC role",
                    ),
                    is_gapped=False,
                    severity="2A",
                ),
                # MANUAL_REVIEW: CIS-2.1
                Finding(
                    control_id="CIS-2.1",
                    status=FindingStatus.MANUAL_REVIEW,
                    title="Ensure password encryption uses SCRAM-SHA-256",
                    rationale="2 user(s) still using MD5 password encryption",
                    evidence_found={"md5_password_count": 2},
                    typed_action=ManualProcedureAction(
                        steps=[
                            "Set password_encryption='scram-sha-256' in postgresql.conf",
                            "Rotate all user credentials with new passwords",
                            "Update application connection strings to support SCRAM",
                            "Verify client driver compatibility",
                        ],
                        description="Migrate password encryption from MD5 to SCRAM-SHA-256",
                    ),
                    is_gapped=False,
                    severity="1",
                ),
                # PASS: Not included in proposals
                Finding(
                    control_id="CIS-1.1.1",
                    status=FindingStatus.PASS,
                    title="Ensure PostgreSQL is updated to latest version",
                    rationale="Running PostgreSQL 16.4 (latest)",
                    evidence_found={"version": "PostgreSQL 16.4"},
                    typed_action=None,
                    is_gapped=False,
                ),
            ],
            summary=AssessmentSummary(
                total=4,
                pass_count=1,
                fail_count=2,
                gapped_count=0,
                manual_review_count=1,
            ),
        )

        # Compile the report
        compiler = ProposalCompiler()
        package = compiler.compile_report(report)

        # Verify package structure
        assert package.snapshot_id == "prod-assessment-2024-09-15"
        assert package.created_at is not None
        assert len(package.proposals) == 3
        assert package.summary["total_proposals"] == 3
        assert package.summary["executable_count"] == 2
        assert package.summary["manual_count"] == 1

        # Verify each proposal
        proposals_by_id = {p.control_id: p for p in package.proposals}

        # CIS-3.1.2: SET_CONFIG_PARAMETER
        prop_312 = proposals_by_id["CIS-3.1.2"]
        assert prop_312.control_id == "CIS-3.1.2"
        assert prop_312.title == "Ensure log_connections is enabled"
        assert prop_312.is_executable_sql is True
        assert "ALTER SYSTEM SET \"log_connections\" = 'on'" in prop_312.remediation_sql
        assert "SELECT pg_reload_conf();" in prop_312.remediation_sql
        assert "ALTER SYSTEM SET \"log_connections\" = 'off'" in prop_312.rollback_sql

        # CIS-4.1.1: REVOKE_SCHEMA_PRIVILEGE
        prop_411 = proposals_by_id["CIS-4.1.1"]
        assert prop_411.control_id == "CIS-4.1.1"
        assert prop_411.title == "Ensure PUBLIC schema CREATE privilege is revoked"
        assert prop_411.is_executable_sql is True
        assert "REVOKE CREATE ON SCHEMA \"public\" FROM \"PUBLIC\";" == prop_411.remediation_sql
        assert "GRANT CREATE ON SCHEMA \"public\" TO \"PUBLIC\";" == prop_411.rollback_sql

        # CIS-2.1: MANUAL_PROCEDURE
        prop_21 = proposals_by_id["CIS-2.1"]
        assert prop_21.control_id == "CIS-2.1"
        assert prop_21.title == "Ensure password encryption uses SCRAM-SHA-256"
        assert prop_21.is_executable_sql is False
        assert prop_21.remediation_sql is None
        assert prop_21.rollback_sql is None
        assert prop_21.manual_steps is not None
        assert len(prop_21.manual_steps) == 4
