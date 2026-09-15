"""Tests for the template-driven remediation proposal contract.

Tests cover:
- RemediationProposal contract validation
- Template-driven proposals vs. hardcoded Python actions
- Template selection and parameter validation
- Evidence reference validation
- SQL injection prevention in parameters
"""

import pytest
from pydantic import ValidationError

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.models import RemediationProposal, HardenResponse


# ============================================================================
# RemediationProposal Contract Tests
# ============================================================================


class TestRemediationProposalContract:
    """Tests for the RemediationProposal Pydantic model."""

    def test_valid_proposal_with_all_fields(self):
        """Test a complete valid proposal."""
        proposal = RemediationProposal(
            control_id="CIS-3.1.2",
            finding_id="finding-001",
            template_id="set_config_parameter",
            template_version=1,
            parameters={"param_name": "log_connections", "param_value": "on"},
            reasoning="log_connections should be enabled for audit trail",
            evidence_refs=["doc-cis-benchmark-3.1.2"],
        )
        assert proposal.control_id == "CIS-3.1.2"
        assert proposal.finding_id == "finding-001"
        assert proposal.template_id == "set_config_parameter"
        assert proposal.template_version == 1
        assert proposal.parameters["param_name"] == "log_connections"
        assert "audit trail" in proposal.reasoning

    def test_minimal_required_fields(self):
        """Test minimum valid proposal."""
        proposal = RemediationProposal(
            control_id="CIS-4.1.1",
            template_id="revoke_public_access",
            parameters={"schema_name": "public"},
            reasoning="PUBLIC should not have schema privileges",
        )
        assert proposal.control_id == "CIS-4.1.1"
        assert proposal.finding_id is None
        assert proposal.template_version is None
        assert proposal.evidence_refs == []

    def test_template_id_required(self):
        """Test that template_id is required."""
        with pytest.raises(ValidationError) as exc_info:
            RemediationProposal(
                control_id="CIS-3.1.2",
                parameters={},
                reasoning="Test",
            )
        assert "template_id" in str(exc_info.value)

    def test_reasoning_required(self):
        """Test that reasoning is required."""
        with pytest.raises(ValidationError) as exc_info:
            RemediationProposal(
                control_id="CIS-3.1.2",
                template_id="test-template",
                parameters={},
            )
        assert "reasoning" in str(exc_info.value)

    def test_empty_reasoning_rejected(self):
        """Test that empty reasoning is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            RemediationProposal(
                control_id="CIS-3.1.2",
                template_id="test-template",
                parameters={},
                reasoning="",
            )
        assert "reasoning" in str(exc_info.value)

    def test_sql_injection_prevention_drop(self):
        """Test that DROP statements in parameters are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            RemediationProposal(
                control_id="CIS-3.1.2",
                template_id="test",
                parameters={"sql": "DROP TABLE users"},
                reasoning="Test",
            )
        assert "dangerous SQL pattern" in str(exc_info.value)

    def test_sql_injection_prevention_comment(self):
        """Test that SQL comments in parameters are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            RemediationProposal(
                control_id="CIS-3.1.2",
                template_id="test",
                parameters={"value": "x'--"},
                reasoning="Test",
            )
        assert "dangerous SQL pattern" in str(exc_info.value)

    def test_sql_injection_prevention_block_comment(self):
        """Test that block comments in parameters are rejected."""
        with pytest.raises(ValidationError) as exc_info:
            RemediationProposal(
                control_id="CIS-3.1.2",
                template_id="test",
                parameters={"value": "x/*comment*/"},
                reasoning="Test",
            )
        assert "dangerous SQL pattern" in str(exc_info.value)

    def test_sql_injection_prevention_exec(self):
        """Test that EXEC() in parameters is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            RemediationProposal(
                control_id="CIS-3.1.2",
                template_id="test",
                parameters={"value": "EXEC('SELECT 1')"},
                reasoning="Test",
            )
        assert "dangerous SQL pattern" in str(exc_info.value)

    def test_valid_parameter_values_accepted(self):
        """Test that valid parameter values are accepted."""
        # Boolean values
        p1 = RemediationProposal(
            control_id="CIS-3.1.2",
            template_id="test",
            parameters={"enabled": "on"},
            reasoning="Test",
        )
        assert p1.parameters["enabled"] == "on"

        # Numeric values
        p2 = RemediationProposal(
            control_id="CIS-3.1.2",
            template_id="test",
            parameters={"value": "200"},
            reasoning="Test",
        )
        assert p2.parameters["value"] == "200"

        # Valid string
        p3 = RemediationProposal(
            control_id="CIS-3.1.2",
            template_id="test",
            parameters={"role": "auditor"},
            reasoning="Test",
        )
        assert p3.parameters["role"] == "auditor"


class TestHardenResponseContract:
    """Tests for HardenResponse after the contract change."""

    def test_response_contains_all_required_fields(self):
        """Test that HardenResponse has all expected fields."""
        response = HardenResponse(
            status="Proposal compiled for DBA review",
            target_db="postgres",
            ai_plan="SELECT 1;",
            retrieved_templates=["template-1"],
            evidence=[],
            reasoning="Test reasoning",
        )
        assert response.status == "Proposal compiled for DBA review"
        assert response.target_db == "postgres"
        assert response.ai_plan == "SELECT 1;"
        assert response.retrieved_templates == ["template-1"]
        assert response.evidence == []
        assert response.reasoning == "Test reasoning"
        assert response.requires_dba_approval is True

    def test_response_with_optional_evidence(self):
        """Test response with evidence citations."""
        response = HardenResponse(
            status="Proposal compiled for DBA review",
            target_db="postgres",
            ai_plan="SELECT 1;",
            retrieved_templates=["template-1"],
            evidence=[{
                "document_id": "doc-001",
                "title": "CIS Benchmark",
                "similarity_score": 0.95,
            }],
            reasoning="Test",
        )
        assert len(response.evidence) == 1
        assert response.evidence[0]["document_id"] == "doc-001"


# ============================================================================
# Integration Tests: End-to-End Proposal Flow
# ============================================================================


class TestTemplateDrivenProposalFlow:
    """Integration tests for the template-driven proposal workflow."""

    def test_proposal_must_use_approved_template(self):
        """Test that proposals reference approved templates, not generate SQL."""
        # Valid template reference
        proposal = RemediationProposal(
            control_id="CIS-3.1.2",
            template_id="set_config_parameter",
            parameters={"param_name": "log_connections", "param_value": "on"},
            reasoning="Enable connection logging per CIS 3.1.2",
            evidence_refs=["doc-cis-3.1.2"],
        )
        # Proposal is template-driven, not SQL-generating
        assert proposal.template_id == "set_config_parameter"
        assert "SQL" not in proposal.model_dump()
        # Parameters are structured, not raw SQL
        assert proposal.parameters["param_name"] == "log_connections"

    def test_proposal_reasoning_must_be_human_readable(self):
        """Test that reasoning is descriptive, not code."""
        proposal = RemediationProposal(
            control_id="CIS-4.1.1",
            template_id="revoke_public_access",
            parameters={"schema_name": "public"},
            reasoning=(
                "The PUBLIC schema should not have privilege "
                "as per CIS control 4.1.1 to prevent unauthorized table creation."
            ),
        )
        # Reasoning should be natural language, not SQL code
        assert "CIS" in proposal.reasoning
        assert "SELECT 1;" not in proposal.reasoning  # Not SQL

    def test_evidence_references_point_to_documents(self):
        """Test that evidence_refs reference knowledge documents."""
        proposal = RemediationProposal(
            control_id="CIS-2.1",
            template_id="password_encryption",
            parameters={"algorithm": "scram-sha-256"},
            reasoning="Migrate from MD5 to SCRAM",
            evidence_refs=["doc-password-policy-v2", "doc-cis-2.1"],
        )
        assert len(proposal.evidence_refs) == 2
        assert all(isinstance(ref, str) for ref in proposal.evidence_refs)
