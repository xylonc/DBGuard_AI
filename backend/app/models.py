"""Pydantic schemas for the proposal and knowledge APIs."""

from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field, model_validator
from typing import Any, Literal, Optional, Union


class HardenResponse(BaseModel):
    status: str
    target_db: str
    ai_plan: str
    retrieved_templates: list[str] = Field(
        default_factory=list,
        description="Template names retrieved via RAG"
    )
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    reasoning: str = ""
    requires_dba_approval: bool = True


class ProposalCompileRequest(BaseModel):
    """Deterministic proposal compilation requested by the HERMES agent."""

    snapshot_id: str = Field(min_length=1, max_length=64)
    requirement: str = Field(min_length=1, max_length=4000)
    template_ids: list[str] = Field(min_length=1, max_length=5)
    parameters: dict[str, Any] = Field(default_factory=dict)
    environment: str = Field(default="all", min_length=1, max_length=64)


class TemplateIngestRequest(BaseModel):
    """Request to ingest a single template into pgvector."""
    template_name: str
    version: int = Field(default=1, ge=1)
    description: str
    sql_template: str
    tags: list[str] = Field(default_factory=list)
    risk_level: Optional[str] = None
    pg_version: Optional[str] = None
    status: Literal["draft", "active"] = "draft"
    approved_by: Optional[str] = None

    @model_validator(mode="after")
    def active_templates_require_an_approver(self):
        if self.status == "active" and not self.approved_by:
            raise ValueError("approved_by is required when status is active")
        return self


class TemplateIngestResponse(BaseModel):
    status: str
    template_name: str
    id: Optional[int] = None
    lifecycle_status: Literal["draft", "active"]


class TemplateApprovalRequest(BaseModel):
    approved_by: str = Field(min_length=1, max_length=255)


class TemplateSearchResponse(BaseModel):
    status: str
    results: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Top-K matching templates with similarity scores"
    )


class KnowledgeIngestRequest(BaseModel):
    document_id: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=512)
    version: str = Field(min_length=1, max_length=64)
    content: str = Field(min_length=100)
    effective_date: datetime
    status: Literal["draft", "active"] = "draft"
    approved_by: Optional[str] = None
    expiry_date: Optional[datetime] = None
    postgresql_versions: list[str] = Field(default_factory=lambda: ["15", "16", "17"])
    environment_applicability: list[str] = Field(default_factory=lambda: ["all"])
    policy_owner: str = ""
    classification: str = "internal"
    source_url: Optional[str] = None

    @model_validator(mode="after")
    def active_documents_require_an_approver(self):
        if self.status == "active" and not self.approved_by:
            raise ValueError("approved_by is required when status is active")
        return self


class KnowledgeApprovalRequest(BaseModel):
    approved_by: str = Field(min_length=1, max_length=255)


class KnowledgeSearchResult(BaseModel):
    chunk_id: int
    document_id: str
    section: str
    content: str
    source_document_title: str
    source_document_version: str
    source_url: Optional[str] = None
    postgresql_versions: list[str]
    environment_applicability: list[str]
    similarity_score: float


class KnowledgeSearchResponse(BaseModel):
    status: str = "ok"
    results: list[KnowledgeSearchResult] = Field(default_factory=list)


class KnowledgeIngestResponse(BaseModel):
    """Response for knowledge ingestion operations (e.g. XLSX upload)."""
    status: str
    document_id: str
    title: str
    chunks_created: int = 0


# ============================================================================
# ASSESS Evaluation Contracts (Offline Assessment Engine)
# ============================================================================


class FindingStatus(str, Enum):
    """Status of a control evaluation against snapshot evidence."""

    PASS = "PASS"
    """Control condition is satisfied by the snapshot evidence."""

    FAIL = "FAIL"
    """Control condition is NOT satisfied and can be remediated automatically."""

    GAPPED = "GAPPED"
    """
    Collector could not gather evidence for this control due to missing privilege,
    unsupported PostgreSQL version, or other collection limitation.
    """

    MANUAL_REVIEW = "MANUAL_REVIEW"
    """Control requires human intervention and cannot be automated."""


class TypedAction(BaseModel):
    """Base class for typed remediation actions."""

    model_config = ConfigDict(extra="forbid")

    action_type: str
    description: str = Field(description="Human-readable description of the remediation")


class SetConfigParameterAction(TypedAction):
    """Automated configuration parameter adjustment."""

    action_type: Literal["SET_CONFIG_PARAMETER"] = "SET_CONFIG_PARAMETER"
    name: str = Field(description="PostgreSQL GUC name")
    value: str = Field(description="Target value for the parameter")


class RevokeSchemaPrivilegeAction(TypedAction):
    """Automated privilege revocation from a schema."""

    action_type: Literal["REVOKE_SCHEMA_PRIVILEGE"] = "REVOKE_SCHEMA_PRIVILEGE"
    schema_name: str = Field(description="Schema name (e.g., 'public')")
    privilege: str = Field(description="Privilege to revoke (e.g., 'CREATE')")
    grantee: str = Field(description="Grantee role name (e.g., 'PUBLIC')")


class ManualProcedureAction(TypedAction):
    """Non-automated procedure requiring human intervention."""

    action_type: Literal["MANUAL_PROCEDURE"] = "MANUAL_PROCEDURE"
    steps: list[str] = Field(
        description="Ordered steps for the manual procedure"
    )


# Union of all supported action types
AnyTypedAction = Union[
    SetConfigParameterAction,
    RevokeSchemaPrivilegeAction,
    ManualProcedureAction,
]


class Finding(BaseModel):
    """Result of evaluating a single control against snapshot evidence."""

    control_id: str = Field(
        description="Unique control identifier (e.g., CIS-3.1.2)"
    )
    status: FindingStatus = Field(
        description="Evaluation outcome: PASS, FAIL, GAPPED, or MANUAL_REVIEW"
    )
    title: str = Field(
        description="Human-readable control title"
    )
    rationale: str = Field(
        description="Explanation of why the control passed or failed"
    )
    evidence_found: Optional[Any] = Field(
        default=None,
        description="Raw evidence extracted from snapshot that determined the status"
    )
    typed_action: Optional[AnyTypedAction] = Field(
        default=None,
        description="Remediation action when status is FAIL or MANUAL_REVIEW"
    )
    is_gapped: bool = Field(
        default=False,
        description="True if the evidence was gapped (null with matching gap record)"
    )
    severity: Optional[str] = Field(
        default=None,
        description="CIS severity level (e.g., '1', '2A', '2B', '3')"
    )


class AssessmentSummary(BaseModel):
    """Summary counts for an assessment report."""

    total: int = Field(description="Total controls evaluated")
    pass_count: int = Field(description="Number of PASS findings")
    fail_count: int = Field(description="Number of FAIL findings")
    gapped_count: int = Field(description="Number of GAPPED findings")
    manual_review_count: int = Field(description="Number of MANUAL_REVIEW findings")


class AssessmentReport(BaseModel):
    """Complete assessment report for a single snapshot."""

    snapshot_id: str = Field(
        description="Content-addressed snapshot identifier"
    )
    evaluated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when evaluation completed"
    )
    summary: AssessmentSummary = Field(
        description="Aggregate counts of finding statuses"
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="Detailed findings for each evaluated control"
    )
