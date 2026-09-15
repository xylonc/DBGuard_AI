"""Pydantic schemas for the proposal and knowledge APIs."""

from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator
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
        default_factory=datetime.now,
        description="Timestamp when evaluation completed"
    )
    summary: AssessmentSummary = Field(
        description="Aggregate counts of finding statuses"
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="Detailed findings for each evaluated control"
    )


# ============================================================================
# Twin Execution & VALIDATE Phase Contracts
# ============================================================================


class TwinExecutionStatus(str, Enum):
    """Status of twin sandbox execution."""

    SKIPPED_MANUAL_REQUIRED = "SKIPPED_MANUAL_REQUIRED"
    """Non-SQL control requiring manual intervention."""
    
    EXECUTING = "EXECUTING"
    """Remediation SQL being executed in twin."""
    
    VERIFYING = "VERIFYING"
    """Twin snapshot collected, re-evaluating controls."""
    
    VERIFIED = "VERIFIED"
    """Flip verified: FAIL -> PASS after remediation."""
    
    ROLLBACK_EXECUTING = "ROLLBACK_EXECUTING"
    """Rollback SQL being executed."""
    
    RESTORED = "RESTORED"
    """Container restored to clean state after rollback."""
    
    FAILED = "FAILED"
    """Execution failed with error details."""


class TwinExecutionResult(BaseModel):
    """Result of twin sandbox verification for a single proposal."""
    
    control_id: str
    status: TwinExecutionStatus
    remediation_executed: bool = False
    rollback_executed: bool = False
    flip_verified: bool = False
    error: Optional[str] = None
    execution_log: list[str] = Field(default_factory=list)
    verification_snapshot_id: Optional[str] = None
    pre_remediation_status: Optional[FindingStatus] = None
    post_remediation_status: Optional[FindingStatus] = None
    post_rollback_status: Optional[FindingStatus] = None


class SetConfigTemplateParams(BaseModel):
    """Validated parameters for SET_CONFIG_PARAMETER template rendering."""
    
    model_config = ConfigDict(extra="forbid")
    
    param_name: str = Field(
        description="PostgreSQL GUC parameter name"
    )
    param_value: str = Field(
        description="Target value for the parameter"
    )
    
    @field_validator("param_name")
    @classmethod
    def validate_param_name(cls, v: str) -> str:
        """Validate parameter name against allowed config parameters."""
        # Allowed config parameters - extend as needed
        allowed_params = {
            "log_connections",
            "log_checkpoints",
            "log_disconnections",
            "log_lock_waits",
            "log_min_duration_statement",
            "log_statement",
            "password_encryption",
            "max_connections",
            "shared_buffers",
            "work_mem",
            "maintenance_work_mem",
            "effective_cache_size",
            "random_page_cost",
            "default_statistics_target",
        }
        if v not in allowed_params:
            raise ValueError(f"Invalid config parameter name: {v}. Must be one of {sorted(allowed_params)}")
        return v
    
    @field_validator("param_value")
    @classmethod
    def validate_param_value(cls, v: str) -> str:
        """Validate parameter value format."""
        # Allow standard PostgreSQL boolean values
        if v.lower() in ("on", "off", "true", "false", "yes", "no", "1", "0"):
            return v
        # Allow numeric values
        try:
            float(v)
            return v
        except ValueError:
            pass
        # Allow quoted-like strings that don't contain SQL injection patterns
        if "'" not in v and ";" not in v and "--" not in v and "/*" not in v:
            return v
        raise ValueError(f"Invalid parameter value: {v}")


class RevokePrivilegeTemplateParams(BaseModel):
    """Validated parameters for REVOKE_SCHEMA_PRIVILEGE template rendering."""
    
    model_config = ConfigDict(extra="forbid")
    
    privilege: str = Field(
        description="Privilege to revoke (e.g., CREATE, USAGE, SELECT)"
    )
    schema_name: str = Field(
        description="Schema name (e.g., public)"
    )
    grantee: str = Field(
        description="Grantee role name (e.g., PUBLIC)"
    )
    
    @field_validator("privilege")
    @classmethod
    def validate_privilege(cls, v: str) -> str:
        """Validate privilege type."""
        allowed_privileges = {
            "SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE",
            "REFERENCES", "TRIGGER", "CREATE", "USAGE", "TEMPORARY",
            "CONNECT", "EXECUTE", "SET", "ALTER SYSTEM"
        }
        upper_v = v.upper()
        if upper_v not in allowed_privileges:
            raise ValueError(f"Invalid privilege type: {v}. Must be one of {sorted(allowed_privileges)}")
        return upper_v
    
    @field_validator("schema_name")
    @classmethod
    def validate_schema_name(cls, v: str) -> str:
        """Validate schema name format."""
        # Allow valid PostgreSQL identifiers (letters, digits, underscore, no spaces)
        import re
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', v):
            raise ValueError(f"Invalid schema name: {v}. Must be a valid PostgreSQL identifier.")
        return v
    
    @field_validator("grantee")
    @classmethod
    def validate_grantee(cls, v: str) -> str:
        """Validate grantee role name format."""
        import re
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', v):
            raise ValueError(f"Invalid grantee name: {v}. Must be a valid PostgreSQL identifier.")
        return v


class ProposalReviewPackage(BaseModel):
    """Complete DBA review package for a single proposal."""
    
    snapshot_id: str = Field(
        description="Target snapshot reference"
    )
    control_id: str = Field(
        description="CIS Control identifier"
    )
    title: str = Field(
        description="Human-readable control title"
    )
    remediation_sql: Optional[str] = Field(
        default=None,
        description="Rendered and verified remediation SQL string (if executable)"
    )
    rollback_sql: Optional[str] = Field(
        default=None,
        description="Rendered and verified rollback SQL string (if executable)"
    )
    manual_procedure: Optional[list[str]] = Field(
        default=None,
        description="Step-by-step guidance list (for non-SQL controls)"
    )
    twin_verification: Optional[TwinExecutionResult] = Field(
        default=None,
        description="TwinExecutionResult containing flip proof"
    )
    rag_justification: str = Field(
        description="CIS benchmark rationale and impact analysis statement"
    )
    requires_dba_review: bool = Field(
        default=True,
        description="Whether DBA review is required before execution"
    )
    risk_level: str = Field(
        default="medium",
        description="Risk assessment level (low, medium, high)"
    )
