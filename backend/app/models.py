"""Pydantic schemas for the proposal and knowledge APIs."""

from datetime import datetime
from pydantic import BaseModel, Field, model_validator
from typing import Any, Literal, Optional


class HardenRequest(BaseModel):
    user_prompt: str = Field(..., min_length=1, description="Natural language hardening request")
    snapshot_id: Optional[str] = Field(
        default=None,
        description="ID returned by POST /api/v1/snapshots",
    )
    metadata_snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description="Deprecated inline metadata; use snapshot_id for collector output",
    )
    environment: str = Field(default="all", min_length=1, max_length=64)


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
