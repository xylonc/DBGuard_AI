"""Pydantic schemas for API request/response."""

from pydantic import BaseModel, Field
from typing import Any, Optional


class HardenRequest(BaseModel):
    user_prompt: str = Field(..., min_length=1, description="Natural language hardening request")
    metadata_snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description="Database engine, schema, version info"
    )


class HardenResponse(BaseModel):
    status: str
    target_db: str
    ai_plan: str
    retrieved_templates: list[str] = Field(
        default_factory=list,
        description="Template names retrieved via RAG"
    )


class TemplateIngestRequest(BaseModel):
    """Request to ingest a single template into pgvector."""
    template_name: str
    description: str
    sql_template: str
    tags: list[str] = Field(default_factory=list)
    risk_level: Optional[str] = None
    pg_version: Optional[str] = None


class TemplateIngestResponse(BaseModel):
    status: str
    template_name: str
    id: Optional[int] = None


class TemplateSearchResponse(BaseModel):
    status: str
    results: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Top-K matching templates with similarity scores"
    )
