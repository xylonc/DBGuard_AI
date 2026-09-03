"""FastAPI endpoints for DBGuardAI."""

import uuid
from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.models import (
    TemplateIngestRequest,
    TemplateIngestResponse,
    TemplateSearchResponse,
)
from app.contracts import (
    CreateRunRequest,
    CreateRunResponse,
    Postgres16EvidenceBundle,
)
from app.services.template_service import compile_sql_plan
from app.services.vector_service import (
    search_templates,
    ingest_all_templates,
    init_db,
    ingest_template,
)
from app.config import settings

app = FastAPI(title="DBGuardAI")


# ── legacy ──────────────────────────────────────────────────────────────────


class HardenRequest(BaseModel):
    user_prompt: str = Field(..., min_length=1)
    metadata_snapshot: dict = Field(default_factory=dict)


class HardenResponse(BaseModel):
    status: str
    target_db: str
    ai_plan: str
    retrieved_templates: list[str] = Field(default_factory=list)


@app.get("/api/v1/health")
def health_check():
    return {"status": "healthy", "service": "DBGuardAI"}


@app.post("/api/v1/runs", response_model=CreateRunResponse)
def create_run(request: CreateRunRequest):
    """Accept a collector evidence bundle.

    Performs only:
      1. Pydantic structural validation
      2. PostgreSQL 16 / collector schema version validation
      3. Returns a validated response (no RAG / LLM / SQL / sandbox).
    """
    return CreateRunResponse(
        run_id=uuid.uuid4(),
        status="validated",
        target_engine="postgresql",
        target_major_version=16,
        collector_schema_version=request.target_evidence.envelope.schema_version,
    )


# ── template endpoints (unchanged) ──────────────────────────────────────────


@app.post("/api/v1/templates/ingest-all")
def ingest_all():
    """Manually trigger re-ingestion of all templates."""
    init_db()
    ingest_all_templates()
    return {"status": "Templates ingested successfully"}


@app.post("/api/v1/templates/ingest", response_model=TemplateIngestResponse)
def ingest_single_template(request: TemplateIngestRequest):
    """Ingest a single SQL hardening template with embedding."""
    result = ingest_template(
        template_name=request.template_name,
        description=request.description,
        sql_template=request.sql_template,
        tags=request.tags,
        risk_level=request.risk_level,
        pg_version=request.pg_version,
    )
    return TemplateIngestResponse(
        status="Template ingested successfully",
        template_name=result["template_name"],
        id=result["id"],
    )


@app.get("/api/v1/templates/search")
def search(search_query: str, top_k: int = 5):
    """Search templates by semantic similarity."""
    results = search_templates(search_query, top_k=top_k)
    return TemplateSearchResponse(
        status="ok",
        results=results,
    )
