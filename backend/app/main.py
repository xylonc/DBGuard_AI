"""FastAPI endpoints for DBGuardAI."""

from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import Any, Optional

from app.models import TemplateIngestRequest, TemplateIngestResponse, TemplateSearchResponse
from app.services.ai_service import generate_hardening_plan
from app.services.template_service import compile_sql_plan
from app.services.vector_service import search_templates, ingest_all_templates, init_db, ingest_template
from app.config import settings

app = FastAPI(title="DBGuardAI")


class HardenRequest(BaseModel):
    user_prompt: str = Field(..., min_length=1)
    metadata_snapshot: dict[str, Any] = Field(default_factory=dict)


class HardenResponse(BaseModel):
    status: str
    target_db: str
    ai_plan: str
    retrieved_templates: list[str] = Field(default_factory=list)


@app.get("/api/v1/health")
def health_check():
    return {"status": "healthy", "service": "DBGuardAI"}


@app.post("/api/v1/harden", response_model=HardenResponse)
def create_hardening_plan(request: HardenRequest):
    # Step 1: RAG retrieval
    retrieved = search_templates(request.user_prompt, top_k=3)
    template_ids = [r["template_name"] for r in retrieved]

    # Step 2: LLM decision with retrieved context
    ai_decision = generate_hardening_plan(
        user_prompt=request.user_prompt,
        metadata=request.metadata_snapshot,
        retrieved_templates=retrieved
    )

    # Step 3: Compile SQL
    full_sql_plan = compile_sql_plan(
        template_ids=ai_decision.get("template_ids", []),
        variables=ai_decision.get("parameters", {})
    )

    return HardenResponse(
        status="Plan generated successfully",
        target_db=request.metadata_snapshot.get("engine", "postgresql"),
        ai_plan=full_sql_plan,
        retrieved_templates=template_ids
    )


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
