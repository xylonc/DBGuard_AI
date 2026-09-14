"""Template HTTP endpoint definitions.

Moved from main.py for routing cleanliness.
Service logic (template_service, vector_service) is imported here
because the endpoint implementations need it — this file is not
testable without those deps, which is fine since the endpoint tests
only verify route registration, not execution.
"""

from fastapi import APIRouter

from app.models import TemplateIngestRequest, TemplateIngestResponse, TemplateSearchResponse
from app.services.template_service import compile_sql_plan
from app.services.vector_service import (
    ingest_all_templates,
    init_db,
    ingest_template,
    search_templates,
)

router = APIRouter(prefix="/api/v1/templates", tags=["templates"])


@router.post("/ingest-all")
def ingest_all():
    """Manually trigger re-ingestion of all templates."""
    init_db()
    ingest_all_templates()
    return {"status": "Templates ingested successfully"}


@router.post("/ingest", response_model=TemplateIngestResponse)
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


@router.get("/search")
def search(search_query: str, top_k: int = 5):
    """Search templates by semantic similarity."""
    results = search_templates(search_query, top_k=top_k)
    return TemplateSearchResponse(
        status="ok",
        results=results,
    )
