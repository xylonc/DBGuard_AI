"""FastAPI entry point for DBGuardAI's proposal-focused POC."""

from dataclasses import asdict

from fastapi import FastAPI, HTTPException, Query
from jinja2 import TemplateError

from app.collector_models import (
    CollectorBundleV020,
    SnapshotContextResponse,
    SnapshotUploadResponse,
)
from app.models import (
    HardenResponse,
    KnowledgeApprovalRequest,
    KnowledgeIngestRequest,
    KnowledgeSearchResponse,
    ProposalCompileRequest,
    TemplateIngestRequest,
    TemplateIngestResponse,
    TemplateApprovalRequest,
    TemplateSearchResponse,
)
from app.services.snapshot_service import SnapshotNotFoundError, SnapshotStore
from app.services.template_service import compile_sql_plan_from_templates
from app.services.vector_service import (
    approve_template,
    get_active_template_version,
    ingest_all_templates,
    ingest_template,
    init_db,
    search_templates,
)
from app.config import settings
from services.rag.rag_service import KnowledgeDocument, RAGService

app = FastAPI(
    title="DBGuardAI",
    version="0.2.0",
    description="Collector snapshot intake, approved knowledge retrieval, and human-reviewed hardening proposals.",
)
snapshot_store = SnapshotStore(settings.snapshot_storage_dir)


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "service": "DBGuardAI",
        "scope": "proposal",
        "assessment_enabled": False,
        "twin_runner_enabled": False,
    }


@app.post("/api/v1/snapshots", response_model=SnapshotUploadResponse, status_code=201)
def upload_snapshot(bundle: CollectorBundleV020):
    """Validate and store an immutable collector v0.2.0 bundle."""
    return snapshot_store.save(bundle)


@app.get("/api/v1/snapshots/{snapshot_id}", response_model=SnapshotContextResponse)
def get_snapshot_context(snapshot_id: str):
    """Return the safe, normalized context used by the proposal agent."""
    try:
        return snapshot_store.context(snapshot_id)
    except SnapshotNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot not found") from exc


@app.post("/api/v1/proposals/compile", response_model=HardenResponse)
def compile_hardening_proposal(request: ProposalCompileRequest):
    """Validate a HERMES selection and render only reviewed SQL templates."""
    try:
        metadata = snapshot_store.context(request.snapshot_id).model_dump(mode="json")
    except SnapshotNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot not found") from exc

    # Re-run retrieval inside the trusted API boundary. HERMES cannot make an
    # arbitrary or archived template eligible simply by naming it.
    retrieved = search_templates(request.requirement, top_k=5)
    eligible_template_ids = {item["template_name"] for item in retrieved}
    selected_template_ids = set(request.template_ids)
    invalid_template_ids = sorted(selected_template_ids - eligible_template_ids)
    if invalid_template_ids:
        raise HTTPException(
            status_code=422,
            detail=(
                "Templates are not in the active retrieval set: "
                f"{invalid_template_ids}"
            ),
        )

    # Load exact template content from PostgreSQL for selected templates
    template_records = []
    for template_id in selected_template_ids:
        record = get_active_template_version(template_id)
        if record is None:
            raise HTTPException(
                status_code=422,
                detail=f"Template {template_id} is not active or does not exist",
            )
        template_records.append(record)

    evidence_results = RAGService(settings.database_url).search(
        query=request.requirement,
        pg_version=metadata.get("postgresql_version"),
        environment=request.environment,
        top_k=5,
        min_score=0.35,
    )
    if not evidence_results:
        raise HTTPException(
            status_code=409,
            detail="MANUAL_REVIEW_REQUIRED: no approved, applicable evidence was found",
        )

    parameters = dict(request.parameters)
    parameters.setdefault("database_name", metadata.get("database", "postgres"))
    try:
        sql_plan = compile_sql_plan_from_templates(template_records, parameters)
    except (TemplateError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Template parameters require DBA review: {exc}",
        ) from exc

    citations = [
        {
            "document_id": result.document_id,
            "title": result.source_document_title,
            "version": result.source_document_version,
            "section": result.section,
            "source_url": result.source_url,
            "similarity_score": result.similarity_score,
        }
        for result in evidence_results
    ]
    return HardenResponse(
        status="Proposal compiled for DBA review",
        target_db=metadata.get("database", metadata.get("engine", "postgresql")),
        ai_plan=sql_plan,
        retrieved_templates=[item["template_name"] for item in retrieved],
        evidence=citations,
        reasoning=(
            "HERMES selected from the active retrieval set; DBGuardAI "
            "revalidated and rendered the reviewed template."
        ),
    )


@app.post("/api/v1/templates/ingest-all")
def ingest_all():
    """Manually trigger re-ingestion of all templates."""
    init_db()
    ingest_all_templates()
    return {"status": "Templates ingested successfully"}


@app.post("/api/v1/templates/ingest", response_model=TemplateIngestResponse)
def ingest_single_template(request: TemplateIngestRequest):
    """Ingest a single SQL hardening template with embedding.
    
    New templates are always created as 'draft' status regardless of request status.
    Approval must happen separately through the template approval flow.
    """
    result = ingest_template(
        template_name=request.template_name,
        description=request.description,
        sql_template=request.sql_template,
        version=request.version,
        tags=request.tags,
        risk_level=request.risk_level,
        pg_version=request.pg_version,
    )
    return TemplateIngestResponse(
        status="Template ingested successfully",
        template_name=result["template_name"],
        id=result["id"],
        lifecycle_status=result["status"],
    )


@app.get("/api/v1/templates/search")
def search(search_query: str, top_k: int = 5):
    """Search templates by semantic similarity."""
    results = search_templates(search_query, top_k=top_k)
    return TemplateSearchResponse(
        status="ok",
        results=results,
    )


@app.post("/api/v1/templates/{template_name}/approve")
def approve_sql_template(template_name: str, request: TemplateApprovalRequest, version: int = 1):
    """Record human approval of an exact template version and make it searchable.
    
    Approval applies to the exact (template_name, version) combination.
    The template must exist and be in 'draft' status.
    """
    if not approve_template(template_name, version, request.approved_by):
        raise HTTPException(status_code=404, detail=f"Draft SQL template {template_name} v{version} not found")
    return {"status": "active", "template_name": template_name, "version": version, "approved_by": request.approved_by}


@app.post("/api/v1/knowledge/documents")
def ingest_knowledge_document(request: KnowledgeIngestRequest):
    """Ingest a draft, or an explicitly human-approved source document."""
    document = KnowledgeDocument(**request.model_dump())
    result = RAGService(settings.database_url).ingest_document(document)
    if result.status in {"failed", "rejected"}:
        raise HTTPException(status_code=422, detail=asdict(result))
    return asdict(result)


@app.post("/api/v1/knowledge/documents/{document_id}/approve")
def approve_knowledge_document(document_id: str, request: KnowledgeApprovalRequest):
    """Record human approval and make a draft eligible for retrieval."""
    if not RAGService(settings.database_url).approve_document(document_id, request.approved_by):
        raise HTTPException(status_code=404, detail="Draft knowledge document not found")
    return {"status": "active", "document_id": document_id, "approved_by": request.approved_by}


@app.get("/api/v1/knowledge/documents/{document_id}")
def get_knowledge_document_metadata(document_id: str):
    """Inspect document lifecycle and provenance without returning all chunks."""
    metadata = RAGService(settings.database_url).get_document_metadata(document_id)
    if metadata is None:
        raise HTTPException(status_code=404, detail="Knowledge document not found")
    return vars(metadata)


@app.get("/api/v1/knowledge/search", response_model=KnowledgeSearchResponse)
def search_approved_knowledge(
    search_query: str = Query(min_length=1),
    pg_version: str | None = None,
    environment: str = "all",
    top_k: int = Query(default=5, ge=1, le=20),
    min_score: float = Query(default=0.5, ge=-1.0, le=1.0),
):
    """Search only active, effective, non-expired, applicable documents."""
    results = RAGService(settings.database_url).search(
        query=search_query,
        pg_version=pg_version,
        environment=environment,
        top_k=top_k,
        min_score=min_score,
    )
    return KnowledgeSearchResponse(results=[vars(result) for result in results])
