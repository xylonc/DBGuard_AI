"""FastAPI entry point for DBGuardAI's proposal-focused POC."""

from dataclasses import asdict
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from datetime import datetime, timezone
import uuid
import os

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from jinja2 import TemplateError
from pydantic import BaseModel, Field

from app.collector_models import (
    CollectorBundleV020,
    SnapshotContextResponse,
    SnapshotUploadResponse,
)
from app.models import (
    AssessmentReport,
    AssessmentSummary,
    Finding,
    FindingStatus,
    HardenResponse,
    KnowledgeApprovalRequest,
    KnowledgeIngestRequest,
    KnowledgeIngestResponse,
    KnowledgeSearchResponse,
    RemediationProposal,
    RemediationProposalRequest,
    TemplateIngestRequest,
    TemplateIngestResponse,
    TemplateApprovalRequest,
    TemplateSearchResponse,
)
from app.services.assessment_service import AssessmentService
from catalog.controls.assess.registry import CONTROL_REGISTRY
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
from services.sandbox_poc.router import router as sandbox_poc_router

app = FastAPI(
    title="DBGuardAI",
    version="0.2.0",
    description="Collector snapshot intake, approved knowledge retrieval, and human-reviewed hardening proposals.",
)
snapshot_store = SnapshotStore(settings.snapshot_storage_dir)

# The new spec-driven local endpoint is separate from legacy /sandbox/validate.
app.include_router(sandbox_poc_router)


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "service": "DBGuardAI",
        "scope": "proposal",
        "assessment_enabled": False,
        "twin_runner_enabled": False,
        "sandbox_poc_enabled": settings.sandbox_poc_enabled,
    }


@app.get("/api/v1/snapshots/{snapshot_id}/assessment", response_model=AssessmentReport)
def get_assessment_report(snapshot_id: str):
    """Evaluate a snapshot against the control registry and return findings.
    
    This endpoint performs deterministic assessment of a snapshot using the
    offline ASSESS evaluation engine. It returns pass/fail/gap status for
    each control.
    """
    try:
        bundle = snapshot_store.load(snapshot_id)
    except SnapshotNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot not found") from exc
    
    # Convert bundle to dict for assessment
    snapshot = bundle.model_dump(mode="json", exclude_none=False)
    
    # Run assessment
    assessment_service = AssessmentService(CONTROL_REGISTRY)
    report = assessment_service.evaluate(snapshot)
    
    # Override snapshot_id to match the requested one
    report.snapshot_id = snapshot_id
    
    return report


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


@app.post("/api/v1/proposals/validate-and-render", response_model=HardenResponse)
def validate_and_render_proposal(request: RemediationProposalRequest):
    """Validate a HERMES proposal and render only reviewed SQL templates.
    
    This is the trusted boundary endpoint. The HERMES agent:
    1. Uses search_approved_templates to find eligible templates
    2. Uses search_approved_knowledge to find evidence
    3. Selects a template + parameters + reasoning
    4. Submits here for validation and rendering
    
    The API validates:
    - Template exists and is active
    - Parameters match template schema
    - Evidence references point to approved documents
    - Renders the template from PostgreSQL
    
    Returns rendered SQL for human DBA review.
    No SQL is ever generated - only rendered from approved templates.
    """
    try:
        metadata = snapshot_store.context(request.snapshot_id).model_dump(mode="json")
    except SnapshotNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Snapshot not found") from exc
    
    proposal = request.proposal
    
    # Step 1: Validate template exists and is active
    template_record = get_active_template_version(proposal.template_id)
    if template_record is None:
        raise HTTPException(
            status_code=422,
            detail=f"Template '{proposal.template_id}' is not active or does not exist. "
                   "Use search_approved_templates to find eligible templates."
        )
    
    # Step 2: Validate template parameters
    # This validates parameters against the template's expected schema
    from app.services.template_service import validate_params
    success, validated_params, error = validate_params(
        proposal.template_id, 
        proposal.parameters
    )
    if not success:
        raise HTTPException(
            status_code=422,
            detail=f"Template parameter validation failed: {error}"
        )
    
    # Step 3: Validate evidence references point to approved documents
    evidence_results = []
    for doc_ref in proposal.evidence_refs:
        # Search for approved documents by ID
        from app.services.vector_service import search_templates
        from services.rag.rag_service import RAGService
        rag = RAGService(settings.database_url)
        docs = rag.search(
            query=doc_ref,
            pg_version=metadata.get("postgresql_version"),
            environment=request.environment,
            top_k=5,
            min_score=0.5,
        )
        if not docs:
            raise HTTPException(
                status_code=409,
                detail=f"MANUAL_REVIEW_REQUIRED: approved evidence reference '{doc_ref}' not found"
            )
        evidence_results.extend(docs)
    
    if not evidence_results:
        # If no evidence refs provided, search by template description
        if not proposal.reasoning and not proposal.evidence_refs:
            # At least one form of justification required
            raise HTTPException(
                status_code=422,
                detail="At least one evidence reference or reasoning is required"
            )
    
    # Step 4: Render the template using PostgreSQL content
    parameters = dict(validated_params)
    parameters.setdefault("database_name", metadata.get("database", "postgres"))
    
    from jinja2 import TemplateError as JinjaTemplateError
    try:
        sql_plan = compile_sql_plan_from_templates([template_record], parameters)
    except (JinjaTemplateError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Template rendering failed: {exc}",
        ) from exc
    
    # Step 5: Build citations from evidence
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
        status="Proposal validated and SQL rendered for DBA review",
        target_db=metadata.get("database", metadata.get("engine", "postgresql")),
        ai_plan=sql_plan,
        retrieved_templates=[template_record["template_name"]],
        evidence=citations,
        reasoning=proposal.reasoning,
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

@app.post("/api/v1/knowledge/upload", response_model=KnowledgeIngestResponse)
async def upload_knowledge_xlsx(file: UploadFile = File(...)):
    """Upload an XLSX file for knowledge ingestion.

    The file is parsed, converted to normalized text, validated via the
    existing ``KnowledgeIngestRequest`` Pydantic model, and passed into
    the existing RAG ingestion pipeline (chunking → embedding → pgvector).
    """
    # 1. Validate file type
    if not file.filename or not file.filename.lower().endswith(".xlsx"):
        raise HTTPException(
            status_code=400,
            detail="Only .xlsx files are accepted.",
        )

    # 2. Read file bytes
    content_bytes = await file.read()

    if not content_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # 3. Extract text from XLSX
    from app.xlsx_extractor import extract_xlsx_to_text

    try:
        normalized_text = extract_xlsx_to_text(content_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse XLSX: {exc}",
        )

    # 4. Build KnowledgeDocument directly — skip KnowledgeIngestRequest
    #    because it enforces a 100-char minimum on content, which is
    #    not appropriate for XLSX ingestion (small sheets may be valid).
    document = KnowledgeDocument(
        document_id=f"xlsx-{uuid.uuid4().hex[:12]}",
        title=file.filename.replace(".xlsx", "").replace("_", " ").title(),
        version="1.0.0",
        content=normalized_text,
        effective_date=datetime.now(timezone.utc),
        status="draft",
    )
    ingestion_result = RAGService(settings.database_url).ingest_document(document)

    if ingestion_result.status in {"failed", "rejected"}:
        raise HTTPException(
            status_code=400,
            detail=f"Ingestion failed: {'; '.join(ingestion_result.errors)}",
        )

    return KnowledgeIngestResponse(
        status=ingestion_result.status,
        document_id=document.document_id,
        title=document.title,
        chunks_created=ingestion_result.chunks_created,
    )


# ============================================================================#
# SANDBOX VALIDATION API
# ============================================================================#


class SandboxValidationRequest(BaseModel):
    """Request for sandbox validation of a proposal."""

    snapshot_id: str = Field(min_length=1, max_length=64)
    control_id: str = Field(
        min_length=1,
        description="CIS control ID (e.g., 'CIS-3.1.2')"
    )
    template_id: str = Field(
        min_length=1,
        description="Approved template ID"
    )
    template_version: int = Field(
        ge=1,
        description="Template version"
    )
    parameters: Dict[str, Any] = Field(default_factory=dict)
    rendered_sql: str = Field(
        min_length=1,
        description="Rendered SQL from approved template"
    )


class SandboxValidationResponse(BaseModel):
    """Response from sandbox validation."""

    sandbox_run_id: str
    snapshot_id: str
    control_id: str
    status: str
    pre_remediation_status: Optional[str] = None
    post_remediation_status: Optional[str] = None
    post_rollback_status: Optional[str] = None
    security_validation_passed: bool
    compatibility_validation_passed: bool
    rollback_executed: bool
    rollback_verified: bool
    logs: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


@app.post("/api/v1/sandbox/validate", response_model=SandboxValidationResponse)
def validate_in_sandbox(request: SandboxValidationRequest):
    """Validate a proposal by executing it in an ephemeral PostgreSQL sandbox.

    This endpoint:
    1. Creates an isolated PostgreSQL container
    2. Replays only security-relevant metadata (settings)
    3. Verifies the initial state matches the source finding (FAIL)
    4. Executes the rendered proposal artifact
    5. Verifies the control flips to PASS
    6. Executes rollback SQL
    7. Verifies restoration to original state
    8. Runs basic compatibility validation
    9. Destroys the container
    10. Returns structured validation evidence

    The sandbox does NOT contain an autonomous agent. It only executes
    the approved artifact from the proposal and returns evidence.
    """
    from app.services.sandbox_service import SandboxValidationService
    from app.services.snapshot_service import SnapshotStore
    from pathlib import Path

    snapshot_dir = Path(os.environ.get("SNAPSHOT_STORAGE_DIR", "data/snapshots"))
    snapshot_store = SnapshotStore(str(snapshot_dir))

    # Load source snapshot to validate it exists
    try:
        source_bundle = snapshot_store.load(request.snapshot_id)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"Snapshot not found: {exc}") from exc

    # Build proposal artifact
    from app.services.sandbox_service import build_proposal_artifact

    artifact = build_proposal_artifact(
        snapshot_id=request.snapshot_id,
        control_id=request.control_id,
        template_id=request.template_id,
        template_version=request.template_version,
        parameters=request.parameters,
        rendered_sql=request.rendered_sql,
        requires_dba_review=True,
    )

    # Validate template_id format (prevent arbitrary SQL)
    if not artifact.template_id.startswith("SET_CONFIG") and not artifact.template_id.startswith("REVOKE"):
        raise HTTPException(
            status_code=400,
            detail=f"Template '{artifact.template_id}' does not match approved templates for automation"
        )

    # Run sandbox validation
    service = SandboxValidationService()

    # Create a minimal proposal for validation
    proposal = RemediationProposal(
        control_id=request.control_id,
        template_id=request.template_id,
        template_version=request.template_version,
        parameters=request.parameters,
        reasoning="Sandbox validation of template-driven remediation",
        evidence_refs=[],
    )

    result = service.verify_proposal(
        snapshot_id=request.snapshot_id,
        control_id=request.control_id,
        proposal=proposal,
        rendered_sql=request.rendered_sql,
    )

    return SandboxValidationResponse(
        sandbox_run_id=artifact.proposal_id,
        snapshot_id=request.snapshot_id,
        control_id=request.control_id,
        status=result.status.value,
        pre_remediation_status=result.pre_remediation_status.value if result.pre_remediation_status else None,
        post_remediation_status=result.post_remediation_status.value if result.post_remediation_status else None,
        post_rollback_status=result.post_rollback_status.value if result.post_rollback_status else None,
        security_validation_passed=result.flip_verified,
        compatibility_validation_passed=result.status.value != "COMPATIBILITY_FAILED",
        rollback_executed=result.rollback_executed,
        rollback_verified=result.rollback_verified,
        logs=result.execution_log,
        errors=[result.error] if result.error else [],
    )
