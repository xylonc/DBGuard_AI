"""Knowledge XLSX upload endpoint.

Adds a single ``POST /api/v1/knowledge/upload`` route that:
1. Accepts a multipart ``.xlsx`` file.
2. Extracts readable text via ``xlsx_extractor``.
3. Builds a ``KnowledgeIngestRequest`` (Pydantic contract).
4. Calls the existing ``RAGService.ingest_document`` directly.
5. Returns the standard ingestion result.

The existing JSON-based ingestion endpoints (template ingest, etc.)
are **not** modified or replaced.
"""

import sys
from pathlib import Path

# Ensure project root is on the path so that `services.rag_service` is importable
# and `app.config` / `app.services` are importable (needed by rag_service.py)
_project_root = Path(__file__).resolve().parent.parent.parent
_backend = Path(__file__).resolve().parent.parent
for p in (_project_root, _backend):
    ps = str(p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

# Import rag_service as a file (not a package) to work around missing __init__.py
_services_rag = str(_project_root / "services" / "rag")
if _services_rag not in sys.path:
    sys.path.insert(0, _services_rag)

import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.models import (
    KnowledgeIngestRequest,
    KnowledgeIngestResponse,
)
from rag_service import RAGService, KnowledgeDocument, IngestionResult  # noqa: E402

router = APIRouter(prefix="/api/v1/knowledge", tags=["knowledge"])

# Shared RAG instance (same pattern as rag_service.py's singleton)
rag_service = RAGService()


@router.post("/upload", response_model=KnowledgeIngestResponse)
async def upload_knowledge_xlsx(file: UploadFile = File(...)):
    """Upload an XLSX file for knowledge ingestion.

    The file is parsed, converted to normalized text, validated via the
    existing ``KnowledgeIngestRequest`` Pydantic model, and passed into
    the existing RAG ingestion pipeline (chunking → embedding → pgvector).
    """
    # ── 1. Validate file type ─────────────────────────────────────────

    if not file.filename or not file.filename.lower().endswith(".xlsx"):
        raise HTTPException(
            status_code=400,
            detail="Only .xlsx files are accepted.",
        )

    # ── 2. Read file bytes ────────────────────────────────────────────

    content = await file.read()

    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # ── 3. Extract text from XLSX ─────────────────────────────────────

    from app.xlsx_extractor import extract_xlsx_to_text

    try:
        normalized_text = extract_xlsx_to_text(content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Failed to parse XLSX: {exc}",
        )

    # ── 4. Build ingestion request with existing Pydantic contract ────

    ingest_request = KnowledgeIngestRequest(
        document_id=f"xlsx-{uuid.uuid4().hex[:12]}",
        title=file.filename.replace(".xlsx", "").replace("_", " ").title(),
        version="1.0.0",
        content=normalized_text,
        effective_date=datetime.now(timezone.utc),
        status="draft",
    )

    # Pydantic validation happens automatically here;
    # if anything is wrong it raises a ValidationError (→ 422).

    # ── 5. Ingest via existing RAG service ────────────────────────────

    knowledge_doc = KnowledgeDocument(
        document_id=ingest_request.document_id,
        title=ingest_request.title,
        version=ingest_request.version,
        content=ingest_request.content,
        effective_date=ingest_request.effective_date,
        status=ingest_request.status,
        approved_by=ingest_request.approved_by,
        expiry_date=ingest_request.expiry_date,
        postgresql_versions=ingest_request.postgresql_versions,
        environment_applicability=ingest_request.environment_applicability,
        policy_owner=ingest_request.policy_owner,
        classification=ingest_request.classification,
        source_url=ingest_request.source_url,
    )

    ingestion_result = rag_service.ingest_document(knowledge_doc)

    if ingestion_result.status == "rejected" or ingestion_result.status == "failed":
        raise HTTPException(
            status_code=502,
            detail=f"Ingestion failed: {'; '.join(ingestion_result.errors)}",
        )

    return KnowledgeIngestResponse(
        status="ingested",
        document_id=ingest_request.document_id,
        title=ingest_request.title,
        chunks_created=ingestion_result.chunks_created,
    )
