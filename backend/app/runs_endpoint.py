"""POST /api/v1/runs — evidence bundle acceptance endpoint.

This module is deliberately standalone: it imports NO template/RAG/vector
services.  This keeps the runs endpoint testable without the heavy deps
(chromadb, openai, etc.).
"""

import uuid
from fastapi import APIRouter

from app.contracts import CreateRunRequest, CreateRunResponse

router = APIRouter()


@router.post("/api/v1/runs", response_model=CreateRunResponse)
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
