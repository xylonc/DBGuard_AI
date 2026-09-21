"""Synchronous local POC endpoint shared by standalone and existing API apps."""
import logging

import psycopg2
from fastapi import APIRouter, Depends, HTTPException

from app.config import settings

from .handoff import SandboxHandoff
from .service import SandboxService
from .shared import ContractError

router = APIRouter(tags=["sandbox-poc"])
logger = logging.getLogger(__name__)


def get_service() -> SandboxService:
    if not settings.sandbox_poc_enabled:
        raise HTTPException(503, "Local sandbox API is disabled; set SANDBOX_POC_ENABLED=true on the Docker host")
    return SandboxService(settings.database_url, settings.sandbox_poc_image)


@router.post("/api/v1/sandbox/runs", summary="Test a pinned, approved fix in disposable PostgreSQL")
def run_sandbox(request: SandboxHandoff, service: SandboxService = Depends(get_service)) -> dict:
    """Returns VERIFIED, FAILED or CLEANUP_FAILED with fix-unit and attempt evidence.

    This synchronous local POC never applies a fix to the source or registry DB.
    HTTP 200 means testing completed; inspect the result's status for acceptance.
    """
    try:
        return service.run(request)
    except ContractError as exc:
        raise HTTPException(422, str(exc)) from exc
    except psycopg2.Error as exc:
        # Do not include connection strings or raw registry errors in responses.
        logger.warning("Sandbox registry lookup failed")
        raise HTTPException(503, "Approved-template registry unavailable") from exc
