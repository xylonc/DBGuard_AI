"""Synchronous local POC endpoint shared by standalone and existing API apps."""
import logging

import psycopg2
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response

from .review_bundle import BundleStore, build_review_bundle, is_fixture

from app.config import settings

from .handoff import SandboxHandoff
from .service import SandboxService
from .shared import ContractError
from .adaptive import LLMReviser
from .upstream import PrepareRequest, HandoffStore, assess_uploaded, prepare_uploaded
from .readiness import check_readiness
from app.services.snapshot_service import SnapshotStore, SnapshotNotFoundError

router = APIRouter(tags=["sandbox-poc"])
logger = logging.getLogger(__name__)
bundles = BundleStore()
handoffs = HandoffStore()


def get_snapshot_store():
    return SnapshotStore(settings.snapshot_storage_dir)


def get_service() -> SandboxService:
    if not settings.sandbox_poc_enabled:
        raise HTTPException(503, "Local sandbox API is disabled; set SANDBOX_POC_ENABLED=true on the Docker host")
    reviser = LLMReviser(settings.sandbox_llm_base_url, settings.sandbox_llm_model,
                         settings.sandbox_llm_api_key) if settings.sandbox_llm_enabled else None
    return SandboxService(settings.database_url, settings.sandbox_poc_image, reviser=reviser)


@router.post("/api/v1/sandbox/runs", summary="Test a pinned, approved fix in disposable PostgreSQL")
def run_sandbox(request: SandboxHandoff, service: SandboxService = Depends(get_service)) -> dict:
    """Returns VERIFIED, FAILED or CLEANUP_FAILED with fix-unit and attempt evidence.

    This synchronous local POC never applies a fix to the source or registry DB.
    HTTP 200 means testing completed; inspect the result's status for acceptance.
    """
    try:
        result = service.run(request)
        if result.get("status") == "VERIFIED":
            try:
                data = build_review_bundle(request, result, service.validate_handoff(request))
                bundles.put(result["run_id"], data)
                result["review_bundle"] = {"status": "READY", "demo_fixture_approval": is_fixture(result), "url": f"/api/v1/sandbox/runs/{result['run_id']}/bundle"}
            except ContractError as exc:
                # Keep the tested outcome; exporting a runnable script is a separate gate.
                result["review_bundle"] = {"status": "UNAVAILABLE", "reason": str(exc)}
        return result
    except ContractError as exc:
        raise HTTPException(422, str(exc)) from exc
    except psycopg2.Error as exc:
        # Do not include connection strings or raw registry errors in responses.
        logger.warning("Sandbox registry lookup failed")
        raise HTTPException(503, "Approved-template registry unavailable") from exc


@router.get("/api/v1/sandbox/runs/{run_id}/bundle", summary="Download a server-verified DBA review bundle")
def download_bundle(run_id: str, service: SandboxService = Depends(get_service)):
    data = bundles.get(run_id)
    if data is None:
        raise HTTPException(404, "Bundle not found or expired; only the last eight verified exports are retained")
    return Response(data, media_type="application/zip", headers={
        "Content-Disposition": 'attachment; filename="dbguard-review.zip"',
        "Cache-Control": "no-store"})


@router.get('/api/v1/snapshots/{snapshot_id}/spec-assessment')
def spec_assessment(snapshot_id: str,
                    benchmark_id: str = Query(default='cis-pg17-v1.1.0', pattern=r'^[a-z0-9]+(?:-[a-z0-9.]+)+$'),
                    store: SnapshotStore = Depends(get_snapshot_store)):
    """Exact-spec assessment for the sandbox; legacy /assessment stays unchanged."""
    try:
        engine, _, assessment = assess_uploaded(store, snapshot_id, benchmark_id)
        return {'snapshot_id': snapshot_id, 'benchmark_id': benchmark_id,
                'assessment': assessment, 'specs': engine.specs,
                'scope': 'Installed specs only; not full benchmark coverage'}
    except SnapshotNotFoundError as exc:
        raise HTTPException(404, 'Snapshot not found') from exc
    except (ContractError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc


@router.post('/api/v1/sandbox/handoffs', status_code=201)
def prepare_handoff(request: PrepareRequest, service: SandboxService = Depends(get_service),
                    store: SnapshotStore = Depends(get_snapshot_store)):
    try:
        handoff = prepare_uploaded(store, service, request)
        readiness = check_readiness(service, handoff, check_registry=True)
        if not readiness['ready_for_sandbox']:
            raise HTTPException(422, readiness)
        key = handoffs.put(handoff, request.snapshot_id)
        return {'handoff_id': key, 'snapshot_id': request.snapshot_id,
                'readiness': readiness, 'retry_mode': handoff.retry_mode,
                'approved_alternative_count': len(handoff.retry_template_refs)}
    except SnapshotNotFoundError as exc:
        raise HTTPException(404, 'Snapshot not found') from exc
    except (ContractError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    except psycopg2.Error as exc:
        raise HTTPException(503, 'Approved-template registry unavailable') from exc


@router.get('/api/v1/sandbox/handoffs/{handoff_id}')
def handoff_status(handoff_id: str, service: SandboxService = Depends(get_service)):
    item = handoffs.get(handoff_id)
    if item is None:
        raise HTTPException(404, 'Handoff not found or expired')
    return {key: value for key, value in item.items() if key != 'handoff'}


@router.post('/api/v1/sandbox/handoffs/{handoff_id}/run')
def run_handoff(handoff_id: str, service: SandboxService = Depends(get_service)):
    try:
        handoff = handoffs.begin(handoff_id)
    except KeyError as exc:
        raise HTTPException(404, 'Handoff not found or expired') from exc
    if handoff is None:
        item = handoffs.get(handoff_id)
        if item and item['status'] == 'FINISHED':
            return item['result']
        raise HTTPException(409, 'This handoff is running or was rejected; check its status')
    try:
        result = run_sandbox(handoff, service)
        return handoffs.finish(handoff_id, result)
    except BaseException:
        handoffs.fail(handoff_id)
        raise
