"""Synchronous local POC endpoint shared by standalone and existing API apps."""
import logging

import psycopg2
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from pydantic import BaseModel, Field
from typing import Literal
from . import history
from fastapi.responses import Response

from .review_bundle import BundleStore, build_review_bundle, is_fixture

from app.config import settings

from .handoff import SandboxHandoff
from .service import SandboxService
from .shared import ContractError
from .adaptive import LLMReviser
from .planning import LLMRiskReviewer, risk_review, recommend_order, fix_scope
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
    risk = LLMRiskReviewer(settings.sandbox_llm_base_url, settings.sandbox_llm_model, settings.sandbox_llm_api_key) if settings.sandbox_llm_enabled else None
    return SandboxService(settings.database_url, settings.sandbox_poc_image, reviser=reviser, risk_reviewer=risk)


@router.post("/api/v1/sandbox/runs", summary="Test a pinned, approved fix in disposable PostgreSQL")
def run_sandbox(request: SandboxHandoff, service: SandboxService = Depends(get_service)) -> dict:
    """Returns VERIFIED, FAILED or CLEANUP_FAILED with fix-unit and attempt evidence.

    This synchronous local POC never applies a fix to the source or registry DB.
    HTTP 200 means testing completed; inspect the result's status for acceptance.
    """
    try:
        data = None
        result = service.run(request)
        if result.get("status") == "VERIFIED":
            try:
                data = build_review_bundle(request, result, service.validate_handoff(request))
                bundles.put(result["run_id"], data)
                result["review_bundle"] = {"status": "READY", "demo_fixture_approval": is_fixture(result), "url": f"/api/v1/sandbox/runs/{result['run_id']}/bundle"}
            except ContractError as exc:
                # Keep the tested outcome; exporting a runnable script is a separate gate.
                result["review_bundle"] = {"status": "UNAVAILABLE", "reason": str(exc)}
        history.record(request, result, data)
        service.record_result(request, result)
        return result
    except ContractError as exc:
        raise HTTPException(422, str(exc)) from exc
    except psycopg2.Error as exc:
        # Do not include connection strings or raw registry errors in responses.
        logger.warning("Sandbox registry lookup failed")
        raise HTTPException(503, "Approved-template registry unavailable") from exc


@router.get("/api/v1/sandbox/runs/{run_id}/bundle", summary="Download a server-verified DBA review bundle")
def download_bundle(run_id: str, service: SandboxService = Depends(get_service)):
    data = bundles.get(run_id) or history.bundle(run_id)
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
        readiness = check_readiness(service, handoff, check_registry=True,
                                    allow_demo_fixtures=getattr(service, 'demo_fixture_mode', False))
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


@router.get('/api/v1/snapshots/{snapshot_id}/fix-plan')
def fix_plan(snapshot_id: str, benchmark_id: str = Query(default='cis-pg17-v1.1.0', pattern=r'^[a-z0-9]+(?:-[a-z0-9.]+)+$'),
             review_with_llm: bool = False, store: SnapshotStore = Depends(get_snapshot_store), service: SandboxService = Depends(get_service)):
    try:
        engine, snapshot, assessment = assess_uploaded(store,snapshot_id,benchmark_id)
        fixes=[];manual=[]
        for sid,finding in assessment['findings'].items():
            if finding['status']=='PASS': continue
            try:
                if finding['status']!='FAIL': raise ContractError('Control requires capability or manual evidence')
                fixes.append(risk_review(engine,snapshot,sid,service.risk_reviewer if review_with_llm else None))
            except ContractError as exc: manual.append({'spec_id':sid,'reason':str(exc)})
        if not review_with_llm:
            for fix in fixes: fix['llm']={'status':'NOT_REQUESTED'}
        return {'snapshot_id':snapshot_id,'spec_set_hash':engine.spec_set_hash,'recommended_order':recommend_order(fixes),'manual_review':manual,
                'ordering_basis':'Dependencies first, then lower operational risk; DBA decides security urgency and final order.'}
    except SnapshotNotFoundError: raise HTTPException(404,'Snapshot not found') from None
    except ContractError as exc: raise HTTPException(422,str(exc)) from exc


@router.get('/api/v1/history')
def run_history():
    return {'runs':history.list_runs()}


@router.get('/api/v1/history/{run_id}')
def run_history_detail(run_id: str):
    try: return history.get(run_id)
    except ContractError as exc: raise HTTPException(404,str(exc)) from exc


class OperatorEvent(BaseModel):
    kind: Literal['DBA_REPORTS_APPLIED','DBA_REPORTS_ROLLED_BACK','REVIEW_NOTE','MANUAL_EVIDENCE_ACCEPTED','MANUAL_EVIDENCE_REJECTED']
    operator: str = Field(min_length=1,max_length=255)
    note: str = Field(min_length=1,max_length=4000)
    evidence_sha256: str | None = Field(default=None,pattern=r"^[a-f0-9]{64}$")


@router.post('/api/v1/history/{run_id}/events')
def operator_event(run_id: str, request: OperatorEvent):
    if not request.operator.strip(): raise HTTPException(422,'Reviewer name is required')
    try:
        if request.kind.startswith('MANUAL_EVIDENCE_'):
            saved=history.get(run_id)
            if not request.evidence_sha256 or not any(e['kind']=='MANUAL_EVIDENCE_UPLOADED' and e['data']['sha256']==request.evidence_sha256 for e in saved['events']):
                raise ContractError('Select the exact uploaded evidence hash to review')
        history.event(run_id,request.kind,{**request.model_dump(),'verification':'Operator statement only; target verification requires fresh reassessment.'})
        return {'status':'RECORDED','kind':request.kind}
    except ContractError as exc: raise HTTPException(404,str(exc)) from exc


class ReassessmentRequest(BaseModel):
    snapshot_id: str = Field(pattern=r'^snap-[a-zA-Z0-9]+$')
    benchmark_id: str = Field(default='cis-pg17-v1.1.0',pattern=r'^[a-z0-9]+(?:-[a-z0-9.]+)+$')


@router.post('/api/v1/history/{run_id}/reassess')
def reassess_run(run_id: str, request: ReassessmentRequest, store: SnapshotStore = Depends(get_snapshot_store)):
    try:
        engine,snapshot,_=assess_uploaded(store,request.snapshot_id,request.benchmark_id)
        return history.compare(run_id,snapshot,engine)
    except (ContractError,SnapshotNotFoundError) as exc: raise HTTPException(422,str(exc)) from exc


@router.post('/api/v1/history/{run_id}/evidence')
async def manual_evidence(run_id: str, control_id: str = Form(...), operator: str = Form(...), file: UploadFile = File(...)):
    import hashlib,base64
    data=await file.read(5*1024*1024+1)
    if len(data)>5*1024*1024 or not (data.startswith(b'\x89PNG\r\n\x1a\n') or data.startswith(b'\xff\xd8\xff')):
        raise HTTPException(422,'Supply a PNG or JPEG of at most 5 MB')
    if not operator.strip() or len(operator)>255: raise HTTPException(422,'Operator name is required')
    try:
        run=history.get(run_id)
        if control_id not in run['result']['spec_hashes']: raise ContractError('Control is outside the recorded spec set')
        receipt={'control_id':control_id,'operator':operator,'sha256':hashlib.sha256(data).hexdigest(),'status':'PENDING_REVIEW','image_base64':base64.b64encode(data).decode(),'format':'png' if data.startswith(b'\x89PNG') else 'jpeg'}
        history.event(run_id,'MANUAL_EVIDENCE_UPLOADED',receipt)
        return {k:v for k,v in receipt.items() if k!='image_base64'}
    except ContractError as exc: raise HTTPException(422,str(exc)) from exc


class BatchRequest(BaseModel):
    fixes: list[PrepareRequest] = Field(min_length=2,max_length=6)
    requested_order: list[str] | None = Field(default=None,max_length=6)


@router.post('/api/v1/sandbox/batches')
def sandbox_batch(request: BatchRequest, service: SandboxService = Depends(get_service), store: SnapshotStore = Depends(get_snapshot_store)):
    from .batch import run_batch
    try:
        requests=[prepare_uploaded(store,service,r) for r in request.fixes]
        result,data=run_batch(requests,service,request.requested_order)
        if data:
            bundles.put(result['run_id'],data)
            result['review_bundle']={'status':'READY','url':f"/api/v1/sandbox/runs/{result['run_id']}/bundle"}
        if result.get('schema_version')=='sandbox-batch-v1': history.record(requests[0],result,data)
        return result
    except (ContractError,ValueError) as exc: raise HTTPException(422,str(exc)) from exc


@router.post('/api/v1/benchmarks/import')
async def import_benchmark(file: UploadFile = File(...)):
    from .benchmarks import import_workbook
    try: return import_workbook(await file.read(20*1024*1024+1))
    except Exception as exc:
        logger.info('Benchmark import rejected: %s',type(exc).__name__)
        raise HTTPException(422,'Workbook must use CIS PostgreSQL 17 v1.1.0 Combined Profiles with valid required fields and within size limits') from None


@router.get('/api/v1/benchmarks/{benchmark_id}/package')
def benchmark_package(benchmark_id: str):
    from .benchmarks import package
    try: return Response(package(benchmark_id),media_type='application/zip',headers={'Content-Disposition':'attachment; filename="benchmark-review.zip"'})
    except ContractError as exc: raise HTTPException(404,str(exc)) from exc


class BenchmarkApproval(BaseModel):
    reviewer: str = Field(min_length=1,max_length=255)
    spec_set_hash: str = Field(pattern=r'^[a-f0-9]{64}$')


@router.post('/api/v1/benchmarks/{benchmark_id}/approve')
def approve_benchmark(benchmark_id: str, request: BenchmarkApproval):
    from .benchmarks import package,local_root
    from .shared import SpecEngine
    from datetime import datetime,timezone
    import json
    try:
        package(benchmark_id)  # validates the ID and existence
        folder=local_root()/benchmark_id
        engine=SpecEngine.load(folder/'specs',folder/'records.json')
        if engine.spec_set_hash!=request.spec_set_hash or not request.reviewer.strip(): raise ContractError('Exact reviewed spec hash and reviewer are required')
        approval={'reviewer':request.reviewer,'spec_set_hash':request.spec_set_hash,'approved_at':datetime.now(timezone.utc).isoformat()}
        if (folder/'approval.json').exists(): raise ContractError('This release already has its recorded approval')
        (folder/'approval.json').write_text(json.dumps(approval,indent=2))
        return {'status':'APPROVED','benchmark_id':benchmark_id,**approval}
    except ContractError as exc: raise HTTPException(422,str(exc)) from exc


@router.get('/api/v1/snapshots/{snapshot_id}/runs')
def snapshot_runs(snapshot_id: str, benchmark_id: str = Query(default='cis-pg17-v1.1.0',pattern=r'^[a-z0-9]+(?:-[a-z0-9.]+)+$'), store: SnapshotStore = Depends(get_snapshot_store)):
    from .shared import digest
    try:
        engine,snapshot,_=assess_uploaded(store,snapshot_id,benchmark_id)
        for summary in history.list_runs():
            item=history.get(summary['run_id'])
            if item['result']['snapshot_hash']==digest(snapshot) and item['result']['spec_set_hash']==engine.spec_set_hash:
                return {'result':item['result']}
        return {'result':None}
    except (ContractError,SnapshotNotFoundError) as exc: raise HTTPException(422,str(exc)) from exc


@router.get('/api/v1/history/{run_id}/evidence-bundle')
def complete_evidence_bundle(run_id: str):
    import io,json,zipfile,base64
    try: item=history.get(run_id)
    except ContractError as exc: raise HTTPException(404,str(exc)) from exc
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED) as z:
        original=history.bundle(run_id)
        if original: z.writestr('original-dba-review.zip',original)
        for e in item['events']:
            data=e['data']
            if e['kind']=='MANUAL_EVIDENCE_UPLOADED':
                z.writestr('attachments/'+data['sha256']+'.'+data['format'],base64.b64decode(data['image_base64']))
                data['image_file']='attachments/'+data['sha256']+'.'+data['format'];del data['image_base64']
        z.writestr('history.json',json.dumps(item,indent=2))
        z.writestr('README.txt','The original sandbox bundle is preserved. history.json contains DBA statements, uploaded evidence reviews and server-computed target reassessments. Operator statements and uploaded images do not independently prove target health.\n')
    return Response(buf.getvalue(),media_type='application/zip',headers={'Content-Disposition':'attachment; filename="dbguard-complete-evidence.zip"'})
