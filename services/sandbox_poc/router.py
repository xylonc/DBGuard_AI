"""Synchronous local POC endpoint shared by standalone and existing API apps."""
import logging

import psycopg2
from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, Form
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field, model_validator
from typing import Literal
from . import history
from fastapi.responses import Response

from .review_bundle import BundleStore, build_review_bundle, is_fixture

from app.config import settings

from .handoff import SandboxHandoff
from .service import SandboxService
from .shared import ContractError
from .adaptive import LLMReviser
from .planning import LLMRiskReviewer, risk_review, recommend_order, fix_scope, manual_fix_reference, session_override_reason
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


# The user's active policy profile for one assessment: a profile hash from the
# profile store. Default none, so every policy control is MANUAL (policy_missing).
PROFILE_QUERY = Query(default=None, pattern=r'^[0-9a-f]{64}$',
                      description='Policy profile hash chosen by the user; omitted = no profile (policy_missing)')


@router.get('/api/v1/snapshots/{snapshot_id}/spec-assessment')
def spec_assessment(snapshot_id: str,
                    benchmark_id: str = Query(default='cis-pg17-v1.1.0', pattern=r'^[a-z0-9]+(?:-[a-z0-9.]+)+$'),
                    policy_profile: str | None = PROFILE_QUERY,
                    store: SnapshotStore = Depends(get_snapshot_store)):
    """Exact-spec assessment for the sandbox; legacy /assessment stays unchanged."""
    try:
        engine, _, assessment = assess_uploaded(store, snapshot_id, benchmark_id, policy_profile)
        return {'snapshot_id': snapshot_id, 'benchmark_id': benchmark_id,
                'policy_profile': engine.policy_pin,
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
             review_with_llm: bool = False, policy_profile: str | None = PROFILE_QUERY,
             store: SnapshotStore = Depends(get_snapshot_store), service: SandboxService = Depends(get_service)):
    try:
        engine, snapshot, assessment = assess_uploaded(store,snapshot_id,benchmark_id,policy_profile)
        fixes=[];manual=[];not_applicable=[]
        for sid,finding in assessment['findings'].items():
            if finding['status']=='PASS': continue
            if finding['status']=='NOT_APPLICABLE':
                # applies_when is false on clean evidence: neither a fix nor manual review.
                spec=next((s for s in engine.specs if s['spec_id']==sid),{})
                not_applicable.append({'spec_id':sid,'title':spec.get('ref',{}).get('title',sid),'tier':spec.get('tier'),
                                       'status':'NOT_APPLICABLE','condition':spec.get('applies_when',{}).get('condition_quote')})
                continue
            try:
                if finding['status']!='FAIL': raise ContractError(session_override_reason(finding) or 'Control requires capability or manual evidence')
                fixes.append(risk_review(engine,snapshot,sid,service.risk_reviewer if review_with_llm else None))
            except ContractError as exc:
                spec=next((s for s in engine.specs if s['spec_id']==sid),{})
                item={'spec_id':sid,'title':spec.get('ref',{}).get('title',sid),'tier':spec.get('tier'),
                      'status':finding['status'],'reason':str(exc)}
                if finding.get('explanation'):
                    # Same structured facts as the assessment row, so the UI shows one plain reason.
                    item['explanation']=finding['explanation']
                if finding['status']=='FAIL':
                    # No fix button: the DBA follows the CIS remediation (e.g. 5.2 without an approved address).
                    item['manual_fix']=manual_fix_reference(engine,spec)
                manual.append(item)
        # Catalog checks (F6) are outside the sandbox findings map; list them from
        # the full report so the DBA still sees them as not fixable.
        statuses={'FAIL':'FAIL','MANUAL':'MANUAL_REVIEW','NEEDS_CAPABILITY':'MANUAL_REVIEW'}
        for row in (assessment.get('upstream_report') or {}).get('results', []):
            if row['spec_id'] not in assessment['findings'] and row['result']!='PASS':
                manual.append({'spec_id':row['spec_id'],'title':row.get('title') or row['spec_id'],'tier':row.get('tier'),
                               'status':statuses.get(row['result'],'GAPPED'),'kind':'catalog',
                               'reason':'Assessment-only catalog check',
                               **({'explanation':row['explanation']} if row.get('explanation') else {})})
        if not review_with_llm:
            for fix in fixes: fix['llm']={'status':'NOT_REQUESTED'}
        return {'snapshot_id':snapshot_id,'spec_set_hash':engine.spec_set_hash,'policy_profile':getattr(engine,'policy_pin',None),'recommended_order':recommend_order(fixes),'manual_review':manual,'not_applicable':not_applicable,
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
        recorded=history.get(run_id)['handoff'].get('policy_profile_sha256')
        engine,snapshot,_=assess_uploaded(store,request.snapshot_id,request.benchmark_id,recorded)
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


# ---- policy profiles (UI only) ----------------------------------------------------
# Human-facing lifecycle for policy profiles. These routes are deliberately NOT
# exposed through the HERMES MCP bridge (services/dbguard_mcp/server.py has no tool
# for them), and approval takes only a profile hash and the reviewer's name: no
# profile values, no model output. An approved profile is never edited; an edit is
# a new draft.

def _profile_store(benchmark_id: str):
    from app.services.spec_engine import RecordsIndex, load_spec
    from .benchmarks import paths
    from .profiles import profile_store
    directory, records_path = paths(benchmark_id)
    if not directory.is_dir() or not records_path.is_file():
        raise ContractError('Exact benchmark specs/records are not installed')
    return profile_store(RecordsIndex.load(records_path), [load_spec(p) for p in sorted(directory.glob('*.yaml'))])


# Request limits for the policy-profile POST routes (drafts, validate-on-edit and
# approvals). A profile holds at most one entry per installed spec (72 CIS PG17
# recommendations), so these caps leave room without allowing unbounded input.
MAX_PROFILE_BODY_BYTES = 64 * 1024
MAX_PROFILE_ENTRIES = 100   # values / fixes entries
MAX_PROFILE_ROLES = 500     # connection_limits.roles entries


class _CappedBodyRequest(Request):
    """Reads at most MAX_PROFILE_BODY_BYTES; a larger body is refused with 413 before parsing."""

    async def body(self) -> bytes:
        if not hasattr(self, '_body'):
            declared = self.headers.get('content-length')
            if declared is not None and (not declared.isdigit() or int(declared) > MAX_PROFILE_BODY_BYTES):
                raise HTTPException(413, f'Policy profile request body exceeds {MAX_PROFILE_BODY_BYTES} bytes')
            chunks, size = [], 0
            async for chunk in self.stream():
                size += len(chunk)
                if size > MAX_PROFILE_BODY_BYTES:
                    raise HTTPException(413, f'Policy profile request body exceeds {MAX_PROFILE_BODY_BYTES} bytes')
                chunks.append(chunk)
            self._body = b''.join(chunks)
        return self._body


class _CappedBodyRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def capped(request: Request):
            return await handler(_CappedBodyRequest(request.scope, request.receive))
        return capped


# The policy-profile POST routes use the capped route class; included into router below.
profile_router = APIRouter(tags=["sandbox-poc"], route_class=_CappedBodyRoute)


class PolicyProfileDraft(BaseModel):
    model_config = {'extra': 'forbid'}
    profile_id: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
    values: dict = Field(default_factory=dict, max_length=MAX_PROFILE_ENTRIES)
    fixes: dict | None = Field(default=None, max_length=MAX_PROFILE_ENTRIES)
    connection_limits: dict | None = None
    based_on: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')

    @model_validator(mode='after')
    def _cap_roles(self):
        roles = (self.connection_limits or {}).get('roles')
        if isinstance(roles, dict) and len(roles) > MAX_PROFILE_ROLES:
            raise ValueError(f'connection_limits.roles must have at most {MAX_PROFILE_ROLES} entries')
        return self


class PolicyProfileApproval(BaseModel):
    model_config = {'extra': 'forbid'}
    approver_name: str = Field(min_length=1, max_length=120)



def _profile_view(store, profile) -> dict:
    """Summary plus displayed content. Both carry approval_auth next to approved_by."""
    from app.services.spec_engine.policy import APPROVAL_AUTH
    return {**store.summary(profile, store.source(profile)),
            'profile': {**store.document(profile), 'approval_auth': APPROVAL_AUTH}}


def _profile_controls(store) -> list[dict]:
    """Read-only display data: the controls a profile can carry a value for.

    ``policy_value``: parameterised specs with ``expected_from: policy`` (values[spec]).
    ``site_fix``: automated specs whose reviewed fix value is site-specific (fixes[spec],
    e.g. 5.2 listen_addresses). Spec text only; nothing here is model output.
    """
    from app.services.spec_engine.validate import uses_policy
    from .planning import POLICIES, FROM_PROFILE
    controls = []
    for spec in store.specs:
        check = spec.get('check')
        if not isinstance(check, dict):
            continue
        if uses_policy(spec):
            kind = 'policy_value'
        elif spec.get('tier') == 'automated' and POLICIES.get(check.get('setting_name'), (None,))[0] == FROM_PROFILE:
            kind = 'site_fix'
        else:
            continue
        ref = spec.get('ref') or {}
        item = {'spec_id': spec['spec_id'], 'kind': kind, 'recommendation': ref.get('recommendation'),
                'title': ref.get('title'), 'setting_name': check.get('setting_name'),
                'operator': check.get('operator'), 'pass_condition_quote': check.get('pass_condition_quote'),
                'reason': spec.get('reason'), 'interpretation': spec.get('interpretation') or []}
        if 'direction' in check:
            item['direction'] = check['direction']
        if kind == 'site_fix':
            item['expected'] = check.get('expected')
        applies_when = spec.get('applies_when')
        if isinstance(applies_when, dict):
            item['applies_when'] = {key: applies_when[key] for key in
                                    ('setting_name', 'operator', 'expected', 'direction', 'condition_quote')
                                    if key in applies_when}
        controls.append(item)

    def order(item):
        parts = str(item.get('recommendation') or '').split('.')
        return [int(p) if p.isdigit() else 0 for p in parts]
    return sorted(controls, key=order)


@router.get('/api/v1/benchmarks/{benchmark_id}/policy-profiles')
def list_policy_profiles(benchmark_id: str):
    from app.services.policy_profile_store import ProfileStoreError
    try:
        store = _profile_store(benchmark_id)
        return {'profiles': store.list(), 'controls': _profile_controls(store)}
    except (ContractError, ProfileStoreError) as exc: raise HTTPException(422, str(exc)) from exc


@profile_router.post('/api/v1/benchmarks/{benchmark_id}/policy-profiles/validate')
def validate_policy_profile_draft(benchmark_id: str, request: PolicyProfileDraft):
    """Read-only: check a draft exactly as create_draft does, without storing or logging it.

    Lets the UI validate on every edit without writing a draft each time. Returns
    {valid, errors[]}; it never approves anything and takes no approver.
    """
    from app.services.policy_profile_store import ProfileNotFoundError, ProfileStoreError, _dump
    from app.services.spec_engine.policy import PolicyProfileError, parse_profile, profile_value_errors
    try:
        store = _profile_store(benchmark_id)
    except ContractError as exc: raise HTTPException(422, str(exc)) from exc
    doc = {'profile_id': request.profile_id, 'benchmark': store.records.benchmark_id,
           'approved_by': None, 'approved_at': None, 'values': request.values or {}}
    if request.fixes:
        doc['fixes'] = request.fixes
    if request.connection_limits is not None:
        doc['connection_limits'] = request.connection_limits
    errors: list[str] = []
    if request.based_on is not None:
        try:
            store.get(request.based_on)
        except (ProfileNotFoundError, ProfileStoreError):
            errors.append('Base policy profile not found')
    try:
        profile = parse_profile(_dump(doc), store.records, 'draft')
    except PolicyProfileError as exc:
        message = str(exc).removeprefix('draft: invalid policy profile: ').removeprefix('draft: ')
        return {'valid': False, 'errors': errors + [part for part in message.split('; ') if part]}
    errors += profile_value_errors(profile, store.specs, strict=True)
    return {'valid': not errors, 'errors': errors}


@router.get('/api/v1/benchmarks/{benchmark_id}/policy-profiles/{profile_ref}')
def get_policy_profile(benchmark_id: str, profile_ref: str):
    from app.services.policy_profile_store import ProfileNotFoundError, ProfileStoreError
    try:
        store = _profile_store(benchmark_id)
        profile = store.get(profile_ref)
        return _profile_view(store, profile)
    except ProfileNotFoundError: raise HTTPException(404, 'Policy profile not found') from None
    except (ContractError, ProfileStoreError) as exc: raise HTTPException(422, str(exc)) from exc


@profile_router.post('/api/v1/benchmarks/{benchmark_id}/policy-profiles', status_code=201)
def create_policy_profile_draft(benchmark_id: str, request: PolicyProfileDraft):
    from app.services.policy_profile_store import ProfileNotFoundError, ProfileStoreError
    try:
        store = _profile_store(benchmark_id)
        profile = store.create_draft(**request.model_dump())
        return _profile_view(store, profile)
    except ProfileNotFoundError: raise HTTPException(404, 'Base policy profile not found') from None
    except (ContractError, ProfileStoreError) as exc: raise HTTPException(422, str(exc)) from exc


@profile_router.post('/api/v1/benchmarks/{benchmark_id}/policy-profiles/{profile_ref}/approve')
def approve_policy_profile(benchmark_id: str, profile_ref: str, request: PolicyProfileApproval):
    from app.services.policy_profile_store import ProfileNotFoundError, ProfileStoreError
    try:
        store = _profile_store(benchmark_id)
        profile = store.approve(profile_ref, request.approver_name)
        return {**_profile_view(store, profile), 'approved_from': profile_ref}
    except ProfileNotFoundError: raise HTTPException(404, 'Policy profile not found') from None
    except (ContractError, ProfileStoreError) as exc: raise HTTPException(422, str(exc)) from exc


router.include_router(profile_router)
