"""Bridge existing uploaded collector snapshots into exact-spec sandbox inputs."""
from collections import OrderedDict
import copy
from threading import Lock
from typing import Literal
import uuid

from pydantic import Field

from .collector_intake import from_collector_bundle
from .handoff import StrictModel, SandboxHandoff, build_handoff
from .shared import ROOT, SpecEngine, ContractError
from .templates import export_reference


class PrepareRequest(StrictModel):
    snapshot_id: str = Field(pattern=r'^snap-[a-zA-Z0-9]+$', max_length=64)
    benchmark_id: str = Field(default='cis-pg17-v1.1.0', pattern=r'^[a-z0-9]+(?:-[a-z0-9.]+)+$')
    template_version: int = Field(ge=1)
    evidence_ids: list[str] = Field(min_length=1, max_length=20)
    environment: Literal['dev', 'test', 'prod'] = 'dev'
    retry_mode: Literal['repeat', 'adaptive'] = 'adaptive'
    retry_template_versions: list[int] = Field(default_factory=list, max_length=2)


def assess_uploaded(store, snapshot_id, benchmark_id):
    directory = ROOT / 'catalog/specs' / benchmark_id
    records = ROOT / 'catalog/benchmarks' / benchmark_id / 'records.json'
    if not directory.is_dir() or not records.is_file():
        raise ContractError('Exact benchmark specs/records are not installed')
    engine = SpecEngine.load(directory, records)
    bundle = store.load(snapshot_id).model_dump(mode='json', exclude_none=False)
    snapshot = from_collector_bundle(bundle, engine)
    return engine, snapshot, engine.assess(snapshot)


def prepare_uploaded(store, service, request):
    engine, snapshot, assessment = assess_uploaded(store, request.snapshot_id, request.benchmark_id)
    ref, _ = export_reference(service.registry_url, request.template_version,
                              request.evidence_ids, request.environment)
    handoff = build_handoff(engine, snapshot, ref, assessment=assessment)
    handoff.retry_mode = request.retry_mode
    if len(set(request.retry_template_versions)) != len(request.retry_template_versions):
        raise ContractError('Retry template versions must be unique')
    handoff.retry_template_refs = [export_reference(service.registry_url, version,
        request.evidence_ids, request.environment)[0] for version in request.retry_template_versions]
    handoff = SandboxHandoff.model_validate(handoff.model_dump())
    service.validate_handoff(handoff)
    return handoff


def result_summary(result):
    return {**{key: result.get(key) for key in ('run_id', 'status', 'retry_mode', 'revisions',
                 'review_bundle', 'requires_dba_review', 'limitations')},
            'attempts': [{key: attempt.get(key) for key in ('attempt', 'candidate_id', 'status',
                         'phase', 'rollback_verified', 'health_after_apply', 'regressions', 'cleanup')}
                         for attempt in result.get('attempts', [])]}


class HandoffStore:
    """Bounded process-local handles; repeated execution returns the saved outcome."""
    def __init__(self, limit=8):
        self.limit, self.items, self.lock = limit, OrderedDict(), Lock()

    def put(self, handoff, snapshot_id):
        with self.lock:
            if len(self.items) >= self.limit:
                removable = next((key for key, item in self.items.items() if item['status'] != 'RUNNING'), None)
                if removable is None:
                    raise ContractError('All handoff slots are running; wait for a result')
                del self.items[removable]
            key = str(uuid.uuid4())
            self.items[key] = {'handoff': handoff.model_copy(deep=True), 'snapshot_id': snapshot_id,
                               'status': 'PREPARED', 'result': None}
            return key

    def get(self, key):
        with self.lock:
            return copy.deepcopy(self.items.get(key))

    def begin(self, key):
        with self.lock:
            item = self.items.get(key)
            if item is None:
                raise KeyError(key)
            if item['status'] != 'PREPARED':
                return None
            item['status'] = 'RUNNING'
            return item['handoff'].model_copy(deep=True)

    def finish(self, key, result):
        with self.lock:
            summary = result_summary(result)
            self.items[key].update(status='FINISHED', result=copy.deepcopy(summary))
            return summary

    def fail(self, key):
        with self.lock:
            self.items[key]['status'] = 'REJECTED'
