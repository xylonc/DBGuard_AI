"""Reproducible collector-to-review demo, with explicit fixture provenance."""
import hashlib
import json
from pathlib import Path

from app.collector_models import parse_snapshot
from app.services.snapshot_service import SnapshotStore

from .demo import DemoResources, DemoService
from .handoff import build_handoff
from .review_bundle import build_review_bundle
from .shared import ROOT, ContractError, digest
from .upstream import assess_uploaded


def run_collector_demo(output_dir: Path, resource_factory=DemoResources):
    # Refuse overwrite before creating a database or reading a registry.
    output_dir.mkdir(parents=True, exist_ok=False)
    summary = {'schema_version': 'collector-demo-v1', 'status': 'FAILED',
               'approval': 'DEMO_FIXTURE_ONLY', 'model': 'NOT_USED',
               'fixture_cleanup_verified': False, 'stage': 'create'}
    resources = resource_factory()
    archive = None

    def save(name, value):
        with (output_dir / name).open('x') as file:
            json.dump(value, file, indent=2)
            file.write('\n')

    try:
        resources.start()
        summary.update(session_id=resources.run_id, stage='collector_intake')
        bundle = resources.collector_bundle
        save('collector-snapshot.json', bundle)
        store = SnapshotStore(output_dir / 'uploaded-snapshots')
        uploaded = store.save(parse_snapshot(bundle))
        save('snapshot-receipt.json', uploaded.model_dump(mode='json'))
        engine, snapshot, assessment = assess_uploaded(store, uploaded.snapshot_id,
                                                       resources.handoff.benchmark_id)
        resources.snapshot = snapshot
        resources.handoff = build_handoff(engine, snapshot, resources.handoff.template_ref,
                                          assessment=assessment)
        save('handoff.json', resources.handoff.model_dump())
        summary.update(snapshot_id=uploaded.snapshot_id, spec_set_hash=engine.spec_set_hash,
                       raw_collector_hash=digest(bundle),
                       collector_files={name: hashlib.sha256((ROOT/'collector'/name).read_bytes()).hexdigest()
                                        for name in ('dbguard-collect.sh', 'collect.sql')},
                       stage='sandbox')
        result = DemoService(resources).run(resources.handoff)
        save('sandbox-result.json', result)
        summary.update(run_id=result['run_id'], sandbox_status=result['status'],
                       attempts=len(result['attempts']),
                       source_unchanged=result['demo_evidence']['source_unchanged'],
                       registry_unchanged=result['demo_evidence']['registry_unchanged'])
        if result['status'] != 'VERIFIED':
            raise ContractError('Sandbox did not verify the fix')
        if not summary['source_unchanged'] or not summary['registry_unchanged']:
            raise ContractError('Source or registry changed during testing')
        summary['stage'] = 'bundle'
        archive = build_review_bundle(resources.handoff, result, engine)
        summary['status'] = 'VERIFIED'
    except Exception:
        # Do not serialize driver errors, which may contain connection details.
        summary['error'] = f"Demo failed during {summary['stage']}; inspect the saved stage evidence"
    finally:
        try:
            resources.close()
            summary['fixture_cleanup_verified'] = True
        except Exception:
            summary.update(status='CLEANUP_FAILED', error='Run-owned fixture cleanup could not be verified')
        if summary['status'] == 'VERIFIED' and summary['fixture_cleanup_verified'] and archive:
            with (output_dir/'review-bundle.zip').open('xb') as output:
                output.write(archive)
            summary['review_bundle'] = 'review-bundle.zip'
            # A standalone report is convenient for reviewing without extraction.
            import io
            import zipfile
            with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
                with (output_dir/'report.html').open('xb') as output:
                    output.write(zipped.read('report.html'))
        save('summary.json', summary)
    return summary
