"""Connect an upstream handoff to approved registry content and the test loop."""
import json
import uuid

from jsonschema import Draft202012Validator, ValidationError

from app.services.spec_engine import RecordsIndex, RecordsIntegrityError

from .handoff import SandboxHandoff
from .provenance import reconstruction_plan
from .runtime import DisposablePostgres
from .shared import ContractError, ROOT, SpecEngine
from .templates import from_registry
from .workflow import CONTROL, RemediationLoop


class SandboxService:
    def __init__(self, registry_url: str, image: str = "postgres:17-bookworm",
                 registry_loader=from_registry, runtime_factory=None):
        self.registry_url = registry_url
        self.image = image
        self.registry_loader = registry_loader
        self.runtime_factory = runtime_factory or (lambda: DisposablePostgres(image))

    def validate_handoff(self, request: SandboxHandoff) -> SpecEngine:
        try:
            records_path = ROOT / "catalog/benchmarks" / request.benchmark_id / "records.json"
            if not records_path.is_file():
                raise ContractError("Benchmark records are not installed on this server")
            validator = Draft202012Validator(json.loads((ROOT / "catalog/specs/schema.json").read_text()))
            for spec in request.specs:
                validator.validate(spec)
            engine = SpecEngine(request.specs, RecordsIndex.load(records_path))
            if engine.spec_set_hash != request.spec_set_hash:
                raise ContractError("Spec-set hash does not match supplied specs")
            assessment = engine.assess(request.snapshot)
            if assessment != request.assessment:
                raise ContractError("Assessment does not match the exact snapshot and specs")
            if assessment["findings"].get(CONTROL, {}).get("status") != "FAIL":
                raise ContractError("The supported log_connections control must be FAIL")
            if any(f["status"] == "GAPPED" for f in assessment["findings"].values()):
                raise ContractError("Gapped controls cannot establish regression coverage")
            reconstruction_plan(request.snapshot, engine.specs)
            return engine
        except ContractError:
            raise
        except (ValidationError, RecordsIntegrityError, KeyError, TypeError, ValueError) as exc:
            raise ContractError("Malformed or untraceable snapshot/spec handoff") from exc

    def run(self, request: SandboxHandoff) -> dict:
        # Validate before opening the registry or allocating any Docker resource.
        engine = self.validate_handoff(request)
        ref = request.template_ref
        template = self.registry_loader(
            self.registry_url, ref.version, ref.sha256,
            [entry.document_id for entry in ref.evidence], ref.environment,
            evidence_pins=[entry.model_dump() for entry in ref.evidence])
        result = RemediationLoop(engine, template, self.runtime_factory).run(
            request.snapshot, request.assessment)
        result.update(run_id=str(uuid.uuid4()), approval_source="registry",
                      requires_dba_review=True, handoff_version=request.schema_version)
        return result
