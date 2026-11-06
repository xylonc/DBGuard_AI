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
from .planning import fix_scope, risk_review, session_override_reason


class SandboxService:
    def __init__(self, registry_url: str, image: str | None = None,
                 registry_loader=from_registry, runtime_factory=None, reviser=None, risk_reviewer=None):
        self.registry_url = registry_url
        self.image = image
        self.registry_loader = registry_loader
        self.runtime_factory = runtime_factory or (lambda: DisposablePostgres(image))
        self.reviser = reviser
        self.risk_reviewer = risk_reviewer

    def record_result(self, request, result):
        """Optional local UI integration; called after bundle generation finishes."""

    def validate_handoff(self, request: SandboxHandoff) -> SpecEngine:
        try:
            from .benchmarks import paths
            _, records_path = paths(request.benchmark_id)
            if not records_path.is_file():
                raise ContractError("Benchmark records are not installed on this server")
            validator = Draft202012Validator(json.loads((ROOT / "catalog/specs/schema.json").read_text()))
            for spec in request.specs:
                validator.validate(spec)
            from .profiles import resolve_profile
            records = RecordsIndex.load(records_path)
            engine = SpecEngine(request.specs, records,
                                resolve_profile(records, request.specs, request.policy_profile_sha256))
            if "-import-" in request.benchmark_id:
                approved = SpecEngine.load(records_path.parent/"specs",records_path)
                if engine.spec_set_hash != approved.spec_set_hash:
                    raise ContractError("Handoff differs from the approved imported spec set")
            if engine.spec_set_hash != request.spec_set_hash:
                raise ContractError("Spec-set hash does not match supplied specs")
            assessment = engine.bind_assessment(request.snapshot, request.assessment)
            from .catalog_fixes import catalog_fix_scope, is_catalog_fix, reconstruction_names
            # W2B: a reviewed catalog-linked fix (3.2, 5.6, 6.10). Its FAIL is in the full
            # report, not the sandbox findings map; catalog_fix_scope checks it.
            catalog = request.object_fix_id is None and is_catalog_fix(engine, request.control_id)
            if request.object_fix_id is None and not catalog:
                if assessment["findings"].get(request.control_id, {}).get("status") != "FAIL":
                    raise ContractError("The selected supported control must be FAIL")
            gapped = engine.gapped_settings(assessment["findings"])
            if gapped:
                overrides = [reason for sid in gapped
                             if (reason := session_override_reason(assessment["findings"][sid]))]
                raise ContractError("Gapped controls cannot establish regression coverage"
                                    + (f". {overrides[0]}" if overrides else ""))
            extra = ()
            if catalog:
                if request.retry_template_refs or request.retry_mode != "repeat":
                    raise ContractError("Catalog-linked fixes have no alternative templates or adaptive retries")
                if request.template_ref.registry_name != "set_config_parameter":
                    raise ContractError("Catalog-linked fixes use the approved set_config_parameter template only")
                scope = catalog_fix_scope(engine, request.snapshot, request.control_id, assessment)
                uses_list = any(c["template"] == "set_config_list" for c in scope["changes"])
                if uses_list != (request.list_template_ref is not None):
                    raise ContractError("A catalog fix that changes shared_preload_libraries needs exactly the "
                                        "approved set_config_list template (list_template_ref); other fixes none")
                extra = reconstruction_names(engine, request.snapshot, scope)
            elif request.list_template_ref is not None:
                raise ContractError("Only a catalog fix that changes shared_preload_libraries uses a list template")
            elif request.object_fix_id is None:
                fix_scope(engine, request.control_id)
            else:
                self.object_proposal(engine, request)
            reconstruction_plan(request.snapshot, engine.specs, extra)
            return engine
        except ContractError:
            raise
        except (ValidationError, RecordsIntegrityError, KeyError, TypeError, ValueError) as exc:
            raise ContractError("Malformed or untraceable snapshot/spec handoff") from exc

    @staticmethod
    def object_proposal(engine: SpecEngine, request: SandboxHandoff) -> dict:
        """Re-derive the selected per-object fix from the handoff's own evidence.

        Only the fix id travels in a handoff; names and values come from
        object_fixes.resolve on this snapshot and the engine's (approved) profile.
        """
        from .object_fixes import FIX_TYPES, resolve
        proposal = resolve(engine, request.snapshot, engine.policy_pin, request.object_fix_id)
        if proposal["spec_id"] != request.control_id:
            raise ContractError("The selected control is not the object fix's control")
        if FIX_TYPES[proposal["fix_type"]].template != request.template_ref.registry_name:
            raise ContractError("The template is not the approved template for this object fix type")
        if not proposal["rehearsable"]:
            raise ContractError(proposal.get("not_rehearsable_reason") or "This fix cannot be rehearsed")
        return proposal

    def resolve_template(self, request: SandboxHandoff, ref=None):
        """Resolve exact pins using the SELECT-only registry loader."""
        ref = ref or request.template_ref
        return self.registry_loader(
            self.registry_url, ref.version, ref.sha256,
            [entry.document_id for entry in ref.evidence], ref.environment,
            evidence_pins=[entry.model_dump() for entry in ref.evidence],
            **({"registry_name":ref.registry_name} if ref.registry_name != "set_config_parameter" else {}))

    def run(self, request: SandboxHandoff) -> dict:
        # Validate before opening the registry or allocating any Docker resource.
        engine = self.validate_handoff(request)
        if request.retry_mode == 'adaptive' and self.reviser is None:
            raise ContractError('Adaptive retries require the sandbox LLM reviewer to be configured')
        if request.object_fix_id is not None:
            return self.run_object(engine, request)
        from .catalog_fixes import is_catalog_fix
        if is_catalog_fix(engine, request.control_id):
            return self.run_catalog(engine, request)
        template = self.resolve_template(request)
        alternatives = [self.resolve_template(request, ref) for ref in request.retry_template_refs] if request.retry_mode == 'adaptive' else []

        def refresh(candidate):
            ref = next(ref for ref in request.retry_template_refs
                       if ref.registry_name == candidate.registry_name and ref.version == candidate.version and ref.sha256 == candidate.sha256)
            return self.resolve_template(request, ref)

        review = risk_review(engine, request.snapshot, request.control_id, self.risk_reviewer, template.risk_level)
        result = RemediationLoop(engine, template, self.runtime_factory,
            reviser=self.reviser if request.retry_mode == 'adaptive' else None,
            alternatives=alternatives, refresh_template=refresh, control_id=request.control_id).run(
            request.snapshot, request.assessment)
        result["risk_review"] = review
        result.update(run_id=str(uuid.uuid4()), approval_source="registry",
                      requires_dba_review=True, handoff_version=request.schema_version)
        return result

    def run_catalog(self, engine: SpecEngine, request: SandboxHandoff) -> dict:
        """W2B: rehearse one reviewed catalog-linked setting fix (3.2, 5.6, 6.10)."""
        from .catalog_fixes import CatalogFixLoop, catalog_risk_review
        template = self.resolve_template(request)
        list_template = (self.resolve_template(request, request.list_template_ref)
                         if request.list_template_ref is not None else None)
        risks = {"low": 0, "medium": 1, "high": 2, "not_assessed": 3}
        template_risk = max((t.risk_level for t in (template, list_template) if t and t.risk_level in risks),
                            key=risks.get, default=None)
        review = catalog_risk_review(engine, request.snapshot, request.control_id,
                                     self.risk_reviewer, template_risk)
        result = CatalogFixLoop(engine, template, self.runtime_factory, control_id=request.control_id,
                                list_template=list_template).run(request.snapshot, request.assessment)
        result["risk_review"] = review
        result.update(run_id=str(uuid.uuid4()), approval_source="registry",
                      requires_dba_review=True, handoff_version=request.schema_version)
        return result

    def run_object(self, engine: SpecEngine, request: SandboxHandoff) -> dict:
        """Wave 2a: rehearse one per-object fix (sandbox loop owned by workflow.py)."""
        from .workflow import ObjectRemediationLoop
        proposal = self.object_proposal(engine, request)
        template = self.resolve_template(request)
        result = ObjectRemediationLoop(engine, template, proposal,
                                       runtime_factory=self.runtime_factory).run(
            request.snapshot, request.assessment)
        result.update(run_id=str(uuid.uuid4()), approval_source="registry",
                      requires_dba_review=True, handoff_version=request.schema_version)
        return result
