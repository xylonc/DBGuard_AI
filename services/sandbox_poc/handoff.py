"""Versioned upstream handoff. No DSNs, filesystem paths or executable SQL."""
import re
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

# Reviewed template-name allowlist for sandbox runs: the setting template (and its
# approved __<variant> alternatives) plus the six Wave 2a per-object fix templates.
# Any other registry name is refused before the registry is read.
SETTING_TEMPLATE_PATTERN = r"set_config_parameter(?:__[a-z0-9_]+)?"
OBJECT_TEMPLATE_NAMES = ("role_connection_limit", "role_drop_attribute", "role_nologin",
                         "function_security_invoker", "function_revoke_public_execute",
                         "table_revoke_dml")
TEMPLATE_NAME_PATTERN = r"^(?:" + SETTING_TEMPLATE_PATTERN + "|" + "|".join(OBJECT_TEMPLATE_NAMES) + r")$"
# fix-<CIS recommendation>-<fix type>-<first 10 hex of sha256(canonical target JSON)>;
# derived and re-derived server-side by object_fixes, never chosen by a client.
OBJECT_FIX_ID_PATTERN = (r"^fix-[0-9]+(?:\.[0-9]+)*-(?:" + "|".join(OBJECT_TEMPLATE_NAMES)
                         + r")-[0-9a-f]{10}$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EvidenceReference(StrictModel):
    document_id: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=64)
    sha256: Hash


class TemplateReference(StrictModel):
    registry_name: str = Field(default="set_config_parameter", pattern=TEMPLATE_NAME_PATTERN)
    version: int = Field(ge=1)
    sha256: Hash
    evidence: list[EvidenceReference] = Field(min_length=1, max_length=20)
    environment: Literal["dev", "test", "prod"] = "dev"

    @model_validator(mode="after")
    def unique_evidence(self):
        ids = [entry.document_id for entry in self.evidence]
        if len(ids) != len(set(ids)):
            raise ValueError("Evidence document IDs must be unique")
        return self


class SandboxHandoff(StrictModel):
    schema_version: Literal["sandbox-handoff-v1"]
    benchmark_id: str = Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9.]+)+$")
    spec_set_hash: Hash
    specs: list[dict] = Field(min_length=1, max_length=1000)
    snapshot: dict
    assessment: dict
    template_ref: TemplateReference
    control_id: str = Field(default="cis-pg17-v1.1.0:3.1.20",
                            description="Exact selected spec ID; defaults to cis-pg17-v1.1.0:3.1.20 for older callers")
    retry_mode: Literal["repeat", "adaptive"] = "repeat"
    retry_template_refs: list[TemplateReference] = Field(default_factory=list, max_length=2)
    # Hash of the policy profile the assessment used (resolved server-side from the
    # profile store); None means no profile (policy_missing). Never profile values.
    policy_profile_sha256: Hash | None = None
    # Wave 2a: a per-object fix chosen from the fix plan. Only the id is carried; the
    # sandbox re-derives the proposal from this snapshot (object_fixes.resolve).
    object_fix_id: str | None = Field(default=None, max_length=96, pattern=OBJECT_FIX_ID_PATTERN)

    @model_validator(mode='after')
    def candidate_scope(self):
        if self.object_fix_id is None:
            if not re.fullmatch(SETTING_TEMPLATE_PATTERN, self.template_ref.registry_name):
                raise ValueError('Per-object fix templates need an object_fix_id')
        else:
            fix_type = self.object_fix_id.split('-')[2]
            if self.template_ref.registry_name != fix_type:
                raise ValueError('The template must be the approved template for this object fix type')
            if self.retry_template_refs or self.retry_mode != 'repeat':
                raise ValueError('Object fixes have no alternative templates or adaptive retries')
        if any(not re.fullmatch(SETTING_TEMPLATE_PATTERN, ref.registry_name) for ref in self.retry_template_refs):
            raise ValueError('Alternative templates must be setting templates')
        refs = [self.template_ref, *self.retry_template_refs]
        if any(ref.environment != self.template_ref.environment for ref in refs):
            raise ValueError('All candidate approvals must apply to the same environment')
        identities = [(ref.registry_name, ref.version, ref.sha256) for ref in refs]
        if len(identities) != len(set(identities)):
            raise ValueError('Candidate template identities must be unique')
        if self.retry_template_refs and self.retry_mode != 'adaptive':
            raise ValueError('Alternative templates require adaptive retry mode')
        return self


def build_handoff(engine, snapshot: dict, template_ref: TemplateReference, *,
                  assessment: dict | None = None, object_fix_id: str | None = None,
                  control_id: str | None = None) -> SandboxHandoff:
    """Xylon's caller can use this after shared collection; no registry writes."""
    calculated = engine.bind_assessment(snapshot, assessment)
    benchmark_ids = {spec["spec_id"].split(":", 1)[0] for spec in engine.specs}
    if len(benchmark_ids) != 1:
        raise ValueError("One benchmark per handoff is supported")
    return SandboxHandoff(
        schema_version="sandbox-handoff-v1", benchmark_id=benchmark_ids.pop(),
        spec_set_hash=engine.spec_set_hash, specs=engine.specs, snapshot=snapshot,
        assessment=calculated, template_ref=template_ref,
        policy_profile_sha256=engine.policy.sha256 if engine.policy is not None else None,
        object_fix_id=object_fix_id,
        **({"control_id": control_id} if control_id is not None else {}))
