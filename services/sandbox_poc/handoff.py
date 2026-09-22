"""Versioned upstream handoff. No DSNs, filesystem paths or executable SQL."""
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class EvidenceReference(StrictModel):
    document_id: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=64)
    sha256: Hash


class TemplateReference(StrictModel):
    registry_name: Literal["set_config_parameter"] = "set_config_parameter"
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
    retry_mode: Literal["repeat", "adaptive"] = "repeat"
    retry_template_refs: list[TemplateReference] = Field(default_factory=list, max_length=2)

    @model_validator(mode='after')
    def candidate_scope(self):
        refs = [self.template_ref, *self.retry_template_refs]
        if any(ref.environment != self.template_ref.environment for ref in refs):
            raise ValueError('All candidate approvals must apply to the same environment')
        identities = [(ref.version, ref.sha256) for ref in refs]
        if len(identities) != len(set(identities)):
            raise ValueError('Candidate template identities must be unique')
        if self.retry_template_refs and self.retry_mode != 'adaptive':
            raise ValueError('Alternative templates require adaptive retry mode')
        return self


def build_handoff(engine, snapshot: dict, template_ref: TemplateReference, *,
                  assessment: dict | None = None) -> SandboxHandoff:
    """Xylon's caller can use this after shared collection; no registry writes."""
    from .shared import ContractError
    calculated = engine.assess(snapshot)
    if assessment is not None and assessment != calculated:
        raise ContractError("Upstream assessment does not match the exact snapshot and specs")
    benchmark_ids = {spec["spec_id"].split(":", 1)[0] for spec in engine.specs}
    if len(benchmark_ids) != 1:
        raise ValueError("One benchmark per handoff is supported")
    return SandboxHandoff(
        schema_version="sandbox-handoff-v1", benchmark_id=benchmark_ids.pop(),
        spec_set_hash=engine.spec_set_hash, specs=engine.specs, snapshot=snapshot,
        assessment=calculated, template_ref=template_ref)
