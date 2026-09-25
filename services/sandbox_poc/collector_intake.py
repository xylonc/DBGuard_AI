"""Accept native Phase 1 evidence without projecting or inventing check results."""
import copy

from .provenance import reconstruction_plan
from .shared import ContractError


def from_collector_bundle(bundle, engine):
    if bundle.get("envelope", {}).get("schema_version") != "0.3.0":
        raise ContractError("Sandbox requires collector v0.3.0 evidence; recollect with the exact check manifest")
    engine.assess(bundle)
    reconstruction_plan(bundle, engine.specs)
    return copy.deepcopy(bundle)
