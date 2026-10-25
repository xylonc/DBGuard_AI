"""Contracts for the read-only PostgreSQL collector bundle.

The collector is owned independently from the downstream application.  These
models deliberately validate its stable envelope and the sections DBGuard uses,
while preserving any new collector sections through ``extra='allow'``.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class CollectorEnvelope(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: Literal["0.2.0"]
    collector_version: str = Field(min_length=1)
    collected_at: datetime
    target_id: str = Field(min_length=1, max_length=255)
    database: str = Field(min_length=1)
    collected_by: str = Field(min_length=1)
    is_superuser: bool
    deployment_type: str = "self-managed"


class CollectionGap(BaseModel):
    model_config = ConfigDict(extra="allow")

    section: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    remediation: str | None = None


class RedactionRecord(BaseModel):
    model_config = ConfigDict(extra="allow")

    field: str = Field(min_length=1)
    note: str | None = None


class CollectorBundleV020(BaseModel):
    """Collector wire format.

    Optional or inaccessible sections may be ``null``.  Do not coerce those
    values into empty collections: downstream code needs the accompanying gap
    record to distinguish unknown evidence from a verified empty result.
    """

    model_config = ConfigDict(extra="allow")

    envelope: CollectorEnvelope
    identity: dict[str, Any]
    settings: list[dict[str, Any]] | None
    roles: list[dict[str, Any]] | None
    gaps: list[CollectionGap] = Field(default_factory=list)
    redactions: list[RedactionRecord] = Field(default_factory=list)


class SnapshotUploadResponse(BaseModel):
    snapshot_id: str
    snapshot_hash: str
    target_id: str
    database: str
    schema_version: str
    collected_at: datetime | None
    gap_count: int
    status: Literal["stored"] = "stored"


class SnapshotContextResponse(BaseModel):
    snapshot_id: str
    snapshot_hash: str
    target_id: str
    database: str
    postgresql_version: str | None
    deployment_type: str
    collected_at: datetime | None
    settings: dict[str, Any]
    roles: list[dict[str, Any]] | None
    gaps: list[CollectionGap]
    available_sections: list[str]
    unavailable_sections: list[str]


class SnapshotV030(BaseModel):
    """Native Phase 1 snapshot, validated against the shared contract."""
    model_config = ConfigDict(extra="forbid", strict=True)
    envelope: dict[str, Any]
    baseline: dict[str, Any]
    checks: dict[str, Any]

    @model_validator(mode="after")
    def validate_wire_contract(self):
        import json
        from pathlib import Path
        from jsonschema import Draft202012Validator, ValidationError
        schema = Path(__file__).resolve().parents[2] / "catalog/specs/contracts/snapshot-v0.3.0.json"
        try:
            Draft202012Validator(json.loads(schema.read_text())).validate(self.model_dump())
        except ValidationError as exc:
            raise ValueError("Invalid snapshot-v0.3.0: " + exc.message) from exc
        return self


def parse_snapshot(payload: dict) -> CollectorBundleV020 | SnapshotV030:
    model = SnapshotV030 if payload.get("envelope", {}).get("schema_version") == "0.3.0" else CollectorBundleV020
    return model.model_validate(payload)
