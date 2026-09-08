"""Immutable local storage and safe context projection for collector bundles."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from app.collector_models import (
    CollectorBundleV020,
    SnapshotContextResponse,
    SnapshotUploadResponse,
)


class SnapshotNotFoundError(FileNotFoundError):
    pass


class SnapshotStore:
    """Content-addressed snapshot storage.

    Identical bundles resolve to the same ID. Files are written atomically so a
    downstream reader never observes a partially uploaded collector bundle.
    """

    def __init__(self, storage_dir: str | Path):
        self.storage_dir = Path(storage_dir).resolve()

    @staticmethod
    def _canonical_bytes(bundle: CollectorBundleV020) -> bytes:
        payload = bundle.model_dump(mode="json", exclude_none=False)
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    def save(self, bundle: CollectorBundleV020) -> SnapshotUploadResponse:
        data = self._canonical_bytes(bundle)
        digest = hashlib.sha256(data).hexdigest()
        snapshot_id = f"snap-{digest[:20]}"
        destination = self.storage_dir / f"{snapshot_id}.json"
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        if not destination.exists():
            with NamedTemporaryFile(
                mode="wb",
                dir=self.storage_dir,
                prefix=f".{snapshot_id}-",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)
            os.replace(temporary_path, destination)

        envelope = bundle.envelope
        return SnapshotUploadResponse(
            snapshot_id=snapshot_id,
            snapshot_hash=digest,
            target_id=envelope.target_id,
            database=envelope.database,
            schema_version=envelope.schema_version,
            collected_at=envelope.collected_at,
            gap_count=len(bundle.gaps),
        )

    def load(self, snapshot_id: str) -> CollectorBundleV020:
        if not snapshot_id.startswith("snap-") or not snapshot_id[5:].isalnum():
            raise SnapshotNotFoundError(snapshot_id)
        path = self.storage_dir / f"{snapshot_id}.json"
        if not path.is_file():
            raise SnapshotNotFoundError(snapshot_id)
        return CollectorBundleV020.model_validate_json(path.read_text(encoding="utf-8"))

    def context(self, snapshot_id: str) -> SnapshotContextResponse:
        bundle = self.load(snapshot_id)
        canonical = self._canonical_bytes(bundle)
        digest = hashlib.sha256(canonical).hexdigest()
        raw = bundle.model_dump(mode="json", exclude_none=False)
        gaps = bundle.gaps
        unavailable = sorted({gap.section for gap in gaps})

        settings: dict[str, Any] = {}
        if bundle.settings is not None:
            settings = {
                item["name"]: item.get("setting")
                for item in bundle.settings
                if isinstance(item, dict) and item.get("name")
            }

        version_number = bundle.identity.get("server_version_num")
        try:
            pg_version = str(int(version_number) // 10000) if version_number else None
        except (TypeError, ValueError):
            pg_version = None
        known_metadata = {"envelope", "gaps", "redactions", "host_not_collected"}
        available = sorted(
            key
            for key, value in raw.items()
            if key not in known_metadata and value is not None
        )

        return SnapshotContextResponse(
            snapshot_id=snapshot_id,
            snapshot_hash=digest,
            target_id=bundle.envelope.target_id,
            database=bundle.envelope.database,
            postgresql_version=pg_version,
            deployment_type=bundle.envelope.deployment_type,
            collected_at=bundle.envelope.collected_at,
            settings=settings,
            roles=bundle.roles,
            gaps=gaps,
            available_sections=available,
            unavailable_sections=unavailable,
        )
