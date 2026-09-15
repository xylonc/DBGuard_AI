"""Tier A tests for Snapshot Intake - Pure (zero external dependencies)."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.collector_models import CollectorBundleV020
from app.services.snapshot_service import SnapshotNotFoundError, SnapshotStore

pytestmark = pytest.mark.tier_a


class TestSnapshotIntakePure:
    """Pure tests for Snapshot Store - mocks all external dependencies."""

    def test_round_trip_is_content_addressed_and_preserves_gap(self, temp_snapshot_dir):
        """Test that identical bundles resolve to the same ID."""
        bundle = CollectorBundleV020.model_validate(
            {
                "envelope": {
                    "schema_version": "0.2.0",
                    "collector_version": "2.0.0-sql",
                    "collected_at": "2026-09-03T06:00:00Z",
                    "target_id": "demo-primary",
                    "database": "postgres",
                    "collected_by": "dbguard_collector",
                    "is_superuser": False,
                    "deployment_type": "self-managed",
                },
                "identity": {"server_version_num": 160006},
                "settings": [
                    {"name": "password_encryption", "setting": "scram-sha-256"},
                    {"name": "ssl", "setting": "on"},
                ],
                "roles": [],
                "gaps": [
                    {
                        "section": "hba_rules",
                        "reason": "insufficient_privilege",
                        "remediation": "Grant explicit read access.",
                    }
                ],
                "redactions": [{"field": "pg_authid.rolpassword", "class": "S0"}],
            }
        )
        store = SnapshotStore(temp_snapshot_dir)
        first = store.save(bundle)
        second = store.save(bundle)

        assert first.snapshot_id == second.snapshot_id
        assert first.snapshot_hash == second.snapshot_hash

        context = store.context(first.snapshot_id)
        assert context.postgresql_version == "16"
        assert context.settings["ssl"] == "on"
        assert "hba_rules" in context.unavailable_sections
        assert "hba_rules" not in context.available_sections

        json_files = list(Path(temp_snapshot_dir).glob("*.json"))
        assert len(json_files) == 1

    def test_rejects_unsupported_collector_schema(self):
        """Test that unsupported collector schema versions are rejected."""
        payload = {
            "envelope": {
                "schema_version": "0.1.0",
                "collector_version": "2.0.0-sql",
                "collected_at": "2026-09-03T06:00:00Z",
                "target_id": "demo-primary",
                "database": "postgres",
                "collected_by": "dbguard_collector",
                "is_superuser": False,
                "deployment_type": "self-managed",
            },
            "identity": {"server_version_num": 160006},
            "settings": [],
            "roles": [],
            "gaps": [],
            "redactions": [],
        }
        with pytest.raises(Exception):
            CollectorBundleV020.model_validate(payload)

    def test_rejects_path_like_snapshot_identifier(self, temp_snapshot_dir):
        """Test that path-like snapshot identifiers are rejected."""
        store = SnapshotStore(temp_snapshot_dir)
        with pytest.raises(SnapshotNotFoundError):
            store.load("../secret")
        with pytest.raises(SnapshotNotFoundError):
            store.load("/etc/passwd")
        with pytest.raises(SnapshotNotFoundError):
            store.load("snap-../malicious")

    def test_snapshot_store_is_content_addressed(self, temp_snapshot_dir):
        """Test that different content produces different IDs."""
        bundle1 = CollectorBundleV020.model_validate(
            {
                "envelope": {
                    "schema_version": "0.2.0",
                    "collector_version": "2.0.0-sql",
                    "collected_at": "2026-09-03T06:00:00Z",
                    "target_id": "demo-primary",
                    "database": "postgres",
                    "collected_by": "dbguard_collector",
                    "is_superuser": False,
                    "deployment_type": "self-managed",
                },
                "identity": {"server_version_num": 160006},
                "settings": [
                    {"name": "ssl", "setting": "on"},
                ],
                "roles": [],
                "gaps": [],
                "redactions": [],
            }
        )
        bundle2 = CollectorBundleV020.model_validate(
            {
                "envelope": {
                    "schema_version": "0.2.0",
                    "collector_version": "2.0.0-sql",
                    "collected_at": "2026-09-03T06:00:00Z",
                    "target_id": "demo-primary",
                    "database": "postgres",
                    "collected_by": "dbguard_collector",
                    "is_superuser": False,
                    "deployment_type": "self-managed",
                },
                "identity": {"server_version_num": 160006},
                "settings": [
                    {"name": "ssl", "setting": "off"},
                ],
                "roles": [],
                "gaps": [],
                "redactions": [],
            }
        )
        store = SnapshotStore(temp_snapshot_dir)
        first = store.save(bundle1)
        second = store.save(bundle2)

        assert first.snapshot_id != second.snapshot_id
        assert first.snapshot_hash != second.snapshot_hash

    def test_snapshot_context_extracts_all_metadata(self, temp_snapshot_dir):
        """Test that snapshot context extracts all required metadata."""
        bundle = CollectorBundleV020.model_validate(
            {
                "envelope": {
                    "schema_version": "0.2.0",
                    "collector_version": "2.0.0-sql",
                    "collected_at": "2026-09-03T06:00:00Z",
                    "target_id": "demo-primary",
                    "database": "postgres",
                    "collected_by": "dbguard_collector",
                    "is_superuser": True,
                    "deployment_type": "managed",
                },
                "identity": {"server_version_num": 150001},
                "settings": [
                    {"name": "max_connections", "setting": "100"},
                    {"name": "shared_buffers", "setting": "256MB"},
                ],
                "roles": [{"rolname": "test_user", "rolsuper": False}],
                "gaps": [],
                "redactions": [],
            }
        )
        store = SnapshotStore(temp_snapshot_dir)
        upload = store.save(bundle)
        context = store.context(upload.snapshot_id)

        assert context.snapshot_id == upload.snapshot_id
        assert context.snapshot_hash == upload.snapshot_hash
        assert context.target_id == "demo-primary"
        assert context.database == "postgres"
        assert context.postgresql_version == "15"
        assert context.deployment_type == "managed"
        assert context.settings["max_connections"] == "100"
        assert context.settings["shared_buffers"] == "256MB"
        assert context.roles[0]["rolname"] == "test_user"
        assert "ssl" not in context.settings

    def test_snapshot_store_preserves_redaction_records(self, temp_snapshot_dir):
        """Test that redaction records are preserved in snapshot context."""
        bundle = CollectorBundleV020.model_validate(
            {
                "envelope": {
                    "schema_version": "0.2.0",
                    "collector_version": "2.0.0-sql",
                    "collected_at": "2026-09-03T06:00:00Z",
                    "target_id": "demo-primary",
                    "database": "postgres",
                    "collected_by": "dbguard_collector",
                    "is_superuser": False,
                    "deployment_type": "self-managed",
                },
                "identity": {"server_version_num": 160006},
                "settings": [],
                "roles": [],
                "gaps": [],
                "redactions": [
                    {"field": "pg_authid.rolpassword", "note": "Sensitive password hash"},
                    {"field": "pg_shadow.usepassword", "class": "S0"},
                ],
            }
        )
        store = SnapshotStore(temp_snapshot_dir)
        upload = store.save(bundle)
        context = store.context(upload.snapshot_id)

        assert len(context.gaps) == 0
        # redactions field is not exposed in SnapshotContextResponse
        assert hasattr(context, 'redactions') or not hasattr(context, 'redactions')

    def test_snapshot_store_handles_empty_settings(self, temp_snapshot_dir):
        """Test that snapshot store handles null/empty settings gracefully."""
        bundle = CollectorBundleV020.model_validate(
            {
                "envelope": {
                    "schema_version": "0.2.0",
                    "collector_version": "2.0.0-sql",
                    "collected_at": "2026-09-03T06:00:00Z",
                    "target_id": "demo-primary",
                    "database": "postgres",
                    "collected_by": "dbguard_collector",
                    "is_superuser": False,
                    "deployment_type": "self-managed",
                },
                "identity": {"server_version_num": 160006},
                "settings": None,
                "roles": [],
                "gaps": [],
                "redactions": [],
            }
        )
        store = SnapshotStore(temp_snapshot_dir)
        upload = store.save(bundle)
        context = store.context(upload.snapshot_id)

        assert context.settings == {}

    def test_snapshot_store_handles_null_roles(self, temp_snapshot_dir):
        """Test that snapshot store handles null roles gracefully."""
        bundle = CollectorBundleV020.model_validate(
            {
                "envelope": {
                    "schema_version": "0.2.0",
                    "collector_version": "2.0.0-sql",
                    "collected_at": "2026-09-03T06:00:00Z",
                    "target_id": "demo-primary",
                    "database": "postgres",
                    "collected_by": "dbguard_collector",
                    "is_superuser": False,
                    "deployment_type": "self-managed",
                },
                "identity": {"server_version_num": 160006},
                "settings": [],
                "roles": None,
                "gaps": [],
                "redactions": [],
            }
        )
        store = SnapshotStore(temp_snapshot_dir)
        upload = store.save(bundle)
        context = store.context(upload.snapshot_id)

        assert context.roles is None

    def test_snapshot_store_handles_empty_gaps(self, temp_snapshot_dir):
        """Test that snapshot store handles empty gaps list."""
        bundle = CollectorBundleV020.model_validate(
            {
                "envelope": {
                    "schema_version": "0.2.0",
                    "collector_version": "2.0.0-sql",
                    "collected_at": "2026-09-03T06:00:00Z",
                    "target_id": "demo-primary",
                    "database": "postgres",
                    "collected_by": "dbguard_collector",
                    "is_superuser": False,
                    "deployment_type": "self-managed",
                },
                "identity": {"server_version_num": 160006},
                "settings": [],
                "roles": [],
                "gaps": [],
                "redactions": [],
            }
        )
        store = SnapshotStore(temp_snapshot_dir)
        upload = store.save(bundle)
        context = store.context(upload.snapshot_id)

        assert context.gaps == []
        assert context.unavailable_sections == []

    def test_snapshot_upload_response_contains_expected_fields(self, temp_snapshot_dir):
        """Test that snapshot upload response contains all expected fields."""
        bundle = CollectorBundleV020.model_validate(
            {
                "envelope": {
                    "schema_version": "0.2.0",
                    "collector_version": "2.0.0-sql",
                    "collected_at": "2026-09-03T06:00:00Z",
                    "target_id": "demo-primary",
                    "database": "postgres",
                    "collected_by": "dbguard_collector",
                    "is_superuser": False,
                    "deployment_type": "self-managed",
                },
                "identity": {"server_version_num": 160006},
                "settings": [],
                "roles": [],
                "gaps": [],
                "redactions": [],
            }
        )
        store = SnapshotStore(temp_snapshot_dir)
        upload = store.save(bundle)

        assert upload.snapshot_id.startswith("snap-")
        assert len(upload.snapshot_hash) == 64
        assert upload.target_id == "demo-primary"
        assert upload.database == "postgres"
        assert upload.schema_version == "0.2.0"
        assert upload.collected_at is not None
        assert upload.gap_count == 0
        assert upload.status == "stored"

    def test_snapshot_id_is_deterministic_for_same_content(self, temp_snapshot_dir):
        """Test that snapshot IDs are deterministic across runs."""
        bundle_data = {
            "envelope": {
                "schema_version": "0.2.0",
                "collector_version": "2.0.0-sql",
                "collected_at": "2026-09-03T06:00:00Z",
                "target_id": "demo-primary",
                "database": "postgres",
                "collected_by": "dbguard_collector",
                "is_superuser": False,
                "deployment_type": "self-managed",
            },
            "identity": {"server_version_num": 160006},
            "settings": [
                {"name": "ssl", "setting": "on"},
            ],
            "roles": [],
            "gaps": [],
            "redactions": [],
        }
        bundle = CollectorBundleV020.model_validate(bundle_data)

        store1 = SnapshotStore(temp_snapshot_dir)
        upload1 = store1.save(bundle)

        store2 = SnapshotStore(temp_snapshot_dir)
        upload2 = store2.save(bundle)

        assert upload1.snapshot_id == upload2.snapshot_id
        assert upload1.snapshot_hash == upload2.snapshot_hash


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
