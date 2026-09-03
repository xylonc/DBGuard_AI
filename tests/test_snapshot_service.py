import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from app.collector_models import CollectorBundleV020
from app.services.snapshot_service import SnapshotNotFoundError, SnapshotStore


def collector_bundle() -> dict:
    return {
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
        "hba_rules": None,
        "gaps": [
            {
                "section": "hba_rules",
                "reason": "insufficient_privilege",
                "remediation": "Grant explicit read access.",
            }
        ],
        "redactions": [{"field": "pg_authid.rolpassword", "class": "S0"}],
    }


class SnapshotStoreTests(unittest.TestCase):
    def test_round_trip_is_content_addressed_and_preserves_gap(self):
        bundle = CollectorBundleV020.model_validate(collector_bundle())
        with tempfile.TemporaryDirectory() as directory:
            store = SnapshotStore(directory)
            first = store.save(bundle)
            second = store.save(bundle)
            context = store.context(first.snapshot_id)

            self.assertEqual(first.snapshot_id, second.snapshot_id)
            self.assertEqual(context.postgresql_version, "16")
            self.assertEqual(context.settings["ssl"], "on")
            self.assertIn("hba_rules", context.unavailable_sections)
            self.assertNotIn("hba_rules", context.available_sections)
            self.assertEqual(len(list(Path(directory).glob("*.json"))), 1)

    def test_rejects_unsupported_collector_schema(self):
        payload = collector_bundle()
        payload["envelope"]["schema_version"] = "0.1.0"
        with self.assertRaises(ValidationError):
            CollectorBundleV020.model_validate(payload)

    def test_rejects_path_like_snapshot_identifier(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SnapshotNotFoundError):
                SnapshotStore(directory).load("../secret")


if __name__ == "__main__":
    unittest.main()
