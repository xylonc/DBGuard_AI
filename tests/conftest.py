"""Pytest configuration and fixtures for DBGuardAI test suite."""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))


@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    """Set up test environment variables."""
    os.environ["MSYS_NO_PATHCONV"] = "1"
    os.environ["DATABASE_URL"] = "postgresql://dbguard:securepassword123@127.0.0.1:5433/dbguard_test"
    os.environ["EMBEDDING_MODEL"] = "nomic-embed-text"
    os.environ["EMBEDDING_DIM"] = "768"
    os.environ["OLLAMA_API_KEY"] = ""
    os.environ["OPENAI_API_KEY"] = ""
    yield


@pytest.fixture
def mock_embedding_provider():
    """Mock the embedding provider to return fixed vectors."""
    with patch("app.services.embedding_service.generate_embedding") as mock:
        mock.return_value = [0.1] * 768
        yield mock


@pytest.fixture
def mock_db_connection():
    """Mock database connection for Tier A tests."""
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    return mock_conn, mock_cursor


@pytest.fixture
def temp_snapshot_dir(tmp_path):
    """Temporary directory for snapshot storage tests."""
    return str(tmp_path / "snapshots")


@pytest.fixture
def test_collector_bundle():
    """Test collector bundle v0.2.0."""
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
        "gaps": [
            {
                "section": "hba_rules",
                "reason": "insufficient_privilege",
                "remediation": "Grant explicit read access.",
            }
        ],
        "redactions": [{"field": "pg_authid.rolpassword", "class": "S0"}],
    }
