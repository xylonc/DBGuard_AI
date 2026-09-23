"""Pytest configuration and fixtures for DBGuardAI test suite."""
import os
import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

# Track if tier_b check has been performed (None=not checked, True=ok, False=failed)
_tier_b_check_result = None


@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    """Set up test environment variables."""
    os.environ["MSYS_NO_PATHCONV"] = "1"
    os.environ["DATABASE_URL"] = "postgresql://dbguard:***@127.0.0.1:5433/dbguard_test"
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


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    """Check tier_b infrastructure before running tier_b tests.
    
    Runs once per session: checks app DB and embedding endpoint using
    actual settings from app.config.settings.
    """
    global _tier_b_check_result
    
    # Only run for tier_b tests
    if item.get_closest_marker("tier_b") is None:
        return
    
    # If already checked and failed, fail this test
    if _tier_b_check_result is False:
        pytest.fail("tier_b: app DB or embedding endpoint unreachable", pytrace=False)
    
    # Skip if already successfully checked
    if _tier_b_check_result is True:
        return
    
    # First tier_b test - perform the check
    try:
        from app.config import settings
    except ImportError:
        # Try to import with correct path
        sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
        try:
            from app.config import settings
        except ImportError:
            _tier_b_check_result = False
            pytest.fail("tier_b: cannot import app.config.settings", pytrace=False)
    
    # Check app database from settings.database_url
    db_ready = False
    try:
        db_url = settings.database_url
        if "@" in db_url:
            host_port = db_url.split("@")[1].split("/")[0]
            if ":" in host_port:
                host, port = host_port.split(":")
                port = int(port)
            else:
                host = host_port
                port = 5432  # default PostgreSQL port
        else:
            _tier_b_check_result = False
            pytest.fail("tier_b: cannot parse database_url", pytrace=False)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            db_ready = True
    except Exception:
        pass
    
    # Check embedding endpoint from settings.ollama_api_url (used by embedding_service.py)
    embedding_ready = False
    try:
        ollama_url = (settings.ollama_api_url or settings.ollama_api_base or "http://localhost:11434").rstrip("/")
        if ollama_url.startswith("http://"):
            ollama_url = ollama_url[7:]
        elif ollama_url.startswith("https://"):
            ollama_url = ollama_url[8:]
        
        if ":" in ollama_url:
            host, port = ollama_url.split(":")
            port = int(port.split("/")[0])
        else:
            host = ollama_url.split("/")[0]
            port = 11434  # default Ollama port
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            embedding_ready = True
    except Exception:
        pass
    
    # Store result for subsequent tests
    _tier_b_check_result = db_ready and embedding_ready
    
    if not _tier_b_check_result:
        pytest.fail("tier_b: app DB or embedding endpoint unreachable", pytrace=False)
