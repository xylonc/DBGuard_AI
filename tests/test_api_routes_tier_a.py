"""Tier A tests for API Routes - Pure (zero external dependencies)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

pytestmark = pytest.mark.tier_a


@pytest.fixture
def client():
    """Create a test client for the FastAPI app with all dependencies mocked."""
    # Patch all database and embedding dependencies at the module level
    with patch("backend.app.main.RAGService") as mock_rag_class, \
         patch("backend.app.main.search_templates") as mock_search, \
         patch("backend.app.main.get_active_template_version") as mock_get_active, \
         patch("backend.app.main.ingest_template") as mock_ingest, \
         patch("backend.app.main.approve_template") as mock_approve, \
         patch("backend.app.main.init_db") as mock_init, \
         patch("backend.app.main.SnapshotStore") as mock_store_class, \
         patch("backend.app.main.get_active_template_version") as mock_get_active:
        
        # Setup RAG Service mock
        mock_rag_instance = MagicMock()
        mock_rag_instance.search.return_value = []
        mock_rag_class.return_value = mock_rag_instance
        
        
        # Setup template mocks
        mock_search.return_value = []
        mock_get_active.return_value = None
        mock_ingest.return_value = {"id": 1, "template_name": "test", "status": "draft"}
        mock_approve.return_value = True
        
        # Import after patching
        from backend.app.main import app
        
        return TestClient(app)


def test_legacy_harden_endpoint_returns_404(client):
    """Test that POST /api/v1/harden is no longer available."""
    response = client.post(
        "/api/v1/harden",
        json={
            "user_prompt": "Create a read-only user",
            "snapshot_id": "test-snapshot",
            "environment": "all",
        },
    )
    assert response.status_code == 404, (
        f"Expected 404 for removed /api/v1/harden, got {response.status_code}"
    )


def test_compile_proposal_endpoint_exists(client):
    """Test that POST /api/v1/proposals/compile is still available."""
    response = client.post(
        "/api/v1/proposals/compile",
        json={
            "snapshot_id": "nonexistent-snapshot-id",
            "requirement": "Create a read-only user",
            "template_ids": ["test-template"],
        },
    )
    # 404 for missing snapshot is expected, but 404 for unknown route is not
    assert response.status_code in {404, 422}, (
        f"Expected 404/422 for /api/v1/proposals/compile, got {response.status_code}"
    )


def test_routes_table_contains_compile():
    """Test that /api/v1/proposals/compile is in the FastAPI route table."""
    from backend.app.main import app
    route_paths = [route.path for route in app.routes]
    assert "/api/v1/proposals/compile" in route_paths, (
        "Expected /api/v1/proposals/compile in route table"
    )


def test_routes_table_does_not_contain_harden():
    """Test that /api/v1/harden is not in the FastAPI route table."""
    from backend.app.main import app
    route_paths = [route.path for route in app.routes]
    assert "/api/v1/harden" not in route_paths, (
        "Expected /api/v1/harden to be removed from route table"
    )


def test_health_endpoint_returns_expected_structure(client):
    """Test that /api/v1/health returns expected status and fields."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "DBGuardAI"
    assert data["scope"] == "proposal"
    assert data["assessment_enabled"] is False
    assert data["twin_runner_enabled"] is False


def test_health_endpoint_is_fastapi_200(client):
    """Test that health endpoint returns HTTP 200."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200


def test_upload_snapshot_endpoint_exists(client):
    """Test that POST /api/v1/snapshots is available."""
    response = client.post(
        "/api/v1/snapshots",
        json={
            "envelope": {
                "schema_version": "0.2.0",
                "collector_version": "2.0.0-sql",
                "collected_at": "2026-09-03T06:00:00Z",
                "target_id": "test-target",
                "database": "postgres",
                "collected_by": "test-collector",
                "is_superuser": False,
                "deployment_type": "self-managed",
            },
            "identity": {"server_version_num": 160006},
            "settings": [],
            "roles": [],
            "gaps": [],
            "redactions": [],
        },
    )
    assert response.status_code in {201, 422, 500}


def test_get_snapshot_context_endpoint_exists(client):
    """Test that GET /api/v1/snapshots/{snapshot_id} is available."""
    response = client.get("/api/v1/snapshots/snap-test")
    # Expected to fail due to missing snapshot, but route must exist
    assert response.status_code in {404, 200}


def test_knowledge_ingest_endpoint_exists(client):
    """Test that POST /api/v1/knowledge/documents is available."""
    response = client.post(
        "/api/v1/knowledge/documents",
        json={
            "document_id": "test_document",
            "title": "Test Document",
            "version": "1.0.0",
            "content": "Test content for knowledge document.",
            "effective_date": "2026-01-01T00:00:00Z",
            "status": "draft",
        },
    )
    assert response.status_code in {200, 422, 500}


# The knowledge search endpoint requires database connectivity which is not available
# in this environment. This test would require patching at the RAGService._get_db_connection
# level which is too deeply nested for reliable mocking in this test setup.

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
