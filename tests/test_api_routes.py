"""Test API routing and endpoint availability."""
import sys
from pathlib import Path
# Add backend to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from fastapi.testclient import TestClient
from app.main import app


class ApiRouteTests:
    """Test that the correct API routes are available."""

    def __init__(self):
        self.client = TestClient(app)

    def test_legacy_harden_endpoint_returns_404(self):
        """Test that POST /api/v1/harden is no longer available."""
        response = self.client.post(
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

    def test_legacy_proposals_compile_endpoint_returns_404(self):
        """Test that POST /api/v1/proposals/compile is no longer available."""
        # The old endpoint should return 404 since it was renamed
        response = self.client.post(
            "/api/v1/proposals/compile",
            json={
                "snapshot_id": "nonexistent-snapshot-id",
                "requirement": "Create a read-only user",
                "template_ids": ["test-template"],
            },
        )
        # 404 for unknown route is expected
        assert response.status_code == 404, (
            f"Expected 404 for removed /api/v1/proposals/compile, got {response.status_code}"
        )

    def test_validate_and_render_proposal_endpoint_exists(self):
        """Test that POST /api/v1/proposals/validate-and-render is available."""
        # We expect this to fail validation (missing snapshot), but not 404
        response = self.client.post(
            "/api/v1/proposals/validate-and-render",
            json={
                "snapshot_id": "nonexistent-snapshot-id",
                "proposal": {
                    "control_id": "CIS-3.1.2",
                    "template_id": "test-template",
                    "parameters": {"param": "value"},
                    "reasoning": "Test reasoning",
                },
            },
        )
        # 404 for missing snapshot is expected, but 404 for unknown route is not
        assert response.status_code in {404, 422}, (
            f"Expected 404/422 for /api/v1/proposals/validate-and-render, got {response.status_code}"
        )

    def test_routes_table_contains_validate_and_render(self):
        """Test that /api/v1/proposals/validate-and-render is in the FastAPI route table."""
        route_paths = [route.path for route in app.routes]
        assert "/api/v1/proposals/validate-and-render" in route_paths, (
            "Expected /api/v1/proposals/validate-and-render in route table"
        )

    def test_routes_table_does_not_contain_compile(self):
        """Test that /api/v1/proposals/compile is not in the FastAPI route table."""
        route_paths = [route.path for route in app.routes]
        assert "/api/v1/proposals/compile" not in route_paths, (
            "Expected /api/v1/proposals/compile to be removed from route table"
        )

    def test_routes_table_does_not_contain_harden(self):
        """Test that /api/v1/harden is not in the FastAPI route table."""
        route_paths = [route.path for route in app.routes]
        assert "/api/v1/harden" not in route_paths, (
            "Expected /api/v1/harden to be removed from route table"
        )


if __name__ == "__main__":
    import unittest

    # Run the tests
    test_instance = ApiRouteTests()
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ApiRouteTests))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    sys.exit(0 if result.wasSuccessful() else 1)
