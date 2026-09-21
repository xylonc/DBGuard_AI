"""Demo transport boundaries and fixture lifecycle; no Docker required."""
import threading
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from services.sandbox_poc.demo import create_app


class Resources:
    def __init__(self):
        self.closed = False
        self.registry_url = "unused"
        self.run_id = "unit-demo"
        self.lock = threading.Lock()
        self.handoff = SimpleNamespace(model_dump=lambda: {"fixture": True})

    def start(self):
        pass

    def close(self):
        self.closed = True

    def source_evidence(self):
        return {"source_unchanged": True}


def test_demo_is_same_origin_and_owns_lifecycle():
    resources = Resources()
    with TestClient(create_app(lambda: resources)) as client:
        assert client.get("/").status_code == 200
        assert client.get("/demo/context").json()["fixture_approval"] is True
        assert client.get("/demo/source").json()["source_unchanged"] is True
        assert client.post("/api/v1/sandbox/runs", json={}, headers={"Origin": "https://external.example"}).status_code == 403
        assert client.get("/demo/context", headers={"Host": "external.example"}).status_code == 400
        # A second operation cannot recollect midway through a sandbox run.
        resources.lock.acquire()
        try:
            assert client.get("/demo/source").status_code == 409
        finally:
            resources.lock.release()
        assert "/api/v1/sandbox/runs" in client.get("/openapi.json").json()["paths"]
    assert resources.closed


def test_partial_startup_still_cleans_up():
    resources = Resources()
    def fail():
        raise RuntimeError("fixture startup failed")
    resources.start = fail
    with pytest.raises(RuntimeError, match="fixture startup failed"):
        with TestClient(create_app(lambda: resources)):
            pass
    assert resources.closed
