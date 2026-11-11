"""The demo API answers approved knowledge/template search with an honest empty result.

The disposable demo has no approved knowledge library or template registry, and
HERMES is told to pass backend=demo. Before this, both searches were HTTP 404 and
HERMES reported a failed search. They must now say "no approved guidance", return
no results (never fixture references) and never echo the query.
"""
from fastapi.testclient import TestClient

from services.sandbox_poc.demo import create_app
from test_demo_ui import Resources
from test_review_bundle import recorded  # noqa: F401  (pytest fixture)
from test_sandbox_poc import engine, snapshot  # noqa: F401  (pytest fixtures)

QUERY = "maximum log file size <script>alert(1)</script>"


def _client(recorded, engine):
    return TestClient(create_app(lambda: Resources(recorded, engine)))


def test_knowledge_search_says_no_approved_guidance(recorded, engine):
    with _client(recorded, engine) as client:
        response = client.get("/api/v1/knowledge/search", params={
            "search_query": QUERY, "environment": "all", "top_k": 5})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok" and body["results"] == []
    assert body["message"].startswith("No approved guidance in this demo")
    assert "alert" not in response.text  # the query is not echoed


def test_template_search_returns_no_templates_and_no_fixture_refs(recorded, engine):
    resources = Resources(recorded, engine)
    with TestClient(create_app(lambda: resources)) as client:
        response = client.get("/api/v1/templates/search", params={"search_query": QUERY, "top_k": 5})
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok" and body["results"] == []
    assert "DEMO_FIXTURE_ONLY" in body["message"]
    ref = resources.handoff.template_ref
    assert body.keys() == {"status", "results", "message"}  # no version or template fields
    for evidence in ref.evidence:  # fixture evidence never leaks through search
        assert evidence.document_id not in response.text
    assert "alert" not in response.text


def test_searches_still_require_a_query(recorded, engine):
    with _client(recorded, engine) as client:
        for path in ("/api/v1/knowledge/search", "/api/v1/templates/search"):
            assert client.get(path).status_code == 422
            assert client.get(path, params={"search_query": ""}).status_code == 422


def test_searches_keep_the_demo_host_guard(recorded, engine):
    with _client(recorded, engine) as client:
        for path in ("/api/v1/knowledge/search", "/api/v1/templates/search"):
            response = client.get(path, params={"search_query": "x"},
                                  headers={"Host": "external.example"})
            assert response.status_code == 400
