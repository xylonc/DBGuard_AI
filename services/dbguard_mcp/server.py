"""Restricted proposal and local sandbox operations for HERMES."""

import os
from typing import Any
from urllib.parse import quote
import requests
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse

DBGUARD_API_URL = os.getenv("DBGUARD_API_URL", "http://api:8000").rstrip("/")
REQUEST_TIMEOUT_SECONDS = float(os.getenv("DBGUARD_MCP_TIMEOUT_SECONDS", "60"))
SANDBOX_TIMEOUT_SECONDS = float(os.getenv("DBGUARD_MCP_SANDBOX_TIMEOUT_SECONDS", "600"))

MCP_PORT = int(os.getenv("DBGUARD_MCP_PORT", "8001"))
TRANSPORT_SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*", f"mcp:{MCP_PORT}"],
    allowed_origins=["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
)

mcp = MCPServer(
    "DBGuardAI",
    instructions=(
        "Use the proposal tools for review-only plans. Use sandbox handoff tools "
        "only for disposable PostgreSQL tests. Report execution and acceptance "
        "only from returned evidence. Never claim the real target was changed."
    ),
)


def _request_json(method: str, path: str, *, timeout=REQUEST_TIMEOUT_SECONDS, **kwargs: Any) -> Any:
    try:
        response = requests.request(
            method,
            f"{DBGUARD_API_URL}{path}",
            timeout=timeout,
            **kwargs,
        )
    except requests.RequestException as exc:
        raise ToolError("DBGuard API is unavailable; no successful result was returned") from exc

    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", "Request rejected")
        except ValueError:
            detail = "Request rejected"
        raise ToolError(f"DBGuard API rejected the request (HTTP {response.status_code}): {detail}. No successful result was returned.")
    return response.json()


@mcp.tool()
def get_demo_workflow_context() -> dict[str, Any]:
    """Discover the connected local demo's snapshot and fixture references.

    Only for an explicit demo request. References are DEMO_FIXTURE_ONLY, never
    human approval or RAG results. Use them with the existing assessment,
    prepare/run/status tools and use ui_url as the bundle link's public base.
    A 404 means this backend is not a demo; do not substitute fixture approvals.
    """
    return _request_json('GET', '/api/v1/demo/workflow')


@mcp.tool()
def get_snapshot_spec_assessment(snapshot_id: str, benchmark_id: str = 'cis-pg17-v1.1.0') -> dict[str, Any]:
    """Get the exact pinned specs and their assessment for the local sandbox.

    This scope differs from the legacy assessment. Use these findings when
    preparing a sandbox handoff; do not translate legacy control IDs yourself.
    """
    return _request_json('GET', f'/api/v1/snapshots/{quote(snapshot_id, safe="")}/spec-assessment',
                         params={'benchmark_id': benchmark_id})


@mcp.tool()
def prepare_sandbox_handoff(snapshot_id: str, template_version: int,
                             evidence_ids: list[str], environment: str,
                             benchmark_id: str = 'cis-pg17-v1.1.0',
                             retry_template_versions: list[int] | None = None) -> dict[str, Any]:
    """Pin existing approved references to an uploaded snapshot, using exact specs.

    Always pass environment explicitly from discovery/search results; never guess
    or substitute dev for test. Select version/IDs from approved search results
    (or explicit demo discovery). No SQL or approvals are
    accepted from the agent. Adaptive testing is enabled for this handoff.
    """
    return _request_json('POST', '/api/v1/sandbox/handoffs', json={
        'snapshot_id': snapshot_id, 'template_version': template_version,
        'evidence_ids': evidence_ids, 'environment': environment, 'benchmark_id': benchmark_id,
        'retry_mode': 'adaptive', 'retry_template_versions': retry_template_versions or []})


@mcp.tool()
def run_sandbox_handoff(handoff_id: str) -> dict[str, Any]:
    """Run up to three isolated attempts with LLM failure review and exact rollback.

    Reusing this handle returns its saved result; it does not restart testing.
    On a timeout, inspect this handle's status before taking another action.
    Returned bundle URLs are relative to the user-facing DBGuard API host.
    """
    return _request_json('POST', f'/api/v1/sandbox/handoffs/{quote(handoff_id, safe="")}/run',
                         timeout=SANDBOX_TIMEOUT_SECONDS)


@mcp.tool()
def get_sandbox_handoff_status(handoff_id: str) -> dict[str, Any]:
    """Retrieve pending/completed testing status and the bundle link, if available."""
    return _request_json('GET', f'/api/v1/sandbox/handoffs/{quote(handoff_id, safe="")}')


@mcp.tool()
def get_snapshot_context(snapshot_id: str) -> dict[str, Any]:
    """Read normalized, redacted context for an uploaded collector snapshot."""
    return _request_json("GET", f"/api/v1/snapshots/{snapshot_id}")


@mcp.tool()
def get_snapshot_assessment(snapshot_id: str) -> dict[str, Any]:
    """Evaluate a snapshot against control rules and return findings.
    
    This tool retrieves the assessment report for a snapshot, including:
    - findings: pass/fail/gap status for each control
    - summary: counts by status
    - rationale and evidence for each finding
    
    Use this to understand the current security state before proposing fixes.
    """
    return _request_json("GET", f"/api/v1/snapshots/{snapshot_id}/assessment")


@mcp.tool()
def search_approved_knowledge(
    query: str,
    pg_version: str | None = None,
    environment: str = "all",
    top_k: int = 5,
) -> dict[str, Any]:
    """Search only active, effective and applicable hardening guidance."""
    return _request_json(
        "GET",
        "/api/v1/knowledge/search",
        params={
            "search_query": query,
            "pg_version": pg_version,
            "environment": environment,
            "top_k": max(1, min(top_k, 20)),
        },
    )


@mcp.tool()
def search_approved_templates(query: str, top_k: int = 5) -> dict[str, Any]:
    """Search human-approved SQL templates by semantic similarity."""
    return _request_json(
        "GET",
        "/api/v1/templates/search",
        params={"search_query": query, "top_k": max(1, min(top_k, 20))},
    )


@mcp.tool()
def validate_and_render_proposal(
    snapshot_id: str,
    proposal: dict[str, Any],
    environment: str = "all",
) -> dict[str, Any]:
    """Validate a template-driven proposal and render SQL.
    
    The agent submits:
    1. template_id: approved template ID from search_approved_templates
    2. parameters: template parameters matching the template schema
    3. reasoning: agent reasoning for why this template applies
    4. evidence_refs: list of approved RAG document IDs
    
    The API validates and returns rendered SQL for human DBA review.
    No SQL is generated - only rendered from approved templates.
    
    Returns:
    - ai_plan: rendered SQL string
    - evidence: citations from approved knowledge
    - reasoning: agent's justification
    """
    return _request_json(
        "POST",
        "/api/v1/proposals/validate-and-render",
        json={
            "snapshot_id": snapshot_id,
            "proposal": proposal,
            "environment": environment,
        },
    )


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    """Container liveness endpoint; it does not expose DBGuard data."""
    return JSONResponse({"status": "ok", "service": "dbguard-mcp"})


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host=os.getenv("DBGUARD_MCP_HOST", "0.0.0.0"),
        port=MCP_PORT,
        transport_security=TRANSPORT_SECURITY,
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )
