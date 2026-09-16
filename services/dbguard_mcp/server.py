"""Expose the proposal-phase DBGuard API as four narrowly scoped MCP tools."""

import os
from typing import Any
import requests
from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse

DBGUARD_API_URL = os.getenv("DBGUARD_API_URL", "http://api:8000").rstrip("/")
REQUEST_TIMEOUT_SECONDS = float(os.getenv("DBGUARD_MCP_TIMEOUT_SECONDS", "60"))

mcp = MCPServer(
    "DBGuardAI",
    instructions=(
        "Use these tools only to create review-only PostgreSQL hardening "
        "proposals. Never claim SQL was executed or approved."
    ),
)


def _request_json(method: str, path: str, **kwargs: Any) -> Any:
    try:
        response = requests.request(
            method,
            f"{DBGUARD_API_URL}{path}",
            timeout=REQUEST_TIMEOUT_SECONDS,
            **kwargs,
        )
    except requests.RequestException as exc:
        raise RuntimeError("DBGuard API is unavailable") from exc

    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", "Request rejected")
        except ValueError:
            detail = "Request rejected"
        raise RuntimeError(f"DBGuard API rejected the request: {detail}")
    return response.json()


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
        host="0.0.0.0",
        port=int(os.getenv("DBGUARD_MCP_PORT", "8001")),
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
    )
