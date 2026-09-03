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
def compile_hardening_proposal(
    snapshot_id: str,
    requirement: str,
    template_ids: list[str],
    parameters: dict[str, Any],
    environment: str = "all",
) -> dict[str, Any]:
    """Validate selected templates and render a review-only SQL proposal."""
    return _request_json(
        "POST",
        "/api/v1/proposals/compile",
        json={
            "snapshot_id": snapshot_id,
            "requirement": requirement,
            "template_ids": template_ids,
            "parameters": parameters,
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
