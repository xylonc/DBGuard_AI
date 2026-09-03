"""FastAPI application assembly for DBGuardAI.

Endpoint definitions live in dedicated modules:
  - runs_endpoint.py   → /api/v1/runs
  - templates_endpoint.py → /api/v1/templates/*

Only the health check endpoint lives here directly.
"""

from fastapi import FastAPI
from app.runs_endpoint import router as runs_router
from app.templates_endpoint import router as templates_router

app = FastAPI(title="DBGuardAI")

# ── health ──────────────────────────────────────────────────────────────────


@app.get("/api/v1/health")
def health_check():
    return {"status": "healthy", "service": "DBGuardAI"}


# ── routers ─────────────────────────────────────────────────────────────────

app.include_router(runs_router)
app.include_router(templates_router)
