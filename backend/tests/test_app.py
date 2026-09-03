"""Minimal FastAPI app for testing the runs endpoint.

This imports ONLY the runs_endpoint module and nothing else heavy.
The real main.py (with template/RAG endpoints) is not needed for
these tests since they only test POST /api/v1/runs.
"""

from fastapi import FastAPI
from app.runs_endpoint import router as runs_router

app = FastAPI(title="DBGuardAI")
app.include_router(runs_router)
