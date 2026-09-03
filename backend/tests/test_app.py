"""Minimal FastAPI app for testing endpoint routing.

Originally tested only the runs router. Now includes all routers
so we can also test route registration for the template endpoints
without importing the heavy services.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI
from app.runs_endpoint import router as runs_router
from app.templates_endpoint import router as templates_router

app = FastAPI(title="DBGuardAI")
app.include_router(runs_router)
app.include_router(templates_router)
