"""Run on the local Docker host: uvicorn services.sandbox_poc.api:app."""
from fastapi import FastAPI

from .router import router

app = FastAPI(title="DBGuard local sandbox API", version="0.1.0")
app.include_router(router)
