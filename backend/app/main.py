from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any
from app.services.ai_service import generate_hardening_plan
from app.services.template_service import compile_sql_plan

app = FastAPI()

class HardenRequest(BaseModel):
    user_prompt: str
    metadata_snapshot: Dict[str, Any]

@app.get("/")
def read_root():
    return {"status": "healthy", "service": "DBGuardAI API"}

@app.post("/api/v1/harden")
def create_hardening_plan(request: HardenRequest):
    ai_decision = generate_hardening_plan(
        user_prompt=request.user_prompt,
        metadata=request.metadata_snapshot
    )

    full_sql_plan = compile_sql_plan(
        template_ids=ai_decision.get("template_ids", []),
        variables=ai_decision.get("parameters", {})
    )

    return {
        "status": "Plan generated successfully",
        "target_db": request.metadata_snapshot.get("engine", "postgresql"),
        "ai_plan": full_sql_plan
    }