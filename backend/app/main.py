from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="DBGuard AI Backend",
    description="AI-Assisted Database Hardening Platform API",
    version="0.1.0"
)

# 2. Define a Pydantic model for incoming data
class HardeningRequest(BaseModel):
    user_prompt: str
    database_product: str = "PostgreSQL"

# 3. Create a health-check endpoint (GET request)
@app.get("/")
def health_check():
    return {
        "status": "online",
        "service": "DBGuard AI API"
    }

# 4. Create a mock hardening endpoint (POST request)
@app.post("/api/v1/harden")
def create_hardening_plan(request: HardeningRequest):
    # This is a mock response until we wire up LiteLLM and RAG
    return {
        "message": "Request received successfully!",
        "target_db": request.database_product,
        "received_prompt": request.user_prompt,
        "status": "Plan generation pending"
    }