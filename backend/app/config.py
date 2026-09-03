"""Application settings — loaded from environment variables."""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    app_name: str = "DBGuardAI"
    app_env: str = "development"

    # Database
    database_url: str = Field(default="postgresql://admin:securepassword123@localhost:5432/dbguard_rag")

    # Embedding
    embedding_model: str = "text-embedding-3-small"
    embedding_dim: int = 1536

    # LLM
    llm_model: str = "gpt-4o-mini"
    openai_api_key: str = ""
    ollama_api_key: str = ""
    ollama_api_base: str = "https://api.ollama.com/v1"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()
