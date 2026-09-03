"""Application settings — loaded from environment variables."""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    app_name: str = "DBGuardAI"
    app_env: str = "development"

    # Database
    database_url: str = Field(default="postgresql://admin:securepassword123@localhost:5432/dbguard_rag")

    # Embedding
    embedding_model: str = "nomic-embed-text"
    embedding_dim: int = 768

    # LLM
    llm_model: str = "llama3.1"
    openai_api_key: str = ""
    # Ollama
    ollama_api_key: str = ""
    ollama_api_base: str = "https://api.ollama.com/v1"
    ollama_api_url: str = "https://api.ollama.com/v1"

    model_config = {"env_file_encoding": "utf-8"}


# Load .env from project root (one level up from this file)
import os
_settings_path = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(os.path.dirname(_settings_path))
_settings_model = Settings(_env_file=os.path.join(_project_root, ".env"))
settings = _settings_model
