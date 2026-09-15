"""Application settings — loaded from environment variables."""

from pydantic_settings import BaseSettings
from pydantic import Field
import os


class Settings(BaseSettings):
    app_name: str = "DBGuardAI"
    app_env: str = "development"

    # Database
    database_url: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", "postgresql://dbguard:dbguard@localhost:5432/dbguard"))
    snapshot_storage_dir: str = "./data/snapshots"

    # Embedding
    embedding_model: str = "nomic-embed-text"
    embedding_dim: int = 768

    # LLM
    llm_model: str = "llama3.1"
    openai_api_key: str = ""
    # Ollama
    ollama_api_key: str = ""
    ollama_api_base: str = "http://localhost:11434"
    ollama_api_url: str = "http://localhost:11434"

    model_config = {"env_file_encoding": "utf-8", "extra": "ignore"}


# Load .env from project root (one level up from this file)
_settings_path = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(os.path.dirname(_settings_path))
_settings_model = Settings(_env_file=os.path.join(_project_root, ".env"))
settings = _settings_model
