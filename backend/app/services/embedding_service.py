"""Single embedding-provider adapter shared by template and document RAG."""

from openai import OpenAI
import requests

from app.config import settings


def _is_real_key(key: str) -> bool:
    if not key:
        return False
    fake_keys = {
        "***",
        "*",
        "your-api-key-here",
        "your-openai-api-key-here",
        "redacted",
        "sk-your-****here",
        "sk-...",
    }
    if key in fake_keys:
        return False
    if key.startswith("sk-"):
        return len(key) > 20 and "*" not in key and "placeholder" not in key.lower()
    return True


def generate_embedding(
    text: str,
    model: str | None = None,
    dimension: int | None = None,
) -> list[float]:
    model = model or settings.embedding_model
    dimension = dimension or settings.embedding_dim
    use_ollama = _is_real_key(settings.ollama_api_key)
    use_openai = _is_real_key(settings.openai_api_key)

    if use_openai and not use_ollama:
        request = {"model": model, "input": text}
        if model.startswith("text-embedding-3-"):
            request["dimensions"] = dimension
        response = OpenAI(api_key=settings.openai_api_key).embeddings.create(**request)
        vector = list(response.data[0].embedding)
    else:
        base = (settings.ollama_api_url or settings.ollama_api_base or "http://localhost:11434").rstrip("/")
        if "ollama.com/api" in base and "api.ollama.com" not in base:
            base = "https://api.ollama.com"
        elif base == "https://api.ollama.com/v1":
            base = "https://api.ollama.com"

        headers = {"Content-Type": "application/json"}
        if settings.ollama_api_key:
            headers["Authorization"] = f"Bearer {settings.ollama_api_key}"
        response = requests.post(
            f"{base}/api/embed",
            json={"model": model, "input": text},
            headers=headers,
            timeout=30,
        )
        if response.status_code != 200:
            raise RuntimeError(f"Embedding failed: {response.status_code} {response.text}")
        vector = list(response.json()["embeddings"][0])

    if len(vector) != dimension:
        raise ValueError(
            f"Embedding model returned {len(vector)} dimensions; database expects "
            f"{dimension}. Configure a matching model."
        )
    return vector
