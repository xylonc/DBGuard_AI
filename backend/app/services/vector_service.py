"""Vector service — pgvector search and ingestion."""

import os
import re
from typing import Optional

import psycopg2
import psycopg2.extras
from openai import OpenAI

from app.config import settings


def _is_real_key(key: str) -> bool:
    """Check if an API key looks real (not a placeholder)."""
    if not key:
        return False
    fake_keys = {"***", "*", "your-api-key-here", "your-openai-api-key-here", "redacted", "sk-your-****here", "sk-..."}
    if key in fake_keys:
        return False
    # OpenAI keys: sk- followed by at least 24 alphanumeric chars
    if key.startswith("sk-"):
        return len(key) > 20 and "*" not in key and "placeholder" not in key.lower()
    return True


def get_client():
    """Get an OpenAI-compatible client for embeddings.
    Priority: Ollama (if configured) > OpenAI (if configured)."""
    
    # Always prefer Ollama if we have a real key for it
    if _is_real_key(settings.ollama_api_key):
        base = settings.ollama_api_base or settings.ollama_api_url or "https://api.ollama.com/v1"
        base = base.rstrip("/")
        # Auto-correct: ollama.com/api should be api.ollama.com
        if "ollama.com/api" in base and "api.ollama.com" not in base:
            base = "https://api.ollama.com"
        return OpenAI(
            api_key=settings.ollama_api_key,
            base_url=base
        )
    
    # Fall back to OpenAI if we have a real key
    if _is_real_key(settings.openai_api_key):
        return OpenAI(api_key=settings.openai_api_key)
    
    raise ValueError(
        "No embedding provider configured. Set OPENAI_API_KEY or "
        "OLLAMA_API_KEY in your .env file."
    )


def get_embedding(text: str) -> list[float]:
    """Generate embedding vector using OpenAI or Ollama API directly."""
    import requests
    
    # Prefer Ollama if we have a real key, otherwise OpenAI
    use_ollama = _is_real_key(settings.ollama_api_key)
    use_openai = _is_real_key(settings.openai_api_key)
    
    if use_openai and not use_ollama:
        client = OpenAI(api_key=settings.openai_api_key)
        model = settings.embedding_model
        response = client.embeddings.create(model=model, input=text)
        embedding_vec = response.data[0].embedding
    else:
        # Use Ollama (local or cloud)
        ollama_base = settings.ollama_api_url or settings.ollama_api_base or "http://localhost:11434"
        ollama_base = ollama_base.rstrip("/")
        # Auto-correct: ollama.com/api should be api.ollama.com
        if "ollama.com/api" in ollama_base and "api.ollama.com" not in ollama_base:
            ollama_base = "https://api.ollama.com"
        elif ollama_base == "https://api.ollama.com/v1":
            ollama_base = "https://api.ollama.com"
        
        model = settings.embedding_model
        headers = {"Content-Type": "application/json"}
        if settings.ollama_api_key:
            headers["Authorization"] = f"Bearer {settings.ollama_api_key}"
        
        response = requests.post(f"{ollama_base}/api/embed", json={
            "model": model,
            "input": text
        }, headers=headers, timeout=30)
        if response.status_code != 200:
            print(f"Ollama embed error: {response.status_code} {response.text}")
            raise RuntimeError(f"Embedding failed: {response.text}")
        data = response.json()
        embedding_vec = data["embeddings"][0]
    
    # Pad or truncate to expected dimension if needed
    if len(embedding_vec) < settings.embedding_dim:
        embedding_vec += [0.0] * (settings.embedding_dim - len(embedding_vec))
    return embedding_vec[:settings.embedding_dim]


def init_db():
    """Run the init.sql migration to create tables and indexes."""
    script_path = os.path.join(os.path.dirname(__file__), "..", "..", "db", "init.sql")
    with open(script_path, "r") as f:
        sql = f.read()

    conn = psycopg2.connect(settings.database_url)
    try:
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()
        print(f"✅ Database initialized from {script_path}")
    finally:
        conn.close()


def ingest_template(
    template_name: str,
    description: str,
    sql_template: str,
    tags: list[str] = None,
    risk_level: str = None,
    pg_version: str = None
) -> dict:
    """Ingest a single template into the templates table with embedding."""
    tags = tags or []
    embedding = get_embedding(description)

    conn = psycopg2.connect(settings.database_url)
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO templates
                (template_name, description, sql_template, tags, risk_level, pg_version, embedding)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (template_name) DO UPDATE SET
                description = EXCLUDED.description,
                sql_template = EXCLUDED.sql_template,
                tags = EXCLUDED.tags,
                risk_level = EXCLUDED.risk_level,
                pg_version = EXCLUDED.pg_version,
                embedding = EXCLUDED.embedding,
                updated_at = NOW()
            RETURNING id, template_name
        """, (template_name, description, sql_template, tags, risk_level, pg_version, embedding))

        row = cur.fetchone()
        result = {"id": row[0], "template_name": row[1]}
        print(f"   ✅ {template_name} ingested (id={row[0]})")
        return result
    finally:
        conn.close()


def search_templates(query: str, top_k: int = 5) -> list[dict]:
    """Search templates by semantic similarity to the query."""
    query_embedding = get_embedding(query)

    conn = psycopg2.connect(settings.database_url)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, template_name, description, tags, risk_level,
                   pg_version,
                   1 - (embedding <=> %s::vector) AS similarity
            FROM templates
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """, (query_embedding, query_embedding, top_k))

        columns = [desc[0] for desc in cur.description]
        results = [dict(zip(columns, row)) for row in cur.fetchall()]
        return results
    finally:
        conn.close()


def _parse_template_comments(sql_template: str) -> str:
    """Extract meaningful description from -- comments in the template."""
    lines = sql_template.strip().split("\n")
    comment_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("--"):
            # Remove -- prefix and extra whitespace
            comment = stripped[2:].strip()
            if comment:
                comment_lines.append(comment)
    return " ".join(comment_lines)


def _auto_generate_tags(description: str) -> list[str]:
    """Generate tags from keywords in the description."""
    desc_lower = description.lower()
    tags = []
    
    if any(word in desc_lower for word in ["read-only", "select-only", "auditor", "auditing"]):
        tags.append("access-control")
        tags.append("read-only")
    if any(word in desc_lower for word in ["revoke", "deny"]):
        tags.append("access-control")
        tags.append("revoke")
    if any(word in desc_lower for word in ["schema", "public", "world"]):
        tags.append("schema-security")
    if any(word in desc_lower for word in ["role", "permission", "privilege"]):
        tags.append("identity")
    if not tags:
        tags.append("general")
    
    return tags


def ingest_all_templates(templates_dir: str = None):
    """
    Ingest all .sql.j2 files from the templates directory.
    Auto-generates metadata from template comments and content.
    """
    if templates_dir is None:
        templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")

    import glob
    template_files = glob.glob(os.path.join(templates_dir, "*.sql.j2"))

    if not template_files:
        print(f"⚠️ No .sql.j2 files found in {templates_dir}")
        return

    print(f"📥 Found {len(template_files)} template(s) to ingest\n")

    for file_path in template_files:
        filename = os.path.basename(file_path)
        template_name = filename.replace(".sql.j2", "")

        with open(file_path, "r") as f:
            sql_template = f.read()

        # Auto-generate description from template comments
        description = _parse_template_comments(sql_template)
        if not description:
            description = f"PostgreSQL hardening template: {template_name}"

        # Auto-generate tags
        tags = _auto_generate_tags(description)
        
        # Default values
        risk_level = "medium"
        pg_version = "12+"

        result = ingest_template(
            template_name=template_name,
            description=description,
            sql_template=sql_template,
            tags=tags,
            risk_level=risk_level,
            pg_version=pg_version
        )

    print(f"\n📦 Ingested {len(template_files)} templates")
