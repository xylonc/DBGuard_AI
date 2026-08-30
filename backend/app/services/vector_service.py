"""Vector service — pgvector search and ingestion."""

import os
import re
from typing import Optional

import psycopg2
import psycopg2.extras
from openai import OpenAI

from app.config import settings


def get_client():
    """Get an OpenAI client for embeddings."""
    return OpenAI(api_key=settings.openai_api_key)


def get_embedding(text: str) -> list[float]:
    """Generate embedding vector using OpenAI API."""
    client = get_client()
    response = client.embeddings.create(
        model=settings.embedding_model,
        input=text,
        dimensions=settings.embedding_dim
    )
    return response.data[0].embedding


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
