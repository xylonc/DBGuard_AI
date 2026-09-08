"""Vector service — pgvector search and ingestion."""

import hashlib
import os

import psycopg2

from app.config import settings
from app.services.embedding_service import generate_embedding


def get_embedding(text: str) -> list[float]:
    return generate_embedding(text)


def init_db():
    """Run the init.sql migration to create tables and indexes."""
    script_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "db", "init.sql")
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


def compute_template_hash(sql_template: str) -> str:
    """Compute SHA-256 hash of template content for auditability."""
    return hashlib.sha256(sql_template.encode("utf-8")).hexdigest()


def ingest_template(
    template_name: str,
    description: str,
    sql_template: str,
    version: int = 1,
    tags: list[str] = None,
    risk_level: str = None,
    pg_version: str = None,
) -> dict:
    """Ingest a single template into the templates table with embedding.
    
    New templates are always created as 'draft' status. Approval must happen
    separately through the template approval flow.
    """
    tags = tags or []
    embedding = get_embedding(description)
    embedding_array = f"[{','.join(str(value) for value in embedding)}]"
    template_hash = compute_template_hash(sql_template)

    conn = psycopg2.connect(settings.database_url)
    try:
        cur = conn.cursor()
        # Insert or update - if template exists, increment version
        # New content always creates a new draft version
        cur.execute("""
            INSERT INTO templates
                (template_name, version, description, sql_template, template_hash,
                 tags, risk_level, pg_version, embedding, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (template_name, version) DO UPDATE SET
                description = EXCLUDED.description,
                sql_template = EXCLUDED.sql_template,
                template_hash = EXCLUDED.template_hash,
                tags = EXCLUDED.tags,
                risk_level = EXCLUDED.risk_level,
                pg_version = EXCLUDED.pg_version,
                embedding = EXCLUDED.embedding,
                updated_at = NOW()
            RETURNING id, template_name, version, status
        """, (
            template_name, version, description, sql_template, template_hash,
            tags, risk_level, pg_version, embedding_array, "draft",
        ))

        row = cur.fetchone()
        conn.commit()
        result = {
            "id": row[0],
            "template_name": row[1],
            "version": row[2],
            "status": row[3],
        }
        print(f"   ✅ {template_name} v{version} ingested (id={row[0]})")
        return result
    finally:
        conn.close()


def search_templates(query: str, top_k: int = 5) -> list[dict]:
    """Search templates by semantic similarity to the query.
    
    Returns only active templates with version info for exact identification.
    """
    query_embedding = get_embedding(query)
    embedding_array = f"[{','.join(str(value) for value in query_embedding)}]"

    conn = psycopg2.connect(settings.database_url)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, template_name, version, description, tags, risk_level,
                   pg_version,
                   1 - (embedding <=> %s::vector) AS similarity
            FROM templates
            WHERE status = 'active'
            ORDER BY embedding <=> %s::vector
            LIMIT %s
        """, (embedding_array, embedding_array, top_k))

        columns = [desc[0] for desc in cur.description]
        results = [dict(zip(columns, row)) for row in cur.fetchall()]
        return results
    finally:
        conn.close()


def approve_template(template_name: str, version: int, approved_by: str) -> bool:
    """Activate a human-reviewed SQL template version for proposal retrieval.
    
    Approval applies to the exact template_name + version combination.
    The sql_template and template_hash must match the stored values.
    """
    conn = psycopg2.connect(settings.database_url)
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE templates
            SET status = 'active', approved_by = %s,
                approved_at = NOW(), updated_at = NOW()
            WHERE template_name = %s AND version = %s AND status = 'draft'
        """, (approved_by, template_name, version))
        success = cur.rowcount == 1
        conn.commit()
        return success
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_active_template_version(template_name: str) -> dict | None:
    """Get the active version of a template by name.
    
    Returns None if no active version exists.
    """
    conn = psycopg2.connect(settings.database_url)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, template_name, version, description, sql_template, template_hash,
                   tags, risk_level, pg_version
            FROM templates
            WHERE template_name = %s AND status = 'active'
        """, (template_name,))
        row = cur.fetchone()
        if row:
            columns = ["id", "template_name", "version", "description", "sql_template",
                       "template_hash", "tags", "risk_level", "pg_version"]
            return dict(zip(columns, row))
        return None
    finally:
        conn.close()


def get_all_versions(template_name: str) -> list[dict]:
    """Get all versions of a template for a given name."""
    conn = psycopg2.connect(settings.database_url)
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT id, template_name, version, description, sql_template, template_hash,
                   tags, risk_level, pg_version, status, approved_by, approved_at
            FROM templates
            WHERE template_name = %s
            ORDER BY version DESC
        """, (template_name,))
        columns = ["id", "template_name", "version", "description", "sql_template",
                   "template_hash", "tags", "risk_level", "pg_version", "status",
                   "approved_by", "approved_at"]
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
    Each file becomes a new draft version.
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

        # Ingest as draft with default version 1
        # (If run again, will create version 2, etc.)
        result = ingest_template(
            template_name=template_name,
            description=description,
            sql_template=sql_template,
            version=1,  # Start with version 1 for each file
            tags=tags,
            risk_level=risk_level,
            pg_version=pg_version
        )

    print(f"\n📦 Ingested {len(template_files)} templates")
