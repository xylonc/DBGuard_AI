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
    version: int | None = None,  # None = auto-increment, otherwise explicit version
    tags: list[str] = None,
    risk_level: str = None,
    pg_version: str = None,
) -> dict:
    """Ingest a single template into the templates table with embedding.
    
    Templates are immutable: once stored, their content cannot be changed.
    - If the latest version for template_name has identical sql_template -> return it (no-op).
    - If it differs -> INSERT new version (max + 1) with status 'draft'.
    - Explicit version can be provided for first version of new template.
    
    Approval must happen separately through the template approval flow.
    """
    tags = tags or []
    embedding = get_embedding(description)
    embedding_array = f"[{','.join(str(value) for value in embedding)}]"
    template_hash = compute_template_hash(sql_template)

    conn = psycopg2.connect(settings.database_url)
    try:
        cur = conn.cursor()
        
        # Find the latest version for this template_name
        cur.execute("""
            SELECT id, version, sql_template, template_hash, status
            FROM templates
            WHERE template_name = %s
            ORDER BY version DESC
            LIMIT 1
        """, (template_name,))
        latest = cur.fetchone()
        
        if latest:
            latest_id, latest_version, latest_sql, latest_hash, latest_status = latest
            
            # If content hash matches, this is a no-op - return the existing row
            if latest_hash == template_hash:
                conn.commit()
                result = {
                    "id": latest_id,
                    "template_name": template_name,
                    "version": latest_version,
                    "status": latest_status,
                    "created": False,  # No new row created
                }
                print(f"   ⏭️  {template_name} v{latest_version} unchanged (hash match)")
                return result
            
            # Content differs -> create new version (latest + 1)
            new_version = latest_version + 1
        else:
            # No existing template -> create version 1
            new_version = version if version is not None else 1
        
        # INSERT new version (never UPDATE)
        cur.execute("""
            INSERT INTO templates
                (template_name, version, description, sql_template, template_hash,
                 tags, risk_level, pg_version, embedding, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, template_name, version, status
        """, (
            template_name, new_version, description, sql_template, template_hash,
            tags, risk_level, pg_version, embedding_array, "draft",
        ))

        row = cur.fetchone()
        conn.commit()
        result = {
            "id": row[0],
            "template_name": template_name,
            "version": row[2],
            "status": row[3],
            "created": True,  # New row was created
        }
        print(f"   ✅ {template_name} v{row[2]} ingested (id={row[0]})")
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
    """Approve one draft version and archive the previously active version, atomically.

    Approval applies to the exact template_name + version combination.
    If the requested version is not a draft, nothing is changed and False is returned.
    """
    conn = psycopg2.connect(settings.database_url)
    try:
        with conn:  # one transaction: commit on success, rollback on any exception
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM templates WHERE template_name = %s AND version = %s "
                    "AND status = 'draft' FOR UPDATE",
                    (template_name, version),
                )
                if cur.fetchone() is None:
                    return False
                # Archive first: the unique index is checked per statement.
                cur.execute(
                    "UPDATE templates SET status = 'archived', updated_at = NOW() "
                    "WHERE template_name = %s AND status = 'active'",
                    (template_name,),
                )
                cur.execute(
                    "UPDATE templates SET status = 'active', approved_by = %s, "
                    "approved_at = NOW(), updated_at = NOW() "
                    "WHERE template_name = %s AND version = %s",
                    (approved_by, template_name, version),
                )
                return True
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

        # Ingest as draft - version is auto-determined by ingest_template
        # (version 1 for new templates, or N+1 for changed content)
        result = ingest_template(
            template_name=template_name,
            description=description,
            sql_template=sql_template,
            tags=tags,
            risk_level=risk_level,
            pg_version=pg_version
        )

    print(f"\n📦 Ingested {len(template_files)} templates")
