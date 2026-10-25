"""Read-only, paged catalogue of exact registry versions, including drafts."""

from contextlib import closing
import psycopg2
from psycopg2.extras import RealDictCursor


def catalogue(database_url, kind, status=None, search="", offset=0, limit=50):
    # Identifiers are constants, never supplied by the caller.
    if kind == "templates":
        table, identity = "templates", "template_name"
        columns = "id,template_name,version,description,sql_template,template_hash,tags,risk_level,pg_version,status,approved_by,approved_at,created_at"
    elif kind == "knowledge":
        table, identity = "knowledge_documents", "document_id"
        columns = "document_id,title,version,status,document_hash,approved_by,approved_at,effective_date,expiry_date,postgresql_versions,environment_applicability,source_url,created_at"
    else:
        raise ValueError("Unknown catalogue")
    with closing(psycopg2.connect(database_url, connect_timeout=10)) as conn:
        conn.set_session(readonly=True)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SET LOCAL statement_timeout='10s'")
            where = f"(%s IS NULL OR status=%s) AND {identity} ILIKE %s"
            params = (status, status, "%" + search + "%")
            cur.execute(f"SELECT count(*) AS total FROM {table} WHERE {where}", params)
            total = cur.fetchone()["total"]
            cur.execute(
                f"SELECT {columns} FROM {table} WHERE {where} ORDER BY {identity},created_at DESC LIMIT %s OFFSET %s",
                (*params, limit, offset),
            )
            return {
                "items": [dict(row) for row in cur.fetchall()],
                "total": total,
                "offset": offset,
                "limit": limit,
            }


def document_content(database_url, document_id):
    with closing(psycopg2.connect(database_url, connect_timeout=10)) as conn:
        conn.set_session(readonly=True)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT section,content,chunk_index FROM knowledge_chunks WHERE document_id=%s ORDER BY chunk_index",
                (document_id,),
            )
            return [dict(row) for row in cur.fetchall()]
