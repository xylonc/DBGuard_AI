#!/usr/bin/env python3
"""
Comprehensive RAG Data Export

Exports ALL data from the RAG database:
- Knowledge documents & chunks (from XLSX uploads)
- Templates (remediation templates)
- Snapshot data (if any)

Usage:
    python export_all.py [db_url] [output_dir]
"""

import json
import sys
from pathlib import Path
from datetime import datetime

import psycopg2
import psycopg2.extras


def export_all(db_url: str, output_dir: str):
    """Export all RAG data to JSON files."""
    conn = psycopg2.connect(db_url)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    result = {}
    
    # ── 1. Export Knowledge Documents ───────────────────────────────────
    print("Exporting knowledge documents...")
    cur.execute("""
        SELECT 
            document_id, title, version, status,
            effective_date, expiry_date,
            postgresql_versions, environment_applicability,
            policy_owner, classification, source_url, superseded_by,
            document_hash, approved_by, approved_at,
            created_at, updated_at
        FROM knowledge_documents
        ORDER BY created_at DESC
    """)
    documents = [dict(r) for r in cur.fetchall()]
    with open(output_path / "documents.json", "w") as f:
        json.dump(documents, f, indent=2, default=str)
    result["documents"] = len(documents)
    print(f"  - {len(documents)} documents")
    
    # ── 2. Export Knowledge Chunks ─────────────────────────────────────
    print("Exporting knowledge chunks...")
    cur.execute("""
        SELECT 
            id as chunk_id, document_id, section, content, chunk_hash,
            chunk_index, postgresql_versions, environment_applicability,
            source_document_title, source_document_version, created_at
        FROM knowledge_chunks
        ORDER BY document_id, chunk_index
    """)
    chunks = [dict(r) for r in cur.fetchall()]
    with open(output_path / "chunks.json", "w") as f:
        json.dump(chunks, f, indent=2, default=str)
    result["chunks"] = len(chunks)
    print(f"  - {len(chunks)} chunks")
    
    # ── 3. Export Templates ───────────────────────────────────────────
    print("Exporting templates...")
    cur.execute("""
        SELECT 
            id, template_id, title, version, status,
            content, tags, postgresql_versions, environment_applicability,
            classification, source_url, policy_owner,
            approved_by, approved_at, effective_date, expiry_date,
            created_at, updated_at
        FROM templates
        ORDER BY created_at DESC
    """)
    templates = [dict(r) for r in cur.fetchall()]
    with open(output_path / "templates.json", "w") as f:
        json.dump(templates, f, indent=2, default=str)
    result["templates"] = len(templates)
    print(f"  - {len(templates)} templates")
    
    # ── 4. Export Snapshot Records ───────────────────────────────────
    print("Exporting snapshots...")
    cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = 'snapshots'")
    table_exists = cur.fetchone()[0] > 0 if cur.fetchone else False
    
    cur.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name LIKE '%snapshot%'
    """)
    snapshot_tables = [r[0] for r in cur.fetchall()]
    
    result["snapshot_tables"] = snapshot_tables
    
    for table in snapshot_tables:
        print(f"  - Exporting {table}...")
        cur.execute(f"SELECT * FROM {table} ORDER BY created_at DESC LIMIT 1000")
        rows = [dict(r) for r in cur.fetchall()]
        with open(output_path / f"snapshot_{table}.json", "w") as f:
            json.dump(rows, f, indent=2, default=str)
        print(f"    - {len(rows)} records")
    
    # ── 5. Export Assessment Catalog ──────────────────────────────────
    print("Exporting assessment catalog...")
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name LIKE '%assessment%'")
    assessment_tables = [r[0] for r in cur.fetchall()]
    
    result["assessment_tables"] = assessment_tables
    
    for table in assessment_tables:
        cur.execute(f"SELECT COUNT(*) FROM {table}")
        count = cur.fetchone()[0]
        print(f"  - {table}: {count} records")
    
    # ── 6. Export Template Ingestion Status ──────────────────────────
    print("Exporting template ingestion status...")
    cur.execute("""
        SELECT 
            template_id, version, status, 
            chunks_created, ingestion_timestamp
        FROM template_ingestion_status
        ORDER BY ingestion_timestamp DESC
    """)
    ingestion_status = [dict(r) for r in cur.fetchall()]
    with open(output_path / "template_ingestion_status.json", "w") as f:
        json.dump(ingestion_status, f, indent=2, default=str)
    result["ingestion_status"] = len(ingestion_status)
    print(f"  - {len(ingestion_status)} records")
    
    cur.close()
    conn.close()
    
    # ── Summary ───────────────────────────────────────────────────────
    summary = {
        "export_timestamp": datetime.utcnow().isoformat(),
        "database_url": db_url,
        "data": result
    }
    
    with open(output_path / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    
    print("\n=== Export Summary ===")
    print(f"Documents: {result['documents']}")
    print(f"Chunks: {result['chunks']}")
    print(f"Templates: {result['templates']}")
    print(f"Ingestion Status: {result.get('ingestion_status', 0)}")
    print(f"\nExported to: {output_path}")
    
    return summary


if __name__ == "__main__":
    db_url = sys.argv[1] if len(sys.argv) > 1 else "postgresql://dbguard:***@localhost:5433/dbguard"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "export"
    
    export_all(db_url, output_dir)
