#!/usr/bin/env python3
"""
Comprehensive RAG Data Import

Imports ALL data from JSON files:
- Knowledge documents & chunks
- Templates
- Snapshot data
- Template ingestion status

Usage:
    python import_all.py <export_dir> [db_url]
"""

import json
import sys
from pathlib import Path

import psycopg2
import psycopg2.extras


def get_or_insert_document(cur, doc_data: dict) -> str:
    """Insert or get existing document."""
    cur.execute(
        "SELECT document_id FROM knowledge_documents WHERE document_id = %s",
        (doc_data["document_id"],)
    )
    if cur.fetchone():
        return doc_data["document_id"]
    
    cur.execute("""
        INSERT INTO knowledge_documents (
            document_id, title, version, status,
            effective_date, expiry_date,
            postgresql_versions, environment_applicability,
            policy_owner, classification, source_url, superseded_by,
            document_hash, approved_by, approved_at,
            created_at, updated_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        doc_data["document_id"],
        doc_data["title"],
        doc_data["version"],
        doc_data["status"],
        doc_data.get("effective_date"),
        doc_data.get("expiry_date"),
        doc_data.get("postgresql_versions", []),
        doc_data.get("environment_applicability", []),
        doc_data.get("policy_owner", ""),
        doc_data.get("classification", "internal"),
        doc_data.get("source_url"),
        doc_data.get("superseded_by"),
        doc_data.get("document_hash"),
        doc_data.get("approved_by"),
        doc_data.get("approved_at"),
        doc_data.get("created_at"),
        doc_data.get("updated_at"),
    ))
    return doc_data["document_id"]


def import_all(export_dir: str, db_url: str):
    """Import all RAG data from JSON files."""
    export_path = Path(export_dir)
    
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute("BEGIN")
    
    total_docs = 0
    total_chunks = 0
    total_templates = 0
    
    # ── Import Documents ───────────────────────────────────────────────
    docs_file = export_path / "documents.json"
    if docs_file.exists():
        print("Importing documents...")
        with open(docs_file) as f:
            documents = json.load(f)
        
        for doc in documents:
            get_or_insert_document(cur, doc)
            total_docs += 1
        print(f"  - {total_docs} documents")
    
    # ── Import Chunks ──────────────────────────────────────────────────
    chunks_file = export_path / "chunks.json"
    if chunks_file.exists():
        print("Importing chunks...")
        with open(chunks_file) as f:
            chunks = json.load(f)
        
        for chunk in chunks:
            cur.execute("""
                INSERT INTO knowledge_chunks (
                    document_id, section, content, chunk_hash,
                    chunk_index, postgresql_versions,
                    environment_applicability, source_document_title,
                    source_document_version, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                chunk["document_id"],
                chunk["section"],
                chunk["content"],
                chunk["chunk_hash"],
                chunk["chunk_index"],
                chunk.get("postgresql_versions", []),
                chunk.get("environment_applicability", []),
                chunk.get("source_document_title"),
                chunk.get("source_document_version"),
                chunk.get("created_at"),
            ))
            total_chunks += 1
        print(f"  - {total_chunks} chunks")
    
    # ── Import Templates ──────────────────────────────────────────────
    templates_file = export_path / "templates.json"
    if templates_file.exists():
        print("Importing templates...")
        with open(templates_file) as f:
            templates = json.load(f)
        
        for template in templates:
            cur.execute(
                "SELECT template_id FROM templates WHERE template_id = %s",
                (template["template_id"],)
            )
            if cur.fetchone():
                continue  # Skip existing
            
            cur.execute("""
                INSERT INTO templates (
                    template_id, title, version, status,
                    content, tags, postgresql_versions,
                    environment_applicability, classification,
                    source_url, policy_owner,
                    approved_by, approved_at,
                    effective_date, expiry_date,
                    created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                template["template_id"],
                template["title"],
                template["version"],
                template["status"],
                template["content"],
                template.get("tags", []),
                template.get("postgresql_versions", []),
                template.get("environment_applicability", []),
                template.get("classification", "internal"),
                template.get("source_url"),
                template.get("policy_owner", ""),
                template.get("approved_by"),
                template.get("approved_at"),
                template.get("effective_date"),
                template.get("expiry_date"),
                template.get("created_at"),
                template.get("updated_at"),
            ))
            total_templates += 1
        print(f"  - {total_templates} templates")
    
    # ── Import Template Ingestion Status ──────────────────────────────
    ingestion_file = export_path / "template_ingestion_status.json"
    if ingestion_file.exists():
        print("Importing template ingestion status...")
        with open(ingestion_file) as f:
            ingestion = json.load(f)
        
        for status in ingestion:
            cur.execute("""
                INSERT INTO template_ingestion_status (
                    template_id, version, status,
                    chunks_created, ingestion_timestamp
                ) VALUES (%s, %s, %s, %s, %s)
            """, (
                status["template_id"],
                status["version"],
                status["status"],
                status.get("chunks_created", 0),
                status.get("ingestion_timestamp"),
            ))
        print(f"  - {len(ingestion)} records")
    
    # ── Import Snapshot Data ──────────────────────────────────────────
    for snapshot_file in export_path.glob("snapshot_*.json"):
        table_name = snapshot_file.stem.replace("snapshot_", "")
        print(f"Importing {table_name}...")
        with open(snapshot_file) as f:
            data = json.load(f)
        
        # Simple bulk insert (assumes table structure matches)
        if data:
            first = data[0]
            columns = list(first.keys())
            placeholders = ", ".join([f"%({c})s" for c in columns])
            cols = ", ".join(columns)
            
            for row in data:
                cur.execute(f"""
                    INSERT INTO {table_name} ({cols}) VALUES ({placeholders})
                """, row)
        print(f"  - {len(data)} records")
    
    conn.commit()
    cur.close()
    conn.close()
    
    # ── Summary ───────────────────────────────────────────────────────
    print("\n=== Import Summary ===")
    print(f"Documents: {total_docs}")
    print(f"Chunks: {total_chunks}")
    print(f"Templates: {total_templates}")
    print(f"\nImport complete from: {export_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python import_all.py <export_dir> [db_url]")
        print("")
        print("Example:")
        print("  python import_all.py export postgresql://dbguard:***@localhost:5433/dbguard")
        sys.exit(1)
    
    export_dir = sys.argv[1]
    db_url = sys.argv[2] if len(sys.argv) > 2 else "postgresql://dbguard:***@localhost:5433/dbguard"
    
    print(f"Importing all RAG data from {export_dir}")
    import_all(export_dir, db_url)
