#!/usr/bin/env python3
"""
Import RAG knowledge data from JSON files into the database.

Usage:
    python import_rag_data.py <export_dir> [db_url]

Example:
    python import_rag_data.py export postgresql://dbguard:***@localhost:5433/dbguard
"""

import json
import sys
from pathlib import Path

import psycopg2
import psycopg2.extras


def get_or_create_document(
    cur: psycopg2.extensions.cursor,
    doc_data: dict
) -> str:
    """Insert or get existing document, return document_id."""
    # Check if document exists
    cur.execute(
        "SELECT document_id FROM knowledge_documents WHERE document_id = %s",
        (doc_data["document_id"],)
    )
    existing = cur.fetchone()
    if existing:
        return doc_data["document_id"]
    
    # Insert document
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


def import_rag_data(
    export_dir: str,
    db_url: str = "postgresql://dbguard:***@localhost:5433/dbguard"
) -> dict:
    """Import RAG data from JSON files."""
    export_path = Path(export_dir)
    
    # Load documents
    documents_file = export_path / "documents.json"
    if not documents_file.exists():
        raise FileNotFoundError(f"Documents file not found: {documents_file}")
    
    with open(documents_file) as f:
        documents = json.load(f)
    
    # Load chunks
    chunks_file = export_path / "chunks.json"
    if not chunks_file.exists():
        raise FileNotFoundError(f"Chunks file not found: {chunks_file}")
    
    with open(chunks_file) as f:
        chunks = json.load(f)
    
    # Connect to database
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    
    # Start transaction
    cur.execute("BEGIN")
    
    inserted_docs = 0
    inserted_chunks = 0
    
    try:
        # Insert documents
        for doc_data in documents:
            doc_id = get_or_create_document(cur, doc_data)
            inserted_docs += 1
        
        # Insert chunks
        for chunk_data in chunks:
            cur.execute("""
                INSERT INTO knowledge_chunks (
                    document_id, section, content, chunk_hash,
                    chunk_index, postgresql_versions,
                    environment_applicability, source_document_title,
                    source_document_version, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                chunk_data["document_id"],
                chunk_data["section"],
                chunk_data["content"],
                chunk_data["chunk_hash"],
                chunk_data["chunk_index"],
                chunk_data.get("postgresql_versions", []),
                chunk_data.get("environment_applicability", []),
                chunk_data.get("source_document_title"),
                chunk_data.get("source_document_version"),
                chunk_data.get("created_at"),
            ))
            inserted_chunks += 1
        
        # Commit
        conn.commit()
        
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()
    
    return {
        "documents_inserted": inserted_docs,
        "chunks_inserted": inserted_chunks
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python import_rag_data.py <export_dir> [db_url]")
        print("")
        print("Example:")
        print("  python import_rag_data.py export postgresql://dbguard:***@localhost:5433/dbguard")
        sys.exit(1)
    
    export_dir = sys.argv[1]
    db_url = sys.argv[2] if len(sys.argv) > 2 else "postgresql://dbguard:***@localhost:5433/dbguard"
    
    print(f"Importing RAG data from {export_dir}")
    print(f"Database: {db_url}")
    print("")
    
    result = import_rag_data(export_dir, db_url)
    
    print("=== Import Complete ===")
    print(f"Documents inserted: {result['documents_inserted']}")
    print(f"Chunks inserted: {result['chunks_inserted']}")
