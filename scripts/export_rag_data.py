#!/usr/bin/env python3
"""
Export RAG knowledge data from the database to JSON files.

This script extracts:
- Knowledge documents metadata (title, version, status, etc.)
- Knowledge chunks content

Output:
- documents.json - Document metadata
- chunks.json - Chunk content and metadata
"""

import json
import sys
from pathlib import Path
from datetime import datetime

import psycopg2
import psycopg2.extras


def export_rag_data(
    db_url: str = "postgresql://dbguard:***@localhost:5433/dbguard",
    output_dir: str = "export"
) -> dict:
    """Export RAG data to JSON files."""
    conn = psycopg2.connect(db_url)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Export documents
    cur.execute("""
        SELECT 
            document_id,
            title,
            version,
            status,
            effective_date,
            expiry_date,
            postgresql_versions,
            environment_applicability,
            policy_owner,
            classification,
            source_url,
            superseded_by,
            document_hash,
            approved_by,
            approved_at,
            created_at,
            updated_at
        FROM knowledge_documents
        ORDER BY created_at DESC
    """)
    documents = cur.fetchall()
    
    documents_file = output_path / "documents.json"
    with open(documents_file, "w") as f:
        json.dump([dict(doc) for doc in documents], f, indent=2, default=str)
    
    print(f"Exported {len(documents)} documents to {documents_file}")
    
    # Export chunks (with content)
    cur.execute("""
        SELECT 
            kc.id as chunk_id,
            kc.document_id,
            kc.section,
            kc.content,
            kc.chunk_hash,
            kc.chunk_index,
            kc.postgresql_versions,
            kc.environment_applicability,
            kc.source_document_title,
            kc.source_document_version,
            kc.created_at
        FROM knowledge_chunks kc
        ORDER BY kc.document_id, kc.chunk_index
    """)
    chunks = cur.fetchall()
    
    chunks_file = output_path / "chunks.json"
    with open(chunks_file, "w") as f:
        json.dump([dict(chunk) for chunk in chunks], f, indent=2, default=str)
    
    print(f"Exported {len(chunks)} chunks to {chunks_file}")
    
    # Export metadata summary
    summary = {
        "export_timestamp": datetime.utcnow().isoformat(),
        "database_url": db_url,
        "documents_count": len(documents),
        "chunks_count": len(chunks),
        "documents": [
            {
                "document_id": doc["document_id"],
                "title": doc["title"],
                "version": doc["version"],
                "status": doc["status"]
            }
            for doc in documents
        ]
    }
    
    summary_file = output_path / "summary.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"Exported summary to {summary_file}")
    
    cur.close()
    conn.close()
    
    return summary


if __name__ == "__main__":
    # Get DB URL from environment or use default
    db_url = sys.argv[1] if len(sys.argv) > 1 else "postgresql://dbguard:***@localhost:5433/dbguard"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "export"
    
    summary = export_rag_data(db_url, output_dir)
    
    print("\n=== Export Complete ===")
    print(f"Documents: {summary['documents_count']}")
    print(f"Chunks: {summary['chunks_count']}")
