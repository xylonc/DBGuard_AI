#!/usr/bin/env python3
"""
Script to ingest the CIS PostgreSQL 17 Benchmark into the RAG knowledge base.

This reads the markdown file and chunks it for semantic search.
"""

import os
import sys
from datetime import datetime
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from services.rag.rag_service import RAGService, KnowledgeDocument


def ingest_cis_benchmark():
    """Ingest the CIS PostgreSQL 17 Benchmark into the RAG system."""
    
    # Path to the benchmark markdown file
    benchmark_path = Path(__file__).parent / "local docs" / "CIS_PostgreSQL_17_Benchmark_v1.1.0.cleaned.md"
    
    if not benchmark_path.exists():
        print(f"Error: Benchmark file not found at {benchmark_path}")
        return
    
    # Read the markdown content
    with open(benchmark_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Create document metadata
    document_id = "cis-pg-17-benchmark-v1.1.0"
    
    document = KnowledgeDocument(
        document_id=document_id,
        title="CIS PostgreSQL 17 Benchmark v1.1.0",
        version="1.1.0",
        content=content,
        effective_date=datetime.utcnow(),
        status="draft",  # Start as draft, needs manual approval
        postgresql_versions=["17"],
        environment_applicability=["all"],
        policy_owner="DBGuardAI Team",
        classification="internal",
        source_url="https://www.cisecurity.org/cis-benchmarks",
    )
    
    # Initialize RAG service
    db_url = os.getenv("DATABASE_URL", "postgresql://dbguard:***@localhost:5432/dbguard")
    rag = RAGService(db_url)
    
    print(f"Ingesting benchmark document: {document.title}")
    print(f"  Document ID: {document_id}")
    print(f"  Content length: {len(content)} characters")
    
    # Ingest the document
    result = rag.ingest_document(document)
    
    print(f"\nIngestion result:")
    print(f"  Status: {result.status}")
    print(f"  Chunks created: {result.chunks_created}")
    
    if result.errors:
        print(f"  Errors: {result.errors}")
    
    if result.status == "draft":
        print("\nNext steps:")
        print(f"  1. Run: curl -X POST http://localhost:8000/api/v1/knowledge/documents/{document_id}/approve")
        print("     - with body: {\"approved_by\": \"your-name\"}")
        print("  2. Then the benchmark will be searchable")


if __name__ == "__main__":
    ingest_cis_benchmark()
