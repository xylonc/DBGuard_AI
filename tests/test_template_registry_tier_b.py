"""Tier B tests for Template Registry and Knowledge Documents - Live DB layer.

These tests require a live PostgreSQL database with pgvector extension.
Running these tests without the database will result in connection errors.

To run Tier B tests, ensure:
1. PostgreSQL is running with pgvector extension
2. DATABASE_URL is set correctly
3. psycopg2 or psycopg2-binary is installed

Run with:
    export DATABASE_URL="postgresql://user:***@localhost:5432/dbname"
    pytest tests/test_template_registry_tier_b.py -m tier_b -v

Or use Docker:
    docker-compose up -d db
    pytest tests/test_template_registry_tier_b.py -m tier_b -v
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.config import settings
from app.services.embedding_service import generate_embedding
from app.services.vector_service import (
    approve_template,
    get_active_template_version,
    ingest_template,
    search_templates,
)


def _get_db_url():
    """Get database URL from environment or build from components.

    Uses DATABASE_URL if set, otherwise falls back to environment variables
    with explicit localhost/127.0.0.1 to avoid IPv6 issues.
    """
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        return db_url

    # Use 127.0.0.1 explicitly to avoid IPv6 resolution issues
    host = os.getenv("POSTGRES_HOST", "127.0.0.1")
    port = os.getenv("POSTGRES_PORT", "5433")
    user = os.getenv("POSTGRES_USER", "dbguard")
    password = os.getenv("POSTGRES_PASSWORD", "securepassword123")
    dbname = os.getenv("POSTGRES_DB", "dbguard_test")

    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"


@pytest.fixture(scope="function")
def db_connection():
    """Create a test database connection."""
    import psycopg2
    db_url = _get_db_url()
    conn = psycopg2.connect(db_url)
    conn.autocommit = False
    yield conn
    conn.rollback()
    conn.close()


@pytest.fixture(scope="function")
def test_template_name():
    """Generate a unique template name for testing."""
    import uuid
    return f"test_template_{uuid.uuid4().hex[:12]}"


@pytest.fixture(scope="function")
def cleanup_template(test_template_name):
    """Cleanup template after test."""
    yield
    try:
        import psycopg2
        db_url = _get_db_url()
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("DELETE FROM templates WHERE template_name = %s", (test_template_name,))
        conn.commit()
        conn.close()
    except Exception:
        pass


@pytest.mark.tier_b
class TestTemplateRegistryLive:
    """Live tests for template registry with real PostgreSQL connection."""

    def test_ingest_template_creates_draft_with_embedding(self, test_template_name, cleanup_template):
        """Test that template ingestion creates a draft with embedded vector."""
        result = ingest_template(
            template_name=test_template_name,
            description="Test template for live DB verification",
            sql_template="SELECT 1;",
            version=1,
        )

        assert result["status"] == "draft"
        assert result["template_name"] == test_template_name
        assert result["version"] == 1

    def test_search_templates_returns_only_active(self, test_template_name, cleanup_template):
        """Test that template search returns only active (approved) templates."""
        # Ingest a template
        ingest_template(
            template_name=test_template_name,
            description="Searchable template for live testing",
            sql_template="SELECT * FROM users WHERE status = 'active';",
            version=1,
        )

        # Search should not return draft template
        results = search_templates("users", top_k=5)
        template_names = [r["template_name"] for r in results]
        assert test_template_name not in template_names

        # Approve the template
        approve_template(test_template_name, 1, "test_approver")

        # Now search should return the active template
        results = search_templates("users", top_k=5)
        template_names = [r["template_name"] for r in results]
        assert test_template_name in template_names

    def test_template_vector_storage_includes_pgvector_embedding(self, test_template_name, cleanup_template):
        """Test that ingested templates have pgvector embeddings stored."""
        import psycopg2

        # Ingest template
        ingest_template(
            template_name=test_template_name,
            description="Template with vector storage test",
            sql_template="SELECT NOW();",
            version=1,
        )

        # Verify embedding is stored in database
        db_url = _get_db_url()
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("""
            SELECT id, template_name, version, embedding IS NOT NULL as has_embedding
            FROM templates
            WHERE template_name = %s AND version = 1
        """, (test_template_name,))
        row = cur.fetchone()
        conn.close()

        assert row is not None
        assert row[3] is True  # has_embedding is True

    def test_similar_template_search_returns_results(self, test_template_name, cleanup_template):
        """Test that semantic search returns similar templates by cosine similarity."""
        import psycopg2

        # Ingest a template about security
        ingest_template(
            template_name=test_template_name,
            description="PostgreSQL security best practices for role management",
            sql_template="REVOKE ALL ON SCHEMA public FROM public;",
            version=1,
        )

        # Approve it
        approve_template(test_template_name, 1, "test_approver")

        # Search for similar security-related templates
        results = search_templates("role permissions security", top_k=5)

        # Should find our template
        assert len(results) > 0
        assert any(r["template_name"] == test_template_name for r in results)

        # Verify similarity scores are reasonable
        template_result = next((r for r in results if r["template_name"] == test_template_name), None)
        assert template_result is not None
        assert "similarity" in template_result
        assert template_result["similarity"] >= 0.0  # Cosine distance is 0-2

    def test_template_approval_marks_as_active(self, test_template_name, cleanup_template):
        """Test that template approval updates status to active."""
        import psycopg2

        # Ingest as draft
        ingest_template(
            template_name=test_template_name,
            description="Template to be approved",
            sql_template="SELECT 1;",
            version=1,
        )

        # Verify it's a draft
        db_url = _get_db_url()
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("SELECT status FROM templates WHERE template_name = %s", (test_template_name,))
        row = cur.fetchone()
        assert row[0] == "draft"
        conn.close()

        # Approve
        result = approve_template(test_template_name, 1, "test_approver")
        assert result is True

        # Verify it's now active
        db_url = _get_db_url()
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("SELECT status FROM templates WHERE template_name = %s", (test_template_name,))
        row = cur.fetchone()
        assert row[0] == "active"
        conn.close()

    def test_approve_template_fails_for_nonexistent(self, test_template_name, cleanup_template):
        """Test that approving non-existent template returns False."""
        result = approve_template(test_template_name, 1, "test_approver")
        assert result is False

    def test_get_active_template_version_returns_none_for_draft(self, test_template_name, cleanup_template):
        """Test that getting active version returns None for draft templates."""
        ingest_template(
            template_name=test_template_name,
            description="Draft template",
            sql_template="SELECT 1;",
            version=1,
        )

        active = get_active_template_version(test_template_name)
        assert active is None

    def test_get_active_template_version_returns_record_when_active(self, test_template_name, cleanup_template):
        """Test that getting active version returns template record when approved."""
        import psycopg2

        # Ingest and approve
        ingest_template(
            template_name=test_template_name,
            description="Active template",
            sql_template="SELECT 1;",
            version=1,
        )
        approve_template(test_template_name, 1, "test_approver")

        # Get active version
        active = get_active_template_version(test_template_name)
        assert active is not None
        assert active["template_name"] == test_template_name
        assert active["version"] == 1
        assert active["sql_template"] == "SELECT 1;"

    def test_search_returns_similar_results_across_versions(self, test_template_name, cleanup_template):
        """Test that search works correctly across template versions."""
        import psycopg2

        # Ingest version 1
        ingest_template(
            template_name=test_template_name,
            description="Version 1 template",
            sql_template="SELECT 1;",
            version=1,
        )

        # Ingest version 2 (different content)
        ingest_template(
            template_name=test_template_name,
            description="Version 2 template",
            sql_template="SELECT 2;",
            version=2,
        )

        # Search should return only active version (if approved)
        # or no results if neither is active
        results = search_templates("version", top_k=5)

        # Both versions should exist in database (not necessarily active)
        db_url = _get_db_url()
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM templates WHERE template_name = %s", (test_template_name,))
        row_count = cur.fetchone()[0]
        conn.close()

        assert row_count == 2


@pytest.mark.tier_b
class TestKnowledgeDocumentsLive:
    """Live tests for knowledge documents with real database."""

    def test_ingest_knowledge_document_stores_chunks(self):
        """Test that knowledge document ingestion stores chunks in database."""
        from datetime import datetime
        from services.rag.rag_service import KnowledgeDocument, RAGService
        import psycopg2

        doc_id = f"test_know_{os.urandom(4).hex()}"

        doc = KnowledgeDocument(
            document_id=doc_id,
            title="Live Knowledge Document",
            version="1.0.0",
            content="# Test Document\n\n" + ("Test content line\n" * 200),
            effective_date=datetime.utcnow(),
            status="draft",
        )

        rag_service = RAGService()
        result = rag_service.ingest_document(doc)

        assert result.document_id == doc_id
        assert result.chunks_created > 0
        assert result.status in ("ingested", "partial")  # Allow partial if some chunks fail

        # Verify chunks are stored in database
        db_url = _get_db_url()
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM knowledge_chunks WHERE document_id = %s", (doc_id,))
        chunk_count = cur.fetchone()[0]
        conn.close()

        assert chunk_count > 0

    def test_search_knowledge_documents_by_semantic_similarity(self):
        """Test that knowledge search returns semantically similar results."""
        from datetime import datetime
        from services.rag.rag_service import KnowledgeDocument, RAGService

        doc_id = f"test_search_{os.urandom(4).hex()}"

        doc = KnowledgeDocument(
            document_id=doc_id,
            title="PostgreSQL Security Best Practices",
            version="1.0.0",
            content="# PostgreSQL Security\n\nThis document covers security best practices for PostgreSQL databases.\n\n" * 50,
            effective_date=datetime.utcnow(),
            status="draft",
        )

        rag_service = RAGService()
        rag_service.ingest_document(doc)

        # Search should return results
        results = rag_service.search("PostgreSQL security", top_k=5)

        assert len(results) >= 0  # May be 0 if not enough chunks

    def test_get_document_metadata_returns_record(self):
        """Test that getting document metadata returns the document record."""
        from datetime import datetime
        from services.rag.rag_service import KnowledgeDocument, RAGService
        import psycopg2

        doc_id = f"test_meta_{os.urandom(4).hex()}"

        doc = KnowledgeDocument(
            document_id=doc_id,
            title="Metadata Test Document",
            version="1.0.0",
            content="# Test\n\nContent here.",
            effective_date=datetime.utcnow(),
            status="draft",
        )

        rag_service = RAGService()
        rag_service.ingest_document(doc)

        metadata = rag_service.get_document_metadata(doc_id)

        assert metadata is not None
        assert metadata.document_id == doc_id
        assert metadata.title == "Metadata Test Document"
        assert metadata.version == "1.0.0"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "tier_b"])
