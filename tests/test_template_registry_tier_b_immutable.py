"""Tier B tests for Template Registry Immutability.

Tests that template versions are immutable:
- Ingesting identical content twice returns the existing row (no-op)
- Ingesting changed content creates a new version N+1
- Active version's sql_template is unchanged after re-ingesting different content

These tests require a live PostgreSQL database with pgvector extension.
"""
import os
import sys
from pathlib import Path
import psycopg2

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.config import settings
from app.services.embedding_service import generate_embedding
from app.services.vector_service import (
    approve_template,
    get_active_template_version,
    get_all_versions,
    ingest_all_templates,
    ingest_template,
)


def _get_db_url():
    """Get database URL from environment or build from components."""
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        return db_url

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
    return f"test_immutable_{uuid.uuid4().hex[:12]}"


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
class TestTemplateImmutability:
    """Tests for template immutability - versions cannot be changed."""

    def test_ingest_identical_content_twice_returns_same_row(self, test_template_name, cleanup_template):
        """Ingesting identical content twice -> exactly one row."""
        # First ingest
        result1 = ingest_template(
            template_name=test_template_name,
            description="Test template",
            sql_template="SELECT 1;",
        )

        # Second ingest with same content
        result2 = ingest_template(
            template_name=test_template_name,
            description="Test template",
            sql_template="SELECT 1;",
        )

        # Should return existing version, no new row created
        assert result1["version"] == result2["version"]
        assert result1["template_name"] == result2["template_name"]
        assert result2["created"] is False  # No new row created
        assert result2["id"] == result1["id"]  # Same id as first ingest

        # Verify only one row in database
        db_url = _get_db_url()
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM templates WHERE template_name = %s", (test_template_name,))
        count = cur.fetchone()[0]
        conn.close()

        assert count == 1

    def test_ingest_changed_content_creates_new_version(self, test_template_name, cleanup_template):
        """Ingesting changed content -> new draft version N+1; version N row unchanged."""
        # Ingest version 1
        result1 = ingest_template(
            template_name=test_template_name,
            description="Version 1",
            sql_template="SELECT 1;",
        )
        assert result1["version"] == 1
        assert result1["id"] is not None  # New row created

        # Ingest version 2 with different content
        result2 = ingest_template(
            template_name=test_template_name,
            description="Version 2 (changed)",
            sql_template="SELECT 2;",
        )
        assert result2["version"] == 2
        assert result2["id"] is not None  # New row created

        # Verify both versions exist
        db_url = _get_db_url()
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("""
            SELECT version, sql_template FROM templates 
            WHERE template_name = %s 
            ORDER BY version
        """, (test_template_name,))
        rows = cur.fetchall()
        conn.close()

        assert len(rows) == 2
        assert rows[0] == (1, "SELECT 1;")
        assert rows[1] == (2, "SELECT 2;")

    def test_active_version_content_unchanged_after_re_ingest(self, test_template_name, cleanup_template):
        """An active version's sql_template is unchanged after re-ingesting different content."""
        # Ingest and approve version 1
        ingest_template(
            template_name=test_template_name,
            description="Original content",
            sql_template="SELECT original;",
        )
        approve_template(test_template_name, 1, "test_approver")

        # Verify active version has original content
        active = get_active_template_version(test_template_name)
        assert active["sql_template"] == "SELECT original;"

        # Re-ingest with different content (creates version 2)
        result = ingest_template(
            template_name=test_template_name,
            description="Changed content",
            sql_template="SELECT changed;",
        )
        assert result["version"] == 2

        # Active version should still have original content
        active = get_active_template_version(test_template_name)
        assert active["sql_template"] == "SELECT original;"
        assert active["version"] == 1

        # Version 2 should have new content but be draft
        all_versions = get_all_versions(test_template_name)
        v2 = next((v for v in all_versions if v["version"] == 2), None)
        assert v2 is not None
        assert v2["sql_template"] == "SELECT changed;"
        assert v2["status"] == "draft"

    def test_ingest_all_templates_uses_dynamic_versioning(self, test_template_name, cleanup_template, tmp_path):
        """ingest_all_templates creates version 1 for new templates."""
        # Create a temp template file in tmp_path
        temp_file = tmp_path / f"{test_template_name}.sql.j2"
        temp_file.write_text("-- Test template\nSELECT 1;\n", encoding="utf-8")
        
        # Run ingest_all_templates with temp directory
        ingest_all_templates(str(tmp_path))
        
        # Verify template was created with version 1
        db_url = _get_db_url()
        conn = psycopg2.connect(db_url)
        cur = conn.cursor()
        cur.execute("""
            SELECT version, status FROM templates 
            WHERE template_name = %s 
            ORDER BY version DESC
        """, (test_template_name,))
        row = cur.fetchone()
        conn.close()
        
        assert row is not None
        assert row[0] == 1  # Version 1
        assert row[1] == "draft"  # Draft status


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "tier_b"])
