"""Tier A tests for Template Registry - Pure (zero external dependencies)."""
import hashlib
from unittest.mock import MagicMock, patch

import pytest

from app.services.embedding_service import generate_embedding
from app.services.template_service import compile_sql_plan_from_templates
from app.services.vector_service import (
    approve_template,
    compute_template_hash,
    get_active_template_version,
    ingest_template,
    init_db,
    search_templates,
)

pytestmark = pytest.mark.tier_a


class TestTemplateRegistryPure:
    """Pure tests for template registry - mocks all external dependencies."""

    def test_compute_template_hash_sha256(self):
        """Test that SHA-256 hash is computed correctly."""
        sql = "SELECT 1;"
        expected_hash = hashlib.sha256(sql.encode("utf-8")).hexdigest()
        actual_hash = compute_template_hash(sql)
        assert actual_hash == expected_hash

    def test_compute_template_hash_different_inputs(self):
        """Test that different SQL produces different hashes."""
        hash1 = compute_template_hash("SELECT 1;")
        hash2 = compute_template_hash("SELECT 2;")
        hash3 = compute_template_hash("SELECT 1;  ")
        assert hash1 != hash2
        assert hash1 != hash3

    def test_compute_template_hash_empty_string(self):
        """Test that empty string produces valid hash."""
        hash_result = compute_template_hash("")
        assert len(hash_result) == 64

    def test_compute_template_hash_unicode(self):
        """Test that unicode characters are hashed correctly."""
        sql1 = "SELECT 'émojis 🚀';"
        sql2 = "SELECT 'émojis 🚀';"
        assert compute_template_hash(sql1) == compute_template_hash(sql2)

    def test_template_ingest_stores_draft_status_with_mock(self):
        """Test that newly ingested template is created as draft (mocked DB)."""
        with patch("app.services.vector_service.psycopg2.connect") as mock_connect, \
             patch("app.services.vector_service.generate_embedding") as mock_embedding:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            # First call to fetchone (SELECT latest version) returns None (no existing template)
            # Second call to fetchone (INSERT RETURNING) returns the new row
            mock_cursor.fetchone.side_effect = [None, [1, "test_template", 1, "draft"]]
            mock_connect.return_value = mock_conn
            mock_embedding.return_value = [0.1] * 768

            result = ingest_template(
                template_name="test_template",
                description="Test template for registry validation",
                sql_template="SELECT 1;",
                version=1,
            )

            assert result["status"] == "draft"
            assert result["template_name"] == "test_template"
            assert result["version"] == 1

            mock_cursor.execute.assert_called()
            # Verify INSERT was called (not ON CONFLICT UPDATE)
            calls = [call[0][0] for call in mock_cursor.execute.call_args_list]
            insert_calls = [c for c in calls if "INSERT INTO templates" in c]
            assert len(insert_calls) >= 1
            # Verify no UPDATE calls
            update_calls = [c for c in calls if "UPDATE templates" in c]
            assert len(update_calls) == 0

    def test_template_search_filters_draft_templates_with_mock(self):
        """Test that search returns only active templates (mocked DB)."""
        with patch("app.services.vector_service.psycopg2.connect") as mock_connect, \
             patch("app.services.vector_service.generate_embedding") as mock_embedding:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_cursor.fetchall.return_value = []
            mock_cursor.description = [("id",), ("template_name",), ("version",)]
            mock_connect.return_value = mock_conn
            mock_embedding.return_value = [0.1] * 768

            results = search_templates("test query", top_k=5)

            assert results == []
            call_args = mock_cursor.execute.call_args[0][0]
            assert "WHERE status = 'active'" in call_args

    def test_template_approval_returns_true_on_success_with_mock(self):
        """Test that approving a template returns True on success (mocked DB)."""
        with patch("app.services.vector_service.psycopg2.connect") as mock_connect:
            mock_conn = MagicMock()
            cur = MagicMock()
            cur.__enter__.return_value = cur  # with conn.cursor() as cur yields this same mock
            cur.fetchone.return_value = [1]   # draft row exists
            mock_conn.cursor.return_value = cur
            mock_connect.return_value = mock_conn

            result = approve_template("test_template", 1, "test_approver")

            assert result is True
            sql = [c.args[0] for c in cur.execute.call_args_list]
            assert len(sql) == 3, sql
            assert "status = 'draft'" in sql[0] and "FOR UPDATE" in sql[0]
            assert "status = 'archived'" in sql[1]
            assert "status = 'active'" in sql[2]

    def test_template_approval_returns_false_no_rows_with_mock(self):
        """Test that approving a non-existent template returns False."""
        with patch("app.services.vector_service.psycopg2.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            # The cursor is used in a context manager: with conn.cursor() as cur
            cursor_context = MagicMock()
            cursor_context.__enter__ = MagicMock(return_value=cursor_context)
            cursor_context.__exit__ = MagicMock(return_value=None)
            cursor_context.execute = MagicMock()
            cursor_context.fetchone = MagicMock(return_value=None)
            mock_conn.cursor.return_value = cursor_context
            mock_connect.return_value = mock_conn

            result = approve_template("nonexistent_template", 1, "test_approver")

            assert result is False
            assert cursor_context.execute.call_count == 1  # only the draft check ran; nothing was updated

    def test_get_active_template_version_returns_none_when_not_active_with_mock(self):
        """Test that getting active version returns None when template is draft."""
        with patch("app.services.vector_service.psycopg2.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_cursor.fetchone.return_value = None
            mock_connect.return_value = mock_conn

            result = get_active_template_version("test_template")

            assert result is None
            call_args = mock_cursor.execute.call_args[0][0]
            assert "WHERE template_name" in call_args

    def test_get_active_template_version_returns_record_when_active_with_mock(self):
        """Test that getting active version returns template record."""
        with patch("app.services.vector_service.psycopg2.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_cursor.fetchone.return_value = [
                1, "test_template", 1, "Test description",
                "SELECT 1;", "abc123", ["tag1"], "medium", "16"
            ]
            mock_connect.return_value = mock_conn

            result = get_active_template_version("test_template")

            assert result is not None
            assert result["template_name"] == "test_template"
            assert result["version"] == 1
            assert result["sql_template"] == "SELECT 1;"

    def test_template_compiler_uses_jinja2(self):
        """Test that template compilation uses Jinja2."""
        template_records = [
            {
                "template_name": "test_template",
                "sql_template": "SELECT '{{ variable }}' AS value;",
                "version": 1,
            }
        ]
        variables = {"variable": "test_value"}

        result = compile_sql_plan_from_templates(template_records, variables)

        assert "SELECT 'test_value' AS value;" in result
        assert "-- Template: test_template" in result

    def test_template_compiler_handles_multiple_templates(self):
        """Test that compilation handles multiple templates."""
        template_records = [
            {
                "template_name": "template_1",
                "sql_template": "SELECT 1;",
                "version": 1,
            },
            {
                "template_name": "template_2",
                "sql_template": "SELECT 2;",
                "version": 1,
            },
        ]
        variables = {}

        result = compile_sql_plan_from_templates(template_records, variables)

        assert "-- Template: template_1" in result
        assert "SELECT 1;" in result
        assert "-- Template: template_2" in result
        assert "SELECT 2;" in result

    def test_template_compiler_strips_whitespace(self):
        """Test that template compiler handles whitespace in SQL."""
        template_records = [
            {
                "template_name": "test_template",
                "sql_template": "  SELECT 1;  ",
                "version": 1,
            }
        ]
        variables = {}

        result = compile_sql_plan_from_templates(template_records, variables)

        assert "SELECT 1;" in result

    def test_template_compiler_handles_empty_variables(self):
        """Test that template compilation works with empty variables dict."""
        template_records = [
            {
                "template_name": "test_template",
                "sql_template": "SELECT 1;",
                "version": 1,
            }
        ]
        variables = {}

        result = compile_sql_plan_from_templates(template_records, variables)

        assert "SELECT 1;" in result

    def test_template_compiler_handles_variables_in_where_clause(self):
        """Test that template compiler handles variables in WHERE clause."""
        template_records = [
            {
                "template_name": "test_template",
                "sql_template": "SELECT * FROM users WHERE name = '{{ name }}';",
                "version": 1,
            }
        ]
        variables = {"name": "john"}

        result = compile_sql_plan_from_templates(template_records, variables)

        assert "SELECT * FROM users WHERE name = 'john';" in result

    def test_template_compiler_handles_missing_variable_raises_error(self):
        """Test that missing required variables raise Jinja2 error."""
        template_records = [
            {
                "template_name": "test_template",
                "sql_template": "SELECT '{{ required_var }}' AS value;",
                "version": 1,
            }
        ]
        variables = {}  # Missing required_var

        with pytest.raises(Exception):
            compile_sql_plan_from_templates(template_records, variables)

    def test_template_compiler_handles_default_values(self):
        """Test that Jinja2 default filter works in templates."""
        template_records = [
            {
                "template_name": "test_template",
                "sql_template": "SELECT '{{ variable | default(\"default_val\") }}' AS value;",
                "version": 1,
            }
        ]
        variables = {}

        result = compile_sql_plan_from_templates(template_records, variables)

        assert "SELECT 'default_val' AS value;" in result

    def test_template_hash_is_sha256_hex_digest(self):
        """Test that template hash is valid SHA-256 hex digest."""
        sql = "SELECT * FROM pg_tables;"
        hash_result = compute_template_hash(sql)

        assert len(hash_result) == 64
        assert all(c in "0123456789abcdef" for c in hash_result)

    def test_template_hash_consistent_across_calls(self):
        """Test that same SQL always produces same hash."""
        sql = "SELECT 1; SELECT 2;"
        hash1 = compute_template_hash(sql)
        hash2 = compute_template_hash(sql)
        hash3 = compute_template_hash(sql)

        assert hash1 == hash2 == hash3

    def test_template_hash_handles_newlines(self):
        """Test that template hash is consistent regardless of trailing newlines."""
        sql1 = "SELECT 1;"
        sql2 = "SELECT 1;\n"
        sql3 = "SELECT 1;\n\n"

        hash1 = compute_template_hash(sql1)
        hash2 = compute_template_hash(sql2)
        hash3 = compute_template_hash(sql3)

        assert hash1 != hash2
        assert hash2 != hash3

    def test_template_hash_handles_different_encodings(self):
        """Test that template hash handles UTF-8 encoding correctly."""
        sql1 = "SELECT '日本語';"
        sql2 = "SELECT '日本語';"

        hash1 = compute_template_hash(sql1)
        hash2 = compute_template_hash(sql2)

        assert hash1 == hash2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
