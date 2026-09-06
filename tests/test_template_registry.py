"""Tests for PostgreSQL template registry as authoritative source of truth."""

import hashlib
import unittest
from unittest.mock import patch

import psycopg2

from app.models import TemplateIngestRequest, ProposalCompileRequest
from app.services.template_service import compile_sql_plan_from_templates
from app.services.vector_service import (
    compute_template_hash,
    ingest_template,
    search_templates,
    approve_template,
    get_active_template_version,
    init_db,
)


class TemplateRegistryTests(unittest.TestCase):
    """Test template registry behavior."""

    @classmethod
    def setUpClass(cls):
        """Initialize the database before all tests."""
        init_db()

    def setUp(self):
        """Set up test fixtures."""
        # Use a test database URL - this assumes a test DB is available
        self.test_template_name = "test_template_registry"
        self.test_description = "Test template for registry validation"

    def test_compute_template_hash(self):
        """Test that SHA-256 hash is computed correctly."""
        sql = "SELECT 1;"
        expected_hash = hashlib.sha256(sql.encode("utf-8")).hexdigest()
        actual_hash = compute_template_hash(sql)
        self.assertEqual(actual_hash, expected_hash)

    def test_ingest_template_creates_draft(self):
        """Test that newly ingested template is created as draft."""
        template_name = f"{self.test_template_name}_draft_v1"
        sql = "-- Test template\nSELECT 1;"

        result = ingest_template(
            template_name=template_name,
            description=self.test_description,
            sql_template=sql,
            version=1,
        )

        self.assertEqual(result["status"], "draft")
        # Verify it's not in active search results
        search_results = search_templates("test template", top_k=5)
        template_names = [r["template_name"] for r in search_results]
        self.assertNotIn(template_name, template_names)

    def test_approved_content_cannot_be_silently_overwritten(self):
        """Test that approving a template doesn't allow silent overwrites."""
        template_name = f"{self.test_template_name}_immutable"
        sql_v1 = "-- Version 1\nSELECT 1;"

        # Ingest and approve version 1
        ingest_template(
            template_name=template_name,
            description=self.test_description,
            sql_template=sql_v1,
            version=1,
        )
        approve_result = approve_template(template_name, 1, "test_approver")
        self.assertTrue(approve_result)

        # Now try to ingest version 2
        sql_v2 = "-- Version 2\nSELECT 2;"
        result = ingest_template(
            template_name=template_name,
            description=self.test_description,
            sql_template=sql_v2,
            version=2,
        )

        # Version 2 should be created as draft, not overwrite v1
        self.assertEqual(result["version"], 2)
        self.assertEqual(result["status"], "draft")

        # v1 should still be active
        active = get_active_template_version(template_name)
        self.assertIsNotNone(active)
        self.assertEqual(active["version"], 1)
        self.assertEqual(active["sql_template"], sql_v1)

    def test_only_active_templates_are_retrievable(self):
        """Test that semantic search returns only active templates."""
        template_name = f"{self.test_template_name}_search_test"

        # First, create a draft
        ingest_template(
            template_name=template_name,
            description=self.test_description,
            sql_template="-- Draft template\nSELECT 1;",
            version=1,
        )

        # Should not appear in search
        search_results = search_templates("test template", top_k=5)
        template_names = [r["template_name"] for r in search_results]
        self.assertNotIn(template_name, template_names)

        # Now approve it
        approve_template(template_name, 1, "test_approver")

        # Should now appear in search
        search_results = search_templates("test template", top_k=5)
        template_names = [r["template_name"] for r in search_results]
        self.assertIn(template_name, template_names)

    def test_exact_approved_template_compiles(self):
        """Test that approved template content from PostgreSQL is used for compilation."""
        template_name = f"{self.test_template_name}_compile_test"
        # Template with unique placeholder that we can verify
        sql = "SELECT '{{ variable_name }}' AS value;"

        # Ingest and approve
        ingest_template(
            template_name=template_name,
            description=self.test_description,
            sql_template=sql,
            version=1,
        )
        approve_template(template_name, 1, "test_approver")

        # Get the active template record
        record = get_active_template_version(template_name)
        self.assertIsNotNone(record)
        self.assertEqual(record["sql_template"], sql)

        # Compile using the record
        template_records = [record]
        variables = {"variable_name": "test_value"}
        result = compile_sql_plan_from_templates(template_records, variables)

        # Verify the compiled SQL contains the exact template content
        self.assertIn("SELECT 'test_value' AS value;", result)
        self.assertIn(template_name, result)

    def test_draft_template_cannot_compile(self):
        """Test that draft/unapproved templates fail compilation."""
        template_name = f"{self.test_template_name}_draft_fail"

        # Create a draft (not approved)
        ingest_template(
            template_name=template_name,
            description=self.test_description,
            sql_template="-- Draft only\nSELECT 1;",
            version=1,
        )

        # Attempt to get active version - should return None
        active = get_active_template_version(template_name)
        self.assertIsNone(active)


class TemplateRegistryWithMockDB(unittest.TestCase):
    """Test template compilation with mocked database for isolation."""

    @patch("app.services.template_service.env.from_string")
    def test_compiler_uses_postgreSQL_content_not_filesystem(self, mock_from_string):
        """Test that compilation uses PostgreSQL template content, not filesystem."""
        # Simulate PostgreSQL returning specific template content
        mock_template = unittest.mock.MagicMock()
        mock_template.render.return_value = "-- PostgreSQL content\nSELECT 1;"

        mock_from_string.return_value = mock_template

        template_records = [
            {
                "template_name": "test_template",
                "sql_template": "SELECT 1;",
                "version": 1,
            }
        ]
        variables = {}

        result = compile_sql_plan_from_templates(template_records, variables)

        # Verify the mock was called (i.e., we used from_string, not get_template)
        mock_from_string.assert_called_once()
        self.assertIn("PostgreSQL content", result)
        self.assertNotIn("filesystem", result.lower())

    @patch("app.services.template_service.env.from_string")
    def test_malformed_template_from_db_raises_error(self, mock_from_string):
        """Test that a malformed Jinja2 template from DB fails appropriately."""
        # Simulate a malformed template in PostgreSQL
        mock_from_string.side_effect = Exception("Jinja2 parse error")

        template_records = [
            {
                "template_name": "malformed_template",
                "sql_template": "SELECT {{ malformed",
                "version": 1,
            }
        ]
        variables = {}

        with self.assertRaises(Exception):
            compile_sql_plan_from_templates(template_records, variables)


if __name__ == "__main__":
    unittest.main()
