import unittest
from unittest.mock import MagicMock

from app.services.template_service import compile_sql_plan_from_templates, quote_identifier


class TemplateServiceTests(unittest.TestCase):
    def test_identifier_quotes_cannot_escape_into_sql(self):
        self.assertEqual(quote_identifier('role"name'), '"role""name"')

    def test_role_template_never_embeds_a_password(self):
        # Use PostgreSQL template content instead of filesystem
        template_records = [
            {
                "template_name": "create_read_only_rule",
                "sql_template": """-- Purpose: Creates a new user role with read-only permissions on a targeted schema.
-- Hardening Action: Create Read-Only Auditor Role
CREATE ROLE {{ role_name | ident }} WITH LOGIN;
GRANT CONNECT ON DATABASE {{ database_name | ident }} TO {{ role_name | ident }};
GRANT USAGE ON SCHEMA {{ schema_name | default('public') | ident }} TO {{ role_name | ident }};
GRANT SELECT ON ALL TABLES IN SCHEMA {{ schema_name | default('public') | ident }} TO {{ role_name | ident }};
""",
            }
        ]

        sql = compile_sql_plan_from_templates(
            template_records,
            {
                "role_name": "readonly_auditor",
                "database_name": "app_db",
                "schema_name": "public",
            },
        )
        self.assertIn('CREATE ROLE "readonly_auditor" WITH LOGIN;', sql)
        self.assertNotIn(" WITH LOGIN PASSWORD ", sql.upper())

    def test_compiler_uses_postgreSQL_content_not_filesystem(self):
        # Test that the function uses from_string (PostgreSQL content) not get_template (filesystem)
        template_records = [
            {
                "template_name": "test_template",
                "sql_template": "SELECT 1;",
            }
        ]

        result = compile_sql_plan_from_templates(template_records, {})
        self.assertIn("SELECT 1;", result)


if __name__ == "__main__":
    unittest.main()
