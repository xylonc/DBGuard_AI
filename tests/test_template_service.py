import unittest

from app.services.template_service import compile_sql_plan, quote_identifier


class TemplateServiceTests(unittest.TestCase):
    def test_identifier_quotes_cannot_escape_into_sql(self):
        self.assertEqual(quote_identifier('role"name'), '"role""name"')

    def test_role_template_never_embeds_a_password(self):
        sql = compile_sql_plan(
            ["create_read_only_rule"],
            {
                "role_name": "readonly_auditor",
                "database_name": "app_db",
                "schema_name": "public",
            },
        )
        self.assertIn('CREATE ROLE "readonly_auditor" WITH LOGIN;', sql)
        self.assertNotIn(" WITH LOGIN PASSWORD ", sql.upper())


if __name__ == "__main__":
    unittest.main()
