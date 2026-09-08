"""Boundary tests and opt-in integration tests for the PostgreSQL executor."""

from __future__ import annotations

import os
import unittest
import uuid
from pathlib import Path

import psycopg2
from psycopg2 import sql
from pydantic import SecretStr

from backend.app.services.template_service import compile_sql_plan_from_templates
from services.assessment import (
    AssessmentFixtureContext,
    AssessmentService,
    AssessmentStatus,
    AssessmentSuite,
    AssessmentVerifierNotAllowed,
    BaselineCatalogStatus,
    InMemoryEvidenceSink,
    PostgresAssessmentExecutor,
    PostgresAssessmentFixtureManager,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TEST_DSN = os.getenv("DBGUARD_TEST_POSTGRES_DSN")


def _apply_template(connection, template_name, parameters):
    template_path = (
        REPOSITORY_ROOT
        / "backend"
        / "app"
        / "templates"
        / f"{template_name}.sql.j2"
    )
    sql_plan = compile_sql_plan_from_templates(
        [
            {
                "template_name": template_name,
                "sql_template": template_path.read_text(encoding="utf-8"),
            }
        ],
        parameters,
    )
    with connection.cursor() as cursor:
        cursor.execute(sql_plan)
    connection.commit()


class PostgresExecutorBoundaryTests(unittest.TestCase):
    def setUp(self):
        context = AssessmentFixtureContext(
            run_id="run-boundary-test",
            database_name="dbguard_test",
            schema_name="public",
            role_name="reporting_user",
            existing_probe_table="existing_probe",
            future_probe_table="future_probe",
            create_probe_table="create_probe",
            target_password=SecretStr("ephemeral-test-only"),
            before_hardening_prepared=True,
            after_hardening_prepared=True,
        )
        self.executor = PostgresAssessmentExecutor(
            "postgresql://admin:secret@127.0.0.1:1/dbguard_test",
            context,
        )

    def test_executor_implements_exactly_sixteen_allowlisted_checks(self):
        self.assertEqual(len(self.executor.verifier_ids), 16)

    def test_unknown_verifier_is_rejected_before_database_access(self):
        with self.assertRaises(AssessmentVerifierNotAllowed):
            self.executor.run_check("execute_llm_sql", {})


@unittest.skipUnless(
    TEST_DSN,
    "set DBGUARD_TEST_POSTGRES_DSN to an isolated PostgreSQL database",
)
class PostgresExecutorIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admin_dsn = TEST_DSN
        with psycopg2.connect(cls.admin_dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT current_database()")
                cls.database_name = cursor.fetchone()[0]

    def _create_schema(self, schema_name, *, public_access=False):
        with psycopg2.connect(self.admin_dsn) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL("CREATE SCHEMA {}").format(
                        sql.Identifier(schema_name)
                    )
                )
                if public_access:
                    cursor.execute(
                        sql.SQL(
                            "GRANT USAGE, CREATE ON SCHEMA {} TO PUBLIC"
                        ).format(sql.Identifier(schema_name))
                    )

    def _cleanup(self, schema_name, role_name=None):
        with psycopg2.connect(self.admin_dsn) as connection:
            with connection.cursor() as cursor:
                if role_name:
                    cursor.execute(
                        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)",
                        (role_name,),
                    )
                    if cursor.fetchone()[0]:
                        cursor.execute(
                            sql.SQL("DROP OWNED BY {}").format(
                                sql.Identifier(role_name)
                            )
                        )
                        cursor.execute(
                            sql.SQL("DROP ROLE {}").format(
                                sql.Identifier(role_name)
                            )
                        )
                cursor.execute(
                    sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                        sql.Identifier(schema_name)
                    )
                )

    def test_read_only_template_is_checked_against_real_database_state(self):
        token = uuid.uuid4().hex[:10]
        run_id = f"run-readonly-{token}"
        role_name = f"dbg_ro_{token}"
        schema_name = f"dbg_schema_{token}"
        parameters = {
            "role_name": role_name,
            "database_name": self.database_name,
            "schema_name": schema_name,
        }
        self._create_schema(schema_name)

        manager = PostgresAssessmentFixtureManager(self.admin_dsn, run_id)
        try:
            manager.prepare_before_hardening(parameters)
            with psycopg2.connect(self.admin_dsn) as connection:
                _apply_template(
                    connection,
                    "create_read_only_rule",
                    parameters,
                )
            context = manager.prepare_after_hardening()
            evidence = InMemoryEvidenceSink(run_id)
            executor = PostgresAssessmentExecutor(
                self.admin_dsn,
                context,
                evidence_sink=evidence,
            )

            report = AssessmentService().assess_template(
                "create_read_only_rule",
                1,
                parameters,
                executor,
            )

            result_by_id = {item.criterion_id: item for item in report.results}
            self.assertEqual(len(report.results), 13)
            self.assertEqual(len(evidence.artifacts), 13)
            self.assertEqual(
                result_by_id["REQ-READONLY-SELECT-FUTURE"].status,
                AssessmentStatus.FAIL,
            )
            self.assertEqual(
                report.suite_status[AssessmentSuite.BASELINE],
                AssessmentStatus.PASS,
            )
            self.assertEqual(
                report.suite_status[AssessmentSuite.REQUIREMENT],
                AssessmentStatus.FAIL,
            )
            self.assertEqual(report.overall_status, AssessmentStatus.FAIL)
            password = context.target_password.get_secret_value()
            self.assertTrue(
                all(password not in item.content for item in evidence.artifacts)
            )
        finally:
            manager.cleanup()
            self._cleanup(schema_name, role_name)

    def test_revoke_public_access_template_passes_real_acl_checks(self):
        token = uuid.uuid4().hex[:10]
        run_id = f"run-public-{token}"
        schema_name = f"dbg_public_{token}"
        parameters = {"schema_name": schema_name}
        self._create_schema(schema_name, public_access=True)

        manager = PostgresAssessmentFixtureManager(self.admin_dsn, run_id)
        try:
            manager.prepare_before_hardening(parameters)
            with psycopg2.connect(self.admin_dsn) as connection:
                _apply_template(
                    connection,
                    "revoke_public_access",
                    parameters,
                )
            context = manager.prepare_after_hardening()
            evidence = InMemoryEvidenceSink(run_id)
            executor = PostgresAssessmentExecutor(
                self.admin_dsn,
                context,
                evidence_sink=evidence,
            )

            report = AssessmentService().assess_template(
                "revoke_public_access",
                1,
                parameters,
                executor,
            )

            self.assertEqual(len(report.results), 3)
            self.assertEqual(len(evidence.artifacts), 3)
            self.assertTrue(
                all(item.status == AssessmentStatus.PASS for item in report.results)
            )
            self.assertEqual(
                report.baseline_catalog_status,
                BaselineCatalogStatus.NOT_READY,
            )
            self.assertEqual(report.overall_status, AssessmentStatus.UNKNOWN)
        finally:
            manager.cleanup()
            self._cleanup(schema_name)


if __name__ == "__main__":
    unittest.main()
