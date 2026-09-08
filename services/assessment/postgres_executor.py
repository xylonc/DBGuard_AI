"""Restricted implementations of DBGuard's allowlisted PostgreSQL checks."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

import psycopg2
from psycopg2 import sql
from psycopg2.extensions import parse_dsn

from services.assessment.definition import validate_postgresql_identifier
from services.assessment.evidence import EvidenceSink, InMemoryEvidenceSink
from services.assessment.fixtures import AssessmentFixtureContext
from services.assessment.models import (
    CheckObservation,
    EvidenceType,
    ObservationState,
)
from services.assessment.verifiers.read_only_role import (
    READ_ONLY_ROLE_VERIFIER_IDS,
)
from services.assessment.verifiers.revoke_public_access import (
    REVOKE_PUBLIC_ACCESS_VERIFIER_IDS,
)


class AssessmentVerifierNotAllowed(LookupError):
    """Raised when a caller requests anything outside the reviewed allowlist."""


class AssessmentContextMismatch(ValueError):
    """Raised when parameters differ from the prepared fixture context."""


class PostgresAssessmentExecutor:
    """Run fixed metadata and behavioural checks against an isolated twin.

    The class has no generic ``execute_sql`` method. Each verifier ID maps to a
    reviewed method containing fixed SQL. HERMES can select a registered
    criterion but cannot submit SQL through this boundary.
    """

    def __init__(
        self,
        admin_dsn: str,
        context: AssessmentFixtureContext,
        *,
        evidence_sink: EvidenceSink | None = None,
        connect_timeout_seconds: int = 5,
    ):
        if not admin_dsn:
            raise ValueError("admin_dsn is required")
        if not context.before_hardening_prepared or not context.after_hardening_prepared:
            raise ValueError(
                "assessment fixtures must be prepared before and after hardening"
            )
        if connect_timeout_seconds < 1 or connect_timeout_seconds > 30:
            raise ValueError("connect_timeout_seconds must be between 1 and 30")

        self._admin_dsn = admin_dsn
        self.context = context
        self.connect_timeout_seconds = connect_timeout_seconds
        self.evidence_sink = evidence_sink or InMemoryEvidenceSink(context.run_id)
        self._handlers: dict[str, Callable[[], CheckObservation]] = {
            "role_exists": self._role_exists,
            "role_can_connect_database": self._role_can_connect_database,
            "role_has_schema_usage": self._role_has_schema_usage,
            "role_can_select_existing_probe_table": self._select_existing,
            "role_can_select_future_probe_table": self._select_future,
            "role_can_insert_probe_table": self._insert_existing,
            "role_can_update_probe_table": self._update_existing,
            "role_can_delete_probe_table": self._delete_existing,
            "role_can_truncate_probe_table": self._truncate_existing,
            "role_can_create_in_schema": self._create_in_schema,
            "role_is_superuser": self._role_is_superuser,
            "role_can_create_database": self._role_can_create_database,
            "role_can_create_role": self._role_can_create_role,
            "public_has_schema_create": self._public_has_schema_create,
            "public_has_schema_usage": self._public_has_schema_usage,
            "schema_owner_has_schema_usage": self._schema_owner_has_usage,
        }
        approved = READ_ONLY_ROLE_VERIFIER_IDS | REVOKE_PUBLIC_ACCESS_VERIFIER_IDS
        if set(self._handlers) != approved:
            raise RuntimeError("executor handlers do not match the reviewed allowlist")

        parsed = parse_dsn(admin_dsn)
        self._admin_password = parsed.get("password")

    @property
    def verifier_ids(self) -> frozenset[str]:
        return frozenset(self._handlers)

    def run_check(
        self,
        verifier_id: str,
        parameters: dict[str, Any],
    ) -> CheckObservation:
        try:
            handler = self._handlers[verifier_id]
        except KeyError as exc:
            raise AssessmentVerifierNotAllowed(
                f"verifier_id {verifier_id!r} is not approved"
            ) from exc
        self._validate_parameters_match_context(parameters)
        return handler()

    def _validate_parameters_match_context(self, parameters: dict[str, Any]) -> None:
        allowed = {"role_name", "database_name", "schema_name"}
        if set(parameters) - allowed:
            raise AssessmentContextMismatch("unsupported assessment parameters")

        schema_name = validate_postgresql_identifier(
            parameters.get("schema_name", "public")
        )
        if schema_name != self.context.schema_name:
            raise AssessmentContextMismatch(
                "schema_name differs from the prepared fixture context"
            )

        role_name = parameters.get("role_name")
        database_name = parameters.get("database_name")
        if role_name is not None:
            role_name = validate_postgresql_identifier(role_name)
            if database_name is None:
                raise AssessmentContextMismatch(
                    "database_name is required when role_name is provided"
                )
            database_name = validate_postgresql_identifier(database_name)
        if role_name != self.context.role_name:
            raise AssessmentContextMismatch(
                "role_name differs from the prepared fixture context"
            )
        if database_name is not None and database_name != self.context.database_name:
            raise AssessmentContextMismatch(
                "database_name differs from the prepared fixture context"
            )

    def _admin_connect(self):
        return psycopg2.connect(
            self._admin_dsn,
            connect_timeout=self.connect_timeout_seconds,
            application_name="dbguard-assessment-executor",
        )

    def _target_connect(self):
        context = self._require_role_context()
        parsed = parse_dsn(self._admin_dsn)
        permitted_keys = {
            "host",
            "hostaddr",
            "port",
            "sslmode",
            "sslrootcert",
            "sslcert",
            "sslkey",
            "sslcrl",
            "gssencmode",
            "channel_binding",
            "target_session_attrs",
        }
        connection_parameters = {
            key: value
            for key, value in parsed.items()
            if key in permitted_keys
        }
        connection_parameters.update(
            {
                "dbname": context.database_name,
                "user": context.role_name,
                "password": context.target_password.get_secret_value(),
                "connect_timeout": self.connect_timeout_seconds,
                "application_name": "dbguard-assessment-target",
            }
        )
        return psycopg2.connect(**connection_parameters)

    def _require_role_context(self) -> AssessmentFixtureContext:
        context = self.context
        if context.role_name is None or context.target_password is None:
            raise AssessmentContextMismatch(
                "this verifier requires read-only-role fixtures"
            )
        return context

    def _sanitize(self, value: Any) -> str:
        text = str(value)
        secrets_to_remove = [self._admin_password]
        if self.context.target_password is not None:
            secrets_to_remove.append(
                self.context.target_password.get_secret_value()
            )
        for secret in secrets_to_remove:
            if secret:
                text = text.replace(secret, "[REDACTED]")
        text = re.sub(
            r"(?i)(password\s*[=:]\s*)([^\s,;]+)",
            r"\1[REDACTED]",
            text,
        )
        return text[:4000]

    def _observation(
        self,
        *,
        verifier_id: str,
        evidence_type: EvidenceType,
        observed_value: bool,
        detail: str,
        evidence_content: dict[str, Any],
    ) -> CheckObservation:
        sanitized_detail = self._sanitize(detail)
        sanitized_content = self._sanitize(
            json.dumps(evidence_content, sort_keys=True, default=str)
        )
        evidence = self.evidence_sink.record(
            verifier_id=verifier_id,
            evidence_type=evidence_type,
            description=sanitized_detail,
            content=sanitized_content,
        )
        return CheckObservation(
            state=ObservationState.OBSERVED,
            observed_value=observed_value,
            detail=sanitized_detail,
            evidence=[evidence],
        )

    def _error(self, verifier_id: str, detail: str) -> CheckObservation:
        return CheckObservation(
            state=ObservationState.ERROR,
            detail=self._sanitize(f"{verifier_id}: {detail}"),
        )

    def _query_boolean(
        self,
        verifier_id: str,
        query: str,
        parameters: tuple[Any, ...],
        description: str,
    ) -> CheckObservation:
        try:
            with self._admin_connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(query, parameters)
                    row = cursor.fetchone()
            if row is None or not isinstance(row[0], bool):
                return self._error(
                    verifier_id,
                    "fixed query did not return one Boolean value",
                )
            observed_value = row[0]
            return self._observation(
                verifier_id=verifier_id,
                evidence_type=EvidenceType.QUERY_OUTPUT,
                observed_value=observed_value,
                detail=f"{description}: {observed_value}",
                evidence_content={
                    "verifier_id": verifier_id,
                    "observed_value": observed_value,
                    "database": self.context.database_name,
                },
            )
        except Exception as exc:
            return self._error(verifier_id, f"fixed query failed: {exc}")

    def _server_is_reachable(self) -> tuple[bool, str]:
        try:
            with self._admin_connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    row = cursor.fetchone()
            return row == (1,), "administrator health query succeeded"
        except Exception as exc:
            return False, self._sanitize(exc)

    def _target_operation(
        self,
        verifier_id: str,
        operation: sql.Composable,
        description: str,
        parameters: tuple[Any, ...] = (),
    ) -> CheckObservation:
        reachable, health_detail = self._server_is_reachable()
        if not reachable:
            return self._error(
                verifier_id,
                f"twin database is unavailable: {health_detail}",
            )

        connection = None
        try:
            connection = self._target_connect()
            connection.autocommit = False
            with connection.cursor() as cursor:
                cursor.execute(operation, parameters)
                row_count = cursor.rowcount
            connection.rollback()
            return self._observation(
                verifier_id=verifier_id,
                evidence_type=EvidenceType.COMMAND_OUTPUT,
                observed_value=True,
                detail=f"{description}: operation was allowed",
                evidence_content={
                    "verifier_id": verifier_id,
                    "result": "allowed",
                    "row_count": row_count,
                    "database": self.context.database_name,
                    "role": self.context.role_name,
                },
            )
        except psycopg2.Error as exc:
            if connection is not None:
                connection.rollback()
            if exc.pgcode == "42501":
                return self._observation(
                    verifier_id=verifier_id,
                    evidence_type=EvidenceType.COMMAND_OUTPUT,
                    observed_value=False,
                    detail=f"{description}: operation was denied",
                    evidence_content={
                        "verifier_id": verifier_id,
                        "result": "denied",
                        "sqlstate": exc.pgcode,
                        "message": self._sanitize(exc),
                        "database": self.context.database_name,
                        "role": self.context.role_name,
                    },
                )
            return self._error(
                verifier_id,
                f"operation failed without a permission-denied result: {exc}",
            )
        except Exception as exc:
            if connection is not None:
                connection.rollback()
            return self._error(verifier_id, f"operation failed: {exc}")
        finally:
            if connection is not None:
                connection.close()

    def _role_exists(self) -> CheckObservation:
        context = self._require_role_context()
        return self._query_boolean(
            "role_exists",
            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)",
            (context.role_name,),
            "Requested role exists",
        )

    def _role_can_connect_database(self) -> CheckObservation:
        verifier_id = "role_can_connect_database"
        reachable, health_detail = self._server_is_reachable()
        if not reachable:
            return self._error(
                verifier_id,
                f"twin database is unavailable: {health_detail}",
            )
        connection = None
        try:
            connection = self._target_connect()
            with connection.cursor() as cursor:
                cursor.execute("SELECT current_database(), current_user")
                row = cursor.fetchone()
            connected = row == (
                self.context.database_name,
                self.context.role_name,
            )
            return self._observation(
                verifier_id=verifier_id,
                evidence_type=EvidenceType.COMMAND_OUTPUT,
                observed_value=connected,
                detail=(
                    "Target role established an authenticated database connection"
                    if connected
                    else "Connection identity did not match the requested role/database"
                ),
                evidence_content={
                    "verifier_id": verifier_id,
                    "result": "connected" if connected else "identity_mismatch",
                    "database": row[0] if row else None,
                    "role": row[1] if row else None,
                },
            )
        except psycopg2.Error as exc:
            return self._observation(
                verifier_id=verifier_id,
                evidence_type=EvidenceType.COMMAND_OUTPUT,
                observed_value=False,
                detail="Target role could not establish a database connection",
                evidence_content={
                    "verifier_id": verifier_id,
                    "result": "connection_denied",
                    "sqlstate": exc.pgcode,
                    "message": self._sanitize(exc),
                    "database": self.context.database_name,
                    "role": self.context.role_name,
                },
            )
        finally:
            if connection is not None:
                connection.close()

    def _role_has_schema_usage(self) -> CheckObservation:
        context = self._require_role_context()
        return self._query_boolean(
            "role_has_schema_usage",
            """
            SELECT COALESCE(
                (SELECT has_schema_privilege(oid, %s, 'USAGE')
                 FROM pg_roles WHERE rolname = %s),
                false
            )
            """,
            (context.schema_name, context.role_name),
            "Role has effective schema USAGE",
        )

    def _select_existing(self) -> CheckObservation:
        context = self._require_role_context()
        return self._target_operation(
            "role_can_select_existing_probe_table",
            sql.SQL("SELECT id, payload FROM {}.{} ORDER BY id LIMIT 1").format(
                sql.Identifier(context.schema_name),
                sql.Identifier(context.existing_probe_table),
            ),
            "SELECT from the existing probe table",
        )

    def _select_future(self) -> CheckObservation:
        context = self._require_role_context()
        return self._target_operation(
            "role_can_select_future_probe_table",
            sql.SQL("SELECT id, payload FROM {}.{} ORDER BY id LIMIT 1").format(
                sql.Identifier(context.schema_name),
                sql.Identifier(context.future_probe_table),
            ),
            "SELECT from the future probe table",
        )

    def _insert_existing(self) -> CheckObservation:
        context = self._require_role_context()
        return self._target_operation(
            "role_can_insert_probe_table",
            sql.SQL("INSERT INTO {}.{} (id, payload) VALUES (%s, %s)").format(
                sql.Identifier(context.schema_name),
                sql.Identifier(context.existing_probe_table),
            ),
            "INSERT into the existing probe table",
            (900001, "dbguard-write-probe"),
        )

    def _update_existing(self) -> CheckObservation:
        context = self._require_role_context()
        return self._target_operation(
            "role_can_update_probe_table",
            sql.SQL("UPDATE {}.{} SET payload = %s WHERE id = %s").format(
                sql.Identifier(context.schema_name),
                sql.Identifier(context.existing_probe_table),
            ),
            "UPDATE of the existing probe table",
            ("dbguard-write-probe", 1),
        )

    def _delete_existing(self) -> CheckObservation:
        context = self._require_role_context()
        return self._target_operation(
            "role_can_delete_probe_table",
            sql.SQL("DELETE FROM {}.{} WHERE id = %s").format(
                sql.Identifier(context.schema_name),
                sql.Identifier(context.existing_probe_table),
            ),
            "DELETE from the existing probe table",
            (1,),
        )

    def _truncate_existing(self) -> CheckObservation:
        context = self._require_role_context()
        return self._target_operation(
            "role_can_truncate_probe_table",
            sql.SQL("TRUNCATE TABLE {}.{}").format(
                sql.Identifier(context.schema_name),
                sql.Identifier(context.existing_probe_table),
            ),
            "TRUNCATE of the existing probe table",
        )

    def _create_in_schema(self) -> CheckObservation:
        context = self._require_role_context()
        return self._target_operation(
            "role_can_create_in_schema",
            sql.SQL("CREATE TABLE {}.{} (id integer)").format(
                sql.Identifier(context.schema_name),
                sql.Identifier(context.create_probe_table),
            ),
            "CREATE TABLE in the requested schema",
        )

    def _role_flag(self, verifier_id: str, column_name: str, description: str):
        context = self._require_role_context()
        if column_name not in {"rolsuper", "rolcreatedb", "rolcreaterole"}:
            raise AssessmentVerifierNotAllowed("role flag is not allowlisted")
        query = sql.SQL(
            "SELECT COALESCE((SELECT {} FROM pg_roles WHERE rolname = %s), false)"
        ).format(sql.Identifier(column_name))
        try:
            with self._admin_connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(query, (context.role_name,))
                    row = cursor.fetchone()
            if row is None or not isinstance(row[0], bool):
                return self._error(verifier_id, "role flag query returned no Boolean")
            return self._observation(
                verifier_id=verifier_id,
                evidence_type=EvidenceType.QUERY_OUTPUT,
                observed_value=row[0],
                detail=f"{description}: {row[0]}",
                evidence_content={
                    "verifier_id": verifier_id,
                    "observed_value": row[0],
                    "role": context.role_name,
                },
            )
        except Exception as exc:
            return self._error(verifier_id, f"role flag query failed: {exc}")

    def _role_is_superuser(self) -> CheckObservation:
        return self._role_flag(
            "role_is_superuser", "rolsuper", "Role is a superuser"
        )

    def _role_can_create_database(self) -> CheckObservation:
        return self._role_flag(
            "role_can_create_database", "rolcreatedb", "Role has CREATEDB"
        )

    def _role_can_create_role(self) -> CheckObservation:
        return self._role_flag(
            "role_can_create_role", "rolcreaterole", "Role has CREATEROLE"
        )

    def _public_privilege(
        self,
        verifier_id: str,
        privilege: str,
    ) -> CheckObservation:
        return self._query_boolean(
            verifier_id,
            """
            SELECT EXISTS (
                SELECT 1
                FROM pg_namespace AS namespace
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(
                        namespace.nspacl,
                        acldefault('n', namespace.nspowner)
                    )
                ) AS privilege
                WHERE namespace.nspname = %s
                  AND privilege.grantee = 0
                  AND privilege.privilege_type = %s
            )
            """,
            (self.context.schema_name, privilege),
            f"PUBLIC has effective schema {privilege}",
        )

    def _public_has_schema_create(self) -> CheckObservation:
        return self._public_privilege(
            "public_has_schema_create", "CREATE"
        )

    def _public_has_schema_usage(self) -> CheckObservation:
        return self._public_privilege(
            "public_has_schema_usage", "USAGE"
        )

    def _schema_owner_has_usage(self) -> CheckObservation:
        return self._query_boolean(
            "schema_owner_has_schema_usage",
            """
            SELECT has_schema_privilege(nspowner, oid, 'USAGE')
            FROM pg_namespace
            WHERE nspname = %s
            """,
            (self.context.schema_name,),
            "Schema owner retains effective USAGE",
        )
