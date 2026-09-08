"""Synthetic fixture lifecycle for one isolated PostgreSQL assessment cycle."""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

import psycopg2
from psycopg2 import sql
from psycopg2.extensions import parse_dsn
from pydantic import SecretStr

from services.assessment.definition import validate_postgresql_identifier


class AssessmentFixtureError(RuntimeError):
    """Raised when safe assessment fixtures cannot be prepared or cleaned up."""


@dataclass(frozen=True)
class AssessmentFixtureContext:
    """Names and ephemeral credentials owned by one assessment run."""

    run_id: str
    database_name: str
    schema_name: str
    role_name: str | None = None
    existing_probe_table: str | None = None
    future_probe_table: str | None = None
    create_probe_table: str | None = None
    target_password: SecretStr | None = field(default=None, repr=False)
    before_hardening_prepared: bool = False
    after_hardening_prepared: bool = False


class PostgresAssessmentFixtureManager:
    """Create controlled probe objects before and after trusted SQL is applied.

    The manager never applies a hardening proposal. The future twin controller
    owns that boundary and calls ``prepare_after_hardening`` only after the
    trusted compiler's SQL has succeeded.
    """

    _RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

    def __init__(
        self,
        admin_dsn: str,
        run_id: str,
        *,
        connect_timeout_seconds: int = 5,
    ):
        if not admin_dsn:
            raise ValueError("admin_dsn is required")
        if not self._RUN_ID_PATTERN.fullmatch(run_id):
            raise ValueError("run_id contains unsupported characters")
        if connect_timeout_seconds < 1 or connect_timeout_seconds > 30:
            raise ValueError("connect_timeout_seconds must be between 1 and 30")

        self._admin_dsn = admin_dsn
        self.run_id = run_id
        self.connect_timeout_seconds = connect_timeout_seconds
        self._context: AssessmentFixtureContext | None = None

    @property
    def context(self) -> AssessmentFixtureContext:
        if self._context is None:
            raise AssessmentFixtureError("fixtures have not been prepared")
        return self._context

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.cleanup()
        return False

    def _connect(self):
        return psycopg2.connect(
            self._admin_dsn,
            connect_timeout=self.connect_timeout_seconds,
            application_name="dbguard-assessment-fixtures",
        )

    def _database_identity(self) -> tuple[str, str]:
        with self._connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT current_database(), current_user")
                row = cursor.fetchone()
        if row is None:
            raise AssessmentFixtureError("could not read twin database identity")
        return str(row[0]), str(row[1])

    @staticmethod
    def _validated_parameters(parameters: dict[str, Any]) -> tuple[str | None, str | None, str]:
        allowed = {"role_name", "database_name", "schema_name"}
        extra = set(parameters) - allowed
        if extra:
            raise AssessmentFixtureError(
                f"unsupported fixture parameters: {sorted(extra)!r}"
            )

        schema_name = validate_postgresql_identifier(
            parameters.get("schema_name", "public")
        )
        role_name = parameters.get("role_name")
        database_name = parameters.get("database_name")
        if role_name is not None:
            role_name = validate_postgresql_identifier(role_name)
            if database_name is None:
                raise AssessmentFixtureError(
                    "database_name is required when role_name is provided"
                )
            database_name = validate_postgresql_identifier(database_name)
        elif database_name is not None:
            raise AssessmentFixtureError(
                "database_name cannot be provided without role_name"
            )
        return role_name, database_name, schema_name

    def prepare_before_hardening(
        self,
        parameters: dict[str, Any],
    ) -> AssessmentFixtureContext:
        if self._context is not None:
            raise AssessmentFixtureError("fixtures are already prepared")

        role_name, requested_database, schema_name = self._validated_parameters(
            parameters
        )
        current_database, admin_user = self._database_identity()
        if requested_database is not None and requested_database != current_database:
            raise AssessmentFixtureError(
                "the requested database does not match the connected twin database"
            )
        if role_name == admin_user:
            raise AssessmentFixtureError(
                "the assessed role cannot be the twin administrator"
            )

        suffix = hashlib.sha256(self.run_id.encode("utf-8")).hexdigest()[:12]
        existing_table = f"dbg_existing_{suffix}" if role_name else None
        future_table = f"dbg_future_{suffix}" if role_name else None
        create_table = f"dbg_create_{suffix}" if role_name else None
        target_password = SecretStr(secrets.token_urlsafe(32)) if role_name else None

        try:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = %s)",
                        (schema_name,),
                    )
                    row = cursor.fetchone()
                    if row is None or not row[0]:
                        raise AssessmentFixtureError(
                            f"schema {schema_name!r} does not exist in the twin"
                        )
                    if existing_table is not None:
                        cursor.execute(
                            sql.SQL("DROP TABLE IF EXISTS {}.{}").format(
                                sql.Identifier(schema_name),
                                sql.Identifier(existing_table),
                            )
                        )
                        cursor.execute(
                            sql.SQL(
                                "CREATE TABLE {}.{} ("
                                "id integer PRIMARY KEY, payload text NOT NULL)"
                            ).format(
                                sql.Identifier(schema_name),
                                sql.Identifier(existing_table),
                            )
                        )
                        cursor.execute(
                            sql.SQL("INSERT INTO {}.{} VALUES (%s, %s)").format(
                                sql.Identifier(schema_name),
                                sql.Identifier(existing_table),
                            ),
                            (1, "existing-probe"),
                        )
        except AssessmentFixtureError:
            raise
        except Exception as exc:
            raise AssessmentFixtureError(
                f"failed to prepare pre-hardening fixtures: {exc}"
            ) from exc

        self._context = AssessmentFixtureContext(
            run_id=self.run_id,
            database_name=current_database,
            schema_name=schema_name,
            role_name=role_name,
            existing_probe_table=existing_table,
            future_probe_table=future_table,
            create_probe_table=create_table,
            target_password=target_password,
            before_hardening_prepared=True,
            after_hardening_prepared=False,
        )
        return self._context

    def prepare_after_hardening(self) -> AssessmentFixtureContext:
        context = self.context
        if context.after_hardening_prepared:
            raise AssessmentFixtureError("post-hardening fixtures are already prepared")

        try:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    if context.future_probe_table is not None:
                        cursor.execute(
                            sql.SQL("DROP TABLE IF EXISTS {}.{}").format(
                                sql.Identifier(context.schema_name),
                                sql.Identifier(context.future_probe_table),
                            )
                        )
                        cursor.execute(
                            sql.SQL(
                                "CREATE TABLE {}.{} ("
                                "id integer PRIMARY KEY, payload text NOT NULL)"
                            ).format(
                                sql.Identifier(context.schema_name),
                                sql.Identifier(context.future_probe_table),
                            )
                        )
                        cursor.execute(
                            sql.SQL("INSERT INTO {}.{} VALUES (%s, %s)").format(
                                sql.Identifier(context.schema_name),
                                sql.Identifier(context.future_probe_table),
                            ),
                            (1, "future-probe"),
                        )

                    if context.role_name and context.target_password:
                        cursor.execute(
                            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)",
                            (context.role_name,),
                        )
                        row = cursor.fetchone()
                        if row and row[0]:
                            cursor.execute(
                                sql.SQL("ALTER ROLE {} PASSWORD %s").format(
                                    sql.Identifier(context.role_name)
                                ),
                                (context.target_password.get_secret_value(),),
                            )
        except Exception as exc:
            raise AssessmentFixtureError(
                f"failed to prepare post-hardening fixtures: {exc}"
            ) from exc

        self._context = AssessmentFixtureContext(
            **{
                **context.__dict__,
                "after_hardening_prepared": True,
            }
        )
        return self._context

    def cleanup(self) -> None:
        context = self._context
        if context is None:
            return
        try:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    for table_name in (
                        context.existing_probe_table,
                        context.future_probe_table,
                        context.create_probe_table,
                    ):
                        if table_name is not None:
                            cursor.execute(
                                sql.SQL("DROP TABLE IF EXISTS {}.{}").format(
                                    sql.Identifier(context.schema_name),
                                    sql.Identifier(table_name),
                                )
                            )
                    if context.role_name:
                        cursor.execute(
                            "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %s)",
                            (context.role_name,),
                        )
                        row = cursor.fetchone()
                        if row and row[0]:
                            cursor.execute(
                                sql.SQL("ALTER ROLE {} PASSWORD NULL").format(
                                    sql.Identifier(context.role_name)
                                )
                            )
        except Exception as exc:
            raise AssessmentFixtureError(
                f"failed to clean assessment fixtures: {exc}"
            ) from exc
        finally:
            self._context = None
