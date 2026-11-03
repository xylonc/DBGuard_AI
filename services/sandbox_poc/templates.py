"""Exact approved-template lookup; the execution layer never receives this DSN."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from app.services.template_service import safe_render_template

from .handoff import OBJECT_TEMPLATE_NAMES, SETTING_TEMPLATE_PATTERN, TEMPLATE_NAME_PATTERN
from .shared import ContractError

# Fixed probe parameters: from_registry renders a per-object template with these
# (both actions) to prove the approved content renders under its schema. Never run.
OBJECT_TEMPLATE_PROBES = {
    "role_connection_limit": {"role_name": "dbguard_probe", "connection_limit": 1},
    "role_drop_attribute": {"role_name": "dbguard_probe", "attribute": "CREATEDB"},
    "role_nologin": {"role_name": "dbguard_probe"},
    "function_security_invoker": {"schema_name": "public", "function_name": "dbguard_probe",
                                  "arg_types": ["integer"]},
    "function_revoke_public_execute": {"schema_name": "public", "function_name": "dbguard_probe",
                                       "arg_types": ["integer"]},
    "table_revoke_dml": {"schema_name": "public", "table_name": "dbguard_probe", "grantee": None,
                         "privileges": ["INSERT"], "grant_option": False},
}


@dataclass(frozen=True)
class ApprovedTemplate:
    registry_name: str
    version: int
    sql: str
    sha256: str
    approved_by: str
    evidence: tuple[dict, ...]
    risk_level: str | None = None

    def _verified(self) -> None:
        if not self.approved_by.strip() or not self.evidence:
            raise ContractError("Approved template and evidence are required")
        if hashlib.sha256(self.sql.encode()).hexdigest() != self.sha256:
            raise ContractError("Template content does not match the pinned hash")

    def render(self, name="log_connections", value="on") -> str:
        """Setting fixes only (set_config_parameter and its __<variant> alternatives)."""
        if not re.fullmatch(SETTING_TEMPLATE_PATTERN, self.registry_name) or self.version < 1:
            raise ContractError("Unsupported template identity")
        self._verified()
        success, sql, error = safe_render_template(
            "set_config_parameter", self.sql,
            {"param_name": name, "param_value": value})
        if not success:
            raise ContractError(error)
        return sql

    def render_object(self, params: dict) -> str:
        """A Wave 2a per-object template with schema-validated parameters.

        Callers pass parameters from object_fixes (evidence-derived), never from a
        request; the registry name selects the strict schema in TEMPLATE_PARAM_SCHEMAS.
        """
        if self.registry_name not in OBJECT_TEMPLATE_NAMES or self.version < 1:
            raise ContractError("Unsupported template identity")
        self._verified()
        success, sql, error = safe_render_template(self.registry_name, self.sql, dict(params))
        if not success:
            raise ContractError(error)
        return sql

    def probe(self) -> None:
        """Render once with fixed probe values to prove the content fits its schema."""
        if self.registry_name in OBJECT_TEMPLATE_NAMES:
            for action in ("apply", "rollback"):
                self.render_object({**OBJECT_TEMPLATE_PROBES[self.registry_name], "action": action})
        else:
            self.render()

    def identity(self) -> dict:
        return {"registry_name": self.registry_name, "version": self.version,
                "sha256": self.sha256, "approved_by": self.approved_by,
                "evidence": list(self.evidence), "risk_level": self.risk_level}


def from_registry(database_url: str, version: int, sha256: str,
                  evidence_refs: list[str], environment: str = "dev", *,
                  evidence_pins: list[dict] | None = None, registry_name: str = "set_config_parameter") -> ApprovedTemplate:
    """Read exact approved content. Never writes to the DBGuard/pgvector DB."""
    import psycopg2

    if not isinstance(registry_name, str) or not re.fullmatch(TEMPLATE_NAME_PATTERN, registry_name):
        raise ContractError("Template name is outside the reviewed allowlist")

    if not evidence_refs:
        raise ContractError("At least one exact approved RAG document ID is required")
    pins = {entry["document_id"]: entry for entry in evidence_pins or []}
    if evidence_pins is not None and (set(pins) != set(evidence_refs) or len(pins) != len(evidence_pins)):
        raise ContractError("Evidence pins must match requested document IDs exactly")
    conn = psycopg2.connect(database_url, connect_timeout=10)
    try:
        conn.set_session(readonly=True, isolation_level="REPEATABLE READ")
        with conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '10s'")
            cur.execute("""SELECT sql_template, template_hash, approved_by, pg_version, risk_level
                FROM templates WHERE template_name = %s AND version = %s
                AND template_hash = %s AND status = 'active' AND approved_by IS NOT NULL""",
                        (registry_name, version, sha256))
            row = cur.fetchone()
            if row is None:
                raise ContractError("Exact approved template version/hash not found")
            supported = row[3] == "17" or (isinstance(row[3], str) and row[3].endswith("+")
                                           and row[3][:-1].isdigit() and int(row[3][:-1]) <= 17)
            if not supported:
                raise ContractError("Template is not explicitly applicable to PostgreSQL 17")
            evidence = []
            for ref in evidence_refs:
                cur.execute("""SELECT document_id, version, document_hash, approved_by
                    FROM knowledge_documents WHERE document_id = %s AND status = 'active'
                    AND approved_by IS NOT NULL AND effective_date <= NOW()
                    AND (expiry_date IS NULL OR expiry_date > NOW())
                    AND ('17' = ANY(postgresql_versions) OR 'all' = ANY(postgresql_versions))
                    AND (%s = ANY(environment_applicability) OR 'all' = ANY(environment_applicability))""",
                            (ref, environment))
                doc = cur.fetchone()
                if doc is None or not doc[2] or not doc[3].strip():
                    raise ContractError(f"Exact approved applicable evidence unavailable: {ref}")
                if ref in pins and (doc[1] != pins[ref]["version"] or doc[2] != pins[ref]["sha256"]):
                    raise ContractError(f"Approved evidence version/hash mismatch: {ref}")
                evidence.append(dict(zip(("document_id", "version", "sha256", "approved_by"), doc)))
        template = ApprovedTemplate(registry_name, version, row[0], row[1],
                                    row[2], tuple(evidence), row[4] if len(row)>4 else None)
        template.probe()
        return template
    finally:
        conn.close()


def export_reference(database_url: str, version: int, evidence_refs: list[str],
                     environment: str = "dev", *, registry_name: str = "set_config_parameter"):
    """Read exact identities, then verify their active approvals and applicability.

    Does not choose a latest version or approve content. A second pinned read
    rejects content changed between discovery and verification. Execution reads
    the registry again, so this reference is not an execution authorization.
    """
    import psycopg2
    from .handoff import TemplateReference

    if not isinstance(registry_name, str) or not re.fullmatch(TEMPLATE_NAME_PATTERN, registry_name):
        raise ContractError("Template name is outside the reviewed allowlist")
    if type(version) is not int or version < 1:
        raise ContractError("An explicit positive template version is required")
    if not evidence_refs or len(set(evidence_refs)) != len(evidence_refs):
        raise ContractError("Explicit unique evidence document IDs are required")
    conn = psycopg2.connect(database_url, connect_timeout=10)
    try:
        conn.set_session(readonly=True, isolation_level="REPEATABLE READ")
        with conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '10s'")
            cur.execute("""SELECT template_hash FROM templates
                WHERE template_name = %s AND version = %s AND status = 'active'
                AND approved_by IS NOT NULL""", (registry_name, version))
            row = cur.fetchone()
            if row is None:
                raise ContractError("Requested approved template version is unavailable")
            pins = []
            for ref in evidence_refs:
                cur.execute("""SELECT document_id, version, document_hash
                    FROM knowledge_documents WHERE document_id = %s
                    AND status = 'active' AND approved_by IS NOT NULL""", (ref,))
                doc = cur.fetchone()
                if doc is None:
                    raise ContractError(f"Requested approved evidence is unavailable: {ref}")
                pins.append(dict(zip(("document_id", "version", "sha256"), doc)))
            reference = TemplateReference(registry_name=registry_name, version=version, sha256=row[0],
                                          evidence=pins, environment=environment)
    finally:
        conn.close()
    template = from_registry(database_url, version, reference.sha256, evidence_refs,
                             environment, evidence_pins=pins, registry_name=registry_name)
    return reference, template


def approved_object_template_versions(database_url: str) -> dict[str, int | None]:
    """Highest active, human-approved version of each per-object fix template.

    Read-only display hint for the fix plan, so the UI sends a version per
    proposal. It authorizes nothing: preparing a run still pins the exact
    version and hash through export_reference/from_registry. A template with no
    approved version maps to None.
    """
    import psycopg2

    names = sorted(OBJECT_TEMPLATE_NAMES)
    conn = psycopg2.connect(database_url, connect_timeout=10)
    try:
        conn.set_session(readonly=True, isolation_level="REPEATABLE READ")
        with conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = '10s'")
            cur.execute("""SELECT template_name, max(version) FROM templates
                WHERE template_name = ANY(%s) AND status = 'active' AND approved_by IS NOT NULL
                GROUP BY template_name""", (names,))
            found = {name: version for name, version in cur.fetchall()}
    finally:
        conn.close()
    return {name: found.get(name) if type(found.get(name)) is int else None for name in names}
