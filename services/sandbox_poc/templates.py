"""Exact approved-template lookup; the execution layer never receives this DSN."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from app.services.template_service import safe_render_template

from .shared import ContractError


@dataclass(frozen=True)
class ApprovedTemplate:
    registry_name: str
    version: int
    sql: str
    sha256: str
    approved_by: str
    evidence: tuple[dict, ...]

    def render(self) -> str:
        if self.registry_name != "set_config_parameter" or self.version < 1:
            raise ContractError("Unsupported template identity")
        if not self.approved_by or not self.evidence:
            raise ContractError("Approved template and evidence are required")
        if hashlib.sha256(self.sql.encode()).hexdigest() != self.sha256:
            raise ContractError("Template content does not match the pinned hash")
        success, sql, error = safe_render_template(
            "set_config_parameter", self.sql,
            {"param_name": "log_connections", "param_value": "on"})
        if not success:
            raise ContractError(error)
        return sql

    def identity(self) -> dict:
        return {"registry_name": self.registry_name, "version": self.version,
                "sha256": self.sha256, "approved_by": self.approved_by,
                "evidence": list(self.evidence)}


def from_registry(database_url: str, version: int, sha256: str,
                  evidence_refs: list[str], environment: str = "dev", *,
                  evidence_pins: list[dict] | None = None) -> ApprovedTemplate:
    """Read exact approved content. Never writes to the DBGuard/pgvector DB."""
    import psycopg2

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
            cur.execute("""SELECT sql_template, template_hash, approved_by, pg_version
                FROM templates WHERE template_name = %s AND version = %s
                AND template_hash = %s AND status = 'active' AND approved_by IS NOT NULL""",
                        ("set_config_parameter", version, sha256))
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
                if doc is None or not doc[2]:
                    raise ContractError(f"Exact approved applicable evidence unavailable: {ref}")
                if ref in pins and (doc[1] != pins[ref]["version"] or doc[2] != pins[ref]["sha256"]):
                    raise ContractError(f"Approved evidence version/hash mismatch: {ref}")
                evidence.append(dict(zip(("document_id", "version", "sha256", "approved_by"), doc)))
        template = ApprovedTemplate("set_config_parameter", version, row[0], row[1],
                                    row[2], tuple(evidence))
        template.render()
        return template
    finally:
        conn.close()
