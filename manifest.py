"""
DBGuardAI — Schema definition for the SQL collector bundle (v0.2).

This is the canonical schema file.  It must be committed to the repository
root and imported by collector/test/validate_schema.py.

It is intentionally separate from apps/api/app/models.py (the Python
collector) — that file and services/snapshot_collector/collect.py were
deleted in the three-CIS-control rewrite.

Usage (development):
    python3 collector/test/validate_schema.py <bundle-dir>
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


# ─── Enums ───────────────────────────────────────────────────────────────

class CollectionStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class RedactionClass(str, Enum):
    S0_NEVER_COLLECTED = "S0_NEVER_COLLECTED"
    S1_DERIVED = "S1_DERIVED"
    S2_SANITISED = "S2_SANITISED"
    S3_CONFIDENTIAL = "S3_CONFIDENTIAL"
    S4_VERBATIM_CONFIDENTIAL = "S4_VERBATIM_CONFIDENTIAL"


class GapReason(str, Enum):
    INSUFFICIENT_PRIVILEGE = "insufficient_privilege"
    NOT_APPLICABLE_PLATFORM = "not_applicable_platform"
    NOT_APPLICABLE_VERSION = "not_applicable_version"
    FILE_NOT_READABLE = "file_not_readable"
    COMMAND_UNAVAILABLE = "command_unavailable"
    REDACTED_BY_POLICY = "redacted_by_policy"
    ERROR = "error"


class ReplicationSource(str, Enum):
    UNKNOWN = "unknown"
    WAL_ARCHIVE = "wal_archive"
    LOGICAL = "logical"
    PHYSICAL = "physical"


# ─── Envelope ────────────────────────────────────────────────────────────

class Envelope(BaseModel):
    """Top-level bundle envelope."""
    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="0.2.0")
    collector_version: str
    collected_at: str
    target_id: str
    server_version_full: str
    server_version_num: Optional[int] = None
    current_user: Optional[str] = None
    status: CollectionStatus
    gaps: List[Dict[str, str]] = Field(default_factory=list)
    redactions: List[Dict[str, str]] = Field(default_factory=list)
    has_gap: bool = False  # derived: True when gaps is non-empty


# ─── Section models ─────────────────────────────────────────────────────

class PostgreSQLSetting(BaseModel):
    """A single row from pg_settings."""
    name: str
    setting: str
    source: str = "postgresql.conf"
    sourcefile: Optional[str] = None
    sourceline: Optional[int] = None
    context: Optional[str] = None
    pending_restart: Optional[bool] = None
    is_modifiable: bool = True


class PublicSchemaACL(BaseModel):
    """ACL on public schema, per database."""
    database: str
    schema_name: str = "public"
    owner: Optional[str] = None
    acl: Optional[str] = None  # raw aclitem array text
    public_has_create: bool


class RoleEntry(BaseModel):
    """Per-role entry with login flag and derived password type."""
    rolname: str
    rolcanlogin: bool
    password_type: str  # scram-sha-256 | md5 | none | unknown


class ReplicationMetadata(BaseModel):
    """Replication status (may be absent for standalone instances)."""
    model_config = ConfigDict(extra="forbid")

    replication_enabled: bool = False
    primary_conninfo: Optional[str] = None
    primary_slot_name: Optional[str] = None
    wal_level: str = "replica"
    max_wal_senders: int = 0


# ─── Section data ────────────────────────────────────────────────────────

class LogConnectionsSetting(BaseModel):
    """§ CIS 5.1 — log_connections setting."""
    model_config = ConfigDict(extra='forbid')

    setting: Optional[PostgreSQLSetting] = None


class PublicSchemaAccess(BaseModel):
    """§ CIS 5.2 — CREATE on schema public not granted to PUBLIC."""
    databases: List[PublicSchemaACL] = Field(default_factory=list)


class PasswordStorage(BaseModel):
    """§ CIS 5.3 — No role uses md5 password storage."""
    model_config = ConfigDict(extra="forbid")

    roles: List[RoleEntry] = Field(default_factory=list)


# ─── Bundle validation ──────────────────────────────────────────────────

def validate_envelope(data: Dict[str, Any]) -> List[str]:
    """Validate envelope JSON against the schema. Returns list of errors."""
    errors: List[str] = []
    try:
        env = Envelope.model_validate(data)
        env.has_gap = len(env.gaps) > 0
    except Exception as exc:
        errors.append(f"Envelope validation failed: {exc}")
    return errors
