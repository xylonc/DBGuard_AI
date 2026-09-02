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
from typing import Any, Dict, List, Optional, Pattern

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ─── Enums ───────────────────────────────────────────────────────────────

class CollectionStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class SanitisationClass(str, Enum):
    S0_NEVER_COLLECTED = "S0_NEVER_COLLECTED"
    S1_DERIVED = "S1_DERIVED"
    S2_SANITISED = "S2_SANITISED"
    S3_CONFIDENTIAL = "S3_CONFIDENTIAL"
    S4_VERBATIM_CONFIDENTIAL = "S4_VERBATIM_CONFIDENTIAL"


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
    password_type: str  # scram-sha-256 | md5 | none | plain


class HostInfo(BaseModel):
    """Information about the host where the collector ran."""
    hostname: Optional[str] = None
    os: Optional[str] = None
    architecture: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class ReplicationMetadata(BaseModel):
    """Replication status (may be absent for standalone instances)."""
    model_config = ConfigDict(extra="forbid")

    replication_enabled: bool = False
    primary_conninfo: Optional[str] = None
    primary_conninfo_parsed: Optional[Dict[str, str]] = Field(
        default=None,
        description="Parsed key=value pairs from primary_conninfo. "
                    "Any value containing 'password' is flagged by validator."
    )
    primary_slot_name: Optional[str] = None
    wal_level: str = "replica"
    max_wal_senders: int = 0

    @field_validator('primary_conninfo_parsed')
    @classmethod
    def validate_password_key(cls, v: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        """Reject primary_conninfo_parsed that contains password-containing keys."""
        if v is None:
            return v
        for key in v:
            if 'password' in key.lower():
                raise ValueError(
                    f"primary_conninfo_parsed contains key '{key}' with "
                    "password-like name — this is a security risk"
                )
        return v


# ─── Section data ────────────────────────────────────────────────────────

class LogConnectionsSetting(BaseModel):
    """§ CIS 5.1 — log_connections setting."""
    model_config = ConfigDict(extra='forbid')

    setting: Optional[PostgreSQLSetting] = None
    value_sanitised: bool = False  # True when the raw setting was redacted


class PublicSchemaAccess(BaseModel):
    """§ CIS 5.2 — CREATE on schema public not granted to PUBLIC."""
    databases: List[PublicSchemaACL] = Field(default_factory=list)


class PasswordStorage(BaseModel):
    """§ CIS 5.3 — No role uses md5 password storage."""
    model_config = ConfigDict(extra="forbid")

    roles: List[RoleEntry] = Field(default_factory=list)


# ─── Bundle constraints ──────────────────────────────────────────────────

sandbox_excluded_fields: List[str] = [
    "primary_conninfo",
    "primary_conninfo_parsed",
    "server_version_num",
    "snapshot_hash",
    "collector_version",
]
"""Fields that must never be scored from the sandbox because they
go false-green in a freshly-provisioned container."""


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
