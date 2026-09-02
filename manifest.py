"""
DBGuardAI — Schema definition for the SQL collector bundle.

This file defines the pydantic models that the collector envelope and sections
must conform to.  It is a stripped-down subset of apps/api/app/models.py
(Revamp branch) — only the types actually used by the three-CIS-control
collector.

Usage (development):
    python collector/test/validate_schema.py <bundle-dir>
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


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


# ─── Envelope ────────────────────────────────────────────────────────────

class Envelope(BaseModel):
    schema_version: str = "0.2.0"
    collector_version: str
    collected_at: str
    target_id: str
    server_version_full: str
    server_version_num: Optional[int]
    current_user: Optional[str]
    status: CollectionStatus
    gaps: List[Dict[str, str]] = Field(default_factory=list)
    redactions: List[Dict[str, str]] = Field(default_factory=list)


# ─── Section models for the three CIS controls ──────────────────────────

class PostgreSQLSetting(BaseModel):
    """A single row from pg_settings."""
    name: str
    setting: str
    source: Optional[str] = None
    sourcefile: Optional[str] = None
    sourceline: Optional[int] = None
    context: Optional[str] = None
    pending_restart: Optional[bool] = None


class PublicSchemaACL(BaseModel):
    """ACL on public schema, per database."""
    database: str
    schema_name: str = "public"
    owner: Optional[str] = None
    acl: Optional[str] = None  # raw aclitem array text
    public_has_create: bool  # derived: does PUBLIC hold CREATE?


class RoleEntry(BaseModel):
    """Per-role entry with login flag and derived password type."""
    rolname: str
    rolcanlogin: bool
    password_type: str  # scram-sha-256 | md5 | none | unknown
    # Hash is never collected (S0).


# ─── Section data ────────────────────────────────────────────────────────

class LogConnectionsSetting(BaseModel):
    """§ CIS 5.1 — log_connections setting."""
    setting: Optional[PostgreSQLSetting] = None


class PublicSchemaAccess(BaseModel):
    """§ CIS 5.2 — CREATE on schema public not granted to PUBLIC."""
    databases: List[PublicSchemaACL] = Field(default_factory=list)


class PasswordStorage(BaseModel):
    """§ CIS 5.3 — No role uses md5 password storage."""
    roles: List[RoleEntry] = Field(default_factory=list)


# ─── Bundle validation ──────────────────────────────────────────────────

def validate_envelope(data: Dict[str, Any]) -> List[str]:
    """Validate envelope JSON against the schema. Returns list of errors."""
    errors: List[str] = []
    try:
        Envelope.model_validate(data)
    except Exception as exc:
        errors.append(f"Envelope validation failed: {exc}")
    return errors
