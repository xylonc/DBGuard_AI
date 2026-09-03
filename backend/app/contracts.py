"""Pydantic v2 models for DBGuardAI evidence contracts.

Contract A – Postgres16EvidenceBundle
    Represents the JSON document emitted by collector/collect.sql.
    Every top-level section is modelled so downstream code has typed
    access to individual security facts (no dict[str, Any] collapse).

Contract B – CreateRunRequest / CreateRunResponse
    API wrapper.  The POST /api/v1/runs body carries {"target_evidence": <bundle>}.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

# ── envelope ────────────────────────────────────────────────────────────────


class CollectorEnvelope(BaseModel):
    schema_version: str
    collector_version: str
    collected_at: datetime
    target_id: str
    database: str
    collected_by: str
    is_superuser: Optional[bool]
    has_pg_monitor: Optional[bool]
    has_read_all_settings: Optional[bool]
    can_read_pg_authid: Optional[bool]
    deployment_type: str

    @field_validator("schema_version")
    @classmethod
    def schema_version_is_020(cls, v: str) -> str:
        if v != "0.2.0":
            raise ValueError(
                f"Unsupported schema version {v!r}; only 0.2.0 is accepted"
            )
        return v


# ── identity ────────────────────────────────────────────────────────────────


class PostgresIdentity(BaseModel):
    version_full: str
    server_version_num: int
    server_encoding: str
    lc_collate: str
    lc_ctype: str
    block_size: int
    wal_segment_size: Optional[str]
    data_checksums: Optional[str]
    data_directory: Optional[Any]
    system_identifier: Optional[Any]

    @field_validator("server_version_num")
    @classmethod
    def major_version_is_16(cls, v: int) -> int:
        major = v // 10000
        if major != 16:
            raise ValueError(
                f"PostgreSQL major version {major} detected; only 16 is supported "
                f"(received {v})"
            )
        return v


# ── settings ────────────────────────────────────────────────────────────────


class PostgresSetting(BaseModel):
    name: str
    setting: str
    unit: Optional[str]
    category: Optional[str]
    context: Optional[str]
    vartype: Optional[str]
    source: str
    sourcefile: Optional[str]
    sourceline: Optional[int]
    boot_val: Optional[str]
    reset_val: Optional[str]
    pending_restart: Optional[bool]
    sanitised: bool


# ── roles ───────────────────────────────────────────────────────────────────


class PostgresRole(BaseModel):
    rolname: str
    oid: int
    rolsuper: bool
    rolinherit: bool
    rolcreaterole: bool
    rolcreatedb: bool
    rolcanlogin: bool
    rolreplication: bool
    rolbypassrls: bool
    rolconnlimit: int
    rolvaliduntil: Optional[str]
    is_predefined: bool


class RoleMembership(BaseModel):
    role: str
    member: str
    grantor: Optional[str]
    admin_option: bool


# ── password types (privileged section; may be null with gap) ───────────────


class PasswordTypeEvidence(BaseModel):
    rolname: str
    password_type: str  # "none" | "md5" | "scram-sha-256" | "other"
    rolvaliduntil: Optional[str]


# ── role settings (privileged; may be null with gap) ───────────────────────


class RoleSettingItem(BaseModel):
    role: str
    database: str
    settings: Optional[list[str]]


# ── databases ───────────────────────────────────────────────────────────────


class DatabaseEvidence(BaseModel):
    datname: str
    owner: str
    encoding: str
    datcollate: str
    datctype: str
    datallowconn: bool
    datconnlimit: int
    datistemplate: bool
    datacl: Optional[list[str]]


# ── schemas ─────────────────────────────────────────────────────────────────


class SchemaEvidence(BaseModel):
    nspname: str
    owner: str
    nspacl: Optional[list[str]]
    public_has_create: bool
    public_has_usage: bool


# ── object ACLs ────────────────────────────────────────────────────────────


class ObjectACLEvidence(BaseModel):
    schema_name: Optional[str] = Field(alias="schema")
    name: str
    kind: str
    owner: str
    acl: Optional[list[str]]
    rls: bool
    rls_forced: bool


# ── default ACLs ───────────────────────────────────────────────────────────


class DefaultACLEvidence(BaseModel):
    owner: str
    schema_name: Optional[str] = Field(alias="schema")
    objtype: str
    acl: Optional[list[str]]


# ── RLS policies ───────────────────────────────────────────────────────────


class RLSPolicyEvidence(BaseModel):
    schema_name: str = Field(alias="schema")
    table: str
    policy: str
    permissive: str
    roles: list[str]
    cmd: str
    qual: Optional[str]
    with_check: Optional[str]


# ── extensions ─────────────────────────────────────────────────────────────


class ExtensionEvidence(BaseModel):
    extname: str
    version: str
    schema_name: Optional[str] = Field(alias="schema")
    owner: str


# ── tablespaces (privileged; may be null with gap) ─────────────────────────


class TablespaceEvidence(BaseModel):
    spcname: str
    owner: str
    acl: Optional[list[str]]
    location: Optional[str]


# ── foreign servers ────────────────────────────────────────────────────────


class ForeignServerEvidence(BaseModel):
    srvname: str
    owner: str
    fdw: str
    acl: Optional[list[str]]


# ── event triggers ─────────────────────────────────────────────────────────


class EventTriggerEvidence(BaseModel):
    evtname: str
    event: str
    owner: str
    enabled: str


# ── HBA rules (privileged; may be null with gap) ───────────────────────────


class HBARule(BaseModel):
    line_number: Optional[int]  # only in PG15+
    type: str
    database: Any  # can be "*" or list of names
    user_name: Any  # can be "*" or list of names
    address: Optional[str]
    netmask: Optional[str]
    auth_method: str
    options: Optional[list[str]]
    error: Optional[str]


# ── ident mappings (privileged; may be null with gap) ──────────────────────


class IdentMapping(BaseModel):
    line_number: int
    mapname: str
    pg_user: str
    system_user: str


# ── file settings (privileged; may be null with gap) ───────────────────────


class FileSetting(BaseModel):
    sourcefile: str
    sourceline: int
    name: str
    setting: str
    applied: bool
    error: Optional[str]


# ── replication ────────────────────────────────────────────────────────────


class ReplicationSlot(BaseModel):
    slot_name: str
    plugin: str
    slot_type: str
    database: Optional[str]
    temporary: bool
    active: bool


class Publication(BaseModel):
    pubname: str
    owner: str
    puballtables: bool
    pubinsert: bool
    pubupdate: bool
    pubdelete: bool


class Subscription(BaseModel):
    subname: str
    owner: str
    enabled: bool
    conninfo_parsed: Optional[Any]


class ReplicationEvidence(BaseModel):
    slots: Optional[list[ReplicationSlot]]
    publications: list[Publication]
    subscriptions: Optional[list[Subscription]]
    primary_conninfo_parsed: Optional[Any]
    in_recovery: bool


# ── connections ────────────────────────────────────────────────────────────


class ConnectionSummary(BaseModel):
    application_name: str
    usename: str
    datname: str
    client_addr_class: str
    count: int


# ── uptime ─────────────────────────────────────────────────────────────────


class UptimeEvidence(BaseModel):
    postmaster_start_time: str
    uptime_seconds: int


# ── gaps ───────────────────────────────────────────────────────────────────


class EvidenceGap(BaseModel):
    section: str
    reason: str
    remediation: str


# ── redactions ─────────────────────────────────────────────────────────────


class RedactionRecord(BaseModel):
    field: str
    class_: str = Field(alias="class")
    note: str


# ── Contract A ─────────────────────────────────────────────────────────────


class Postgres16EvidenceBundle(BaseModel):
    """Full collector output — the JSON document produced by collect.sql."""

    envelope: CollectorEnvelope
    identity: PostgresIdentity
    settings: list[PostgresSetting]
    roles: list[PostgresRole]
    role_memberships: list[RoleMembership]
    password_types: Optional[list[PasswordTypeEvidence]]
    role_settings: Optional[list[RoleSettingItem]]
    databases: list[DatabaseEvidence]
    schemas: list[SchemaEvidence]
    object_acls: list[ObjectACLEvidence]
    default_acls: list[DefaultACLEvidence]
    rls_policies: list[RLSPolicyEvidence]
    extensions: list[ExtensionEvidence]
    tablespaces: Optional[list[TablespaceEvidence]]
    foreign_servers: list[ForeignServerEvidence]
    event_triggers: list[EventTriggerEvidence]
    hba_rules: Optional[list[HBARule]]
    ident_mappings: Optional[list[IdentMapping]]
    file_settings: Optional[list[FileSetting]]
    replication: ReplicationEvidence
    connections: Optional[list[ConnectionSummary]]
    uptime: UptimeEvidence
    gaps: list[EvidenceGap]
    redactions: list[RedactionRecord]
    host_not_collected: list[str]


# ── Contract B ─────────────────────────────────────────────────────────────


class CreateRunRequest(BaseModel):
    target_evidence: Postgres16EvidenceBundle


class CreateRunResponse(BaseModel):
    run_id: uuid.UUID
    status: str
    target_engine: str
    target_major_version: int
    collector_schema_version: str
