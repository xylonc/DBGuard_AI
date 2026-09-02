"""
Core data contracts for DBGuardAI.
Pydantic models for validation and serialization.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, SecretStr, validator


# ─── Enums ───────────────────────────────────────────────────────────

class AssessmentPhase(str, Enum):
    """Workflow state machine phases."""
    RECEIVED = "RECEIVED"
    SNAPSHOT_VALIDATED = "SNAPSHOT_VALIDATED"
    TARGET_PROFILE_RESOLVED = "TARGET_PROFILE_RESOLVED"
    IMAGE_RESOLVED = "IMAGE_RESOLVED"
    TWIN_STARTING = "TWIN_STARTING"
    TWIN_VERIFIED = "TWIN_VERIFIED"
    SNAPSHOT_REPLAYED = "SNAPSHOT_REPLAYED"
    BASELINE_ASSESSED = "BASELINE_ASSESSED"
    PLAN_PROPOSED = "PLAN_PROPOSED"
    REMEDIATION_TESTING = "REMEDIATION_TESTING"
    FINAL_TWIN_ASSESSED = "FINAL_TWIN_ASSESSED"
    REVIEW_PACKAGE_READY = "REVIEW_PACKAGE_READY"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    
    # Error states
    INVALID_SNAPSHOT = "INVALID_SNAPSHOT"
    UNSUPPORTED_TARGET = "UNSUPPORTED_TARGET"
    IMAGE_VERIFICATION_FAILED = "IMAGE_VERIFICATION_FAILED"
    TWIN_CREATION_FAILED = "TWIN_CREATION_FAILED"
    SNAPSHOT_REPLAY_FAILED = "SNAPSHOT_REPLAY_FAILED"
    POLICY_REJECTED = "POLICY_REJECTED"
    REMEDIATION_EXHAUSTED = "REMEDIATION_EXHAUSTED"
    ASSESSMENT_FAILED = "ASSESSMENT_FAILED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ControlStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    REMEDIATED_IN_TWIN = "REMEDIATED_IN_TWIN"
    REMEDIATION_EXHAUSTED = "REMEDIATION_EXHAUSTED"


class FidelityLevel(str, Enum):
    VERIFIED_IN_TWIN = "VERIFIED_IN_TWIN"
    STATICALLY_CHECKED = "STATICALLY_CHECKED"
    APPROXIMATED = "APPROXIMATED"
    REQUIRES_PRODUCTION_VALIDATION = "REQUIRES_PRODUCTION_VALIDATION"
    NOT_REPRESENTABLE = "NOT_REPRESENTABLE"
    MANUAL_CONTROL = "MANUAL_CONTROL"


class ImageStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    CANDIDATE = "CANDIDATE"
    TESTING = "TESTING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    DEPRECATED = "DEPRECATED"
    REVOKED = "REVOKED"


class ControlRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ─── SnapshotBundle ──────────────────────────────────────────────────

class DatabaseIdentity(BaseModel):
    engine: str = "postgresql"
    version: str
    server_version_num: Optional[int]
    distribution: str = "community"
    architecture: str = "amd64"
    deployment_type: str = "self-managed"


class PostgreSQLSetting(BaseModel):
    name: str
    setting: str
    source: str = "postgresql.conf"
    is_modifiable: bool = True


class RoleInfo(BaseModel):
    name: str
    is_superuser: bool
    can_create_db: bool
    can_create_role: bool
    member_of: List[str] = Field(default_factory=list)


class GrantInfo(BaseModel):
    table_name: str
    schema_name: str
    role_name: str
    privilege_type: str
    with_grant_option: bool = False


class ExtensionInfo(BaseModel):
    name: str
    version: Optional[str]
    schema_name: str = "public"


class AuthenticationRule(BaseModel):
    database: str
    user: str
    address: Optional[str] = None
    method: str  # scram-sha-256, md5, trust, peer, etc.


class TLSMetadata(BaseModel):
    ssl_enabled: bool
    ssl_cert_file: Optional[str] = None
    ssl_key_file: Optional[str] = None
    ssl_min_protocol_version: Optional[str] = None


class LoggingConfig(BaseModel):
    log_statement: str = "none"
    log_connections: bool = False
    log_disconnections: bool = False
    log_line_prefix: str = ""
    logging_collector: bool = False


class ReplicationMetadata(BaseModel):
    replication_enabled: bool = False
    max_wal_senders: int = 0
    wal_level: str = "replica"


class SnapshotBundle(BaseModel):
    """Security-relevant metadata from PostgreSQL. NO business data."""
    collector_version: str = "1.0.0"
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)
    snapshot_hash: str = ""

    identity: DatabaseIdentity
    settings: List[PostgreSQLSetting] = Field(default_factory=list)
    roles: List[RoleInfo] = Field(default_factory=list)
    grants: List[GrantInfo] = Field(default_factory=list)
    extensions: List[ExtensionInfo] = Field(default_factory=list)
    authentication_rules: List[AuthenticationRule] = Field(default_factory=list)
    tls_metadata: Optional[TLSMetadata] = None
    logging_config: Optional[LoggingConfig] = None
    replication_metadata: Optional[ReplicationMetadata] = None
    collection_errors: List[str] = Field(default_factory=list)


# ─── TargetProfile ───────────────────────────────────────────────────

class TargetProfile(BaseModel):
    """Normalized database profile for catalog matching."""
    engine_version_major: int
    engine_version_minor: int
    distribution: str = "community"
    architecture: str = "amd64"
    deployment_type: str = "self-managed"
    extensions: List[str] = Field(default_factory=list)


# ─── ImageCatalogEntry ───────────────────────────────────────────────

class ImageCatalogEntry(BaseModel):
    """Approved PostgreSQL image entry."""
    profile_id: str
    version_major: int
    version_minor: int
    os: str = "debian"
    architecture: str = "amd64"
    digest: str  # sha256:xxx
    internal_registry: str
    repository: str
    status: ImageStatus = ImageStatus.CANDIDATE
    supports_hba_testing: bool = True
    supports_tls_testing: bool = True


# ─── TwinSpecification ───────────────────────────────────────────────

class TwinSpecification(BaseModel):
    """Validated request for the Restricted Twin Runner."""
    run_id: str
    approved_profile_id: str
    snapshot_id: str
    ttl_minutes: int = 60


# ─── HardeningControl ────────────────────────────────────────────────

class ControlAssessment(BaseModel):
    action: str
    query_or_command: str


class ControlRemediation(BaseModel):
    action: str
    allowed_parameters: Dict[str, List[str]] = Field(default_factory=dict)


class ControlRollback(BaseModel):
    action: str
    rollback_query: str


class ControlImpact(BaseModel):
    risk_level: ControlRiskLevel
    flags: List[str] = Field(default_factory=list)
    requires_restart: bool = False
    requires_reload: bool = False


class HardeningControl(BaseModel):
    control_id: str
    title: str
    engine: str = "postgresql"
    cis_cat_mapping: Optional[str] = None
    supported_versions: Dict[str, Any] = Field(default_factory=dict)
    assessment: ControlAssessment
    remediation: ControlRemediation
    rollback: ControlRollback
    impact: ControlImpact
    references: List[str] = Field(default_factory=list)


# ─── AssessmentResult ────────────────────────────────────────────────

class ControlResult(BaseModel):
    control_id: str
    status: ControlStatus
    severity: Severity
    baseline_result: str = ""
    twin_result: str = ""
    attempts: int = 0
    rollback_performed: bool = False
    evidence_status: str = "missing"
    compatibility_risk: str = "none"


class AssessmentSummary(BaseModel):
    run_id: str
    target_profile: Optional[TargetProfile] = None
    image_fidelity: str = "unknown"
    baseline_score: float = 0.0
    twin_score: float = 0.0
    controls_assessed: int = 0
    controls_passed: int = 0
    controls_failed: int = 0
    manual_controls: int = 0
    exceptions: int = 0


# ─── ActionRequest ───────────────────────────────────────────────────

class ActionRequest(BaseModel):
    """Structured action from HERMES. Typed to prevent arbitrary SQL."""
    control_id: str
    parameters: Dict[str, Any]
    justification: str


# ─── ReviewPackage ───────────────────────────────────────────────────

class ReviewPackage(BaseModel):
    """Human-facing assessment report."""
    run_id: str
    baseline_score: float
    twin_score: float
    controls: List[ControlResult]
    warnings: List[str] = Field(default_factory=list)
    disclaimer: str = Field(
        default="DBGuard does not modify production. Approved changes require human review."
    )


# ─── RAG / Knowledge ─────────────────────────────────────────────────

class DocumentMetadata(BaseModel):
    """Metadata for a document in the RAG knowledge base."""
    document_id: str
    title: str
    version: str
    status: str  # active, superseded, archived
    effective_date: datetime
    expiry_date: Optional[datetime] = None
    postgresql_versions: List[str] = Field(default_factory=lambda: ["15", "16", "17"])
    environment_applicability: List[str] = Field(default_factory=lambda: ["all"])
    policy_owner: str = ""
    classification: str = "internal"  # public, internal, confidential, licensed
    source_url: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class KnowledgeChunk(BaseModel):
    """A chunk of a knowledge document for embedding and retrieval."""
    document_id: str
    section: str
    content: str
    chunk_hash: str  # SHA-256 of content
    chunk_index: int
    postgresql_versions: List[str] = Field(default_factory=lambda: ["15", "16", "17"])
    environment_applicability: List[str] = Field(default_factory=lambda: ["all"])
    source_document_title: str = ""
    source_document_version: str = ""


class RetrievalResult(BaseModel):
    """A result from a RAG knowledge search."""
    chunk_id: str
    document_id: str
    section: str
    content: str
    chunk_hash: str
    postgresql_versions: List[str]
    environment_applicability: List[str]
    source_document_title: str
    source_document_version: str
    similarity_score: float
    retrieval_timestamp: datetime = Field(default_factory=datetime.utcnow)


class KnowledgePackManifest(BaseModel):
    """Manifest for a knowledge pack to be ingested."""
    pack_name: str
    pack_version: str
    effective_date: datetime
    expiry_date: Optional[datetime] = None
    documents: List[Dict[str, Any]] = Field(default_factory=list)
    classification: str = "internal"


class KnowledgeStatus(str, Enum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    ARCHIVED = "archived"
