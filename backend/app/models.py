"""Pydantic schemas for the proposal and knowledge APIs."""

import re
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator
from typing import Any, Literal, Optional, Union


class RemediationProposal(BaseModel):
    """Generic, template-driven remediation proposal contract.
    
    This is the single authoritative contract for proposing remediation.
    The AI/Hermes agent selects from approved templates and provides
    structured parameters - NOT arbitrary SQL or Python action objects.
    
    Template selection + parameters → validation → rendering → execution
    """
    
    control_id: str = Field(
        description="Control identifier (e.g., 'cis-pg17-v1.1.0:3.1.20' or 'DBGUARD-MD5-PASSWORDS')"
    )
    finding_id: Optional[str] = Field(
        default=None,
        description="Optional finding identifier from assessment"
    )
    template_id: str = Field(
        description="Approved template ID (must exist in active registry)"
    )
    template_version: Optional[int] = Field(
        default=None,
        description="Optional exact version; defaults to latest active"
    )
    parameters: dict[str, Any] = Field(
        description="Template parameters - validated against template schema"
    )
    reasoning: str = Field(
        min_length=1,
        description="Agent reasoning: why this template, how it applies"
    )
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="References to approved RAG evidence documents"
    )
    
    @field_validator("parameters", mode="after")
    @classmethod
    def validate_parameters_not_arbitrary_sql(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Prevent arbitrary SQL injection through parameters."""
        for key, value in v.items():
            if isinstance(value, str):
                # Check for SQL injection patterns in parameter values
                # Match dangerous SQL patterns anywhere in the string
                dangerous_patterns = [
                    r"(?i)\b(drop|truncate|delete|update|insert)\b",  # SQL keywords
                    r"--",  # Inline comment
                    r"/\*",  # Block comment start
                    r"(?i)\bexec\b\s*\(",  # EXEC function call
                ]
                for pattern in dangerous_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        raise ValueError(
                            f"Parameter '{key}' contains dangerous SQL pattern: {pattern}"
                        )
        return v


class RemediationProposalRequest(BaseModel):
    """Request to create a remediation proposal from an approved template.
    
    HERMES/MCP submits a proposal by selecting an approved template ID
    and providing structured parameters. The API validates, renders, and
    executes the template.
    """
    
    snapshot_id: str = Field(min_length=1, max_length=64)
    proposal: RemediationProposal
    environment: str = Field(default="all", min_length=1, max_length=64)


class HardenResponse(BaseModel):
    status: str
    target_db: str
    ai_plan: str
    retrieved_templates: list[str] = Field(
        default_factory=list,
        description="Template names retrieved via RAG"
    )
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    reasoning: str = ""
    requires_dba_approval: bool = True


class ProposalCompileRequest(BaseModel):
    """Deterministic proposal compilation requested by the HERMES agent."""

    snapshot_id: str = Field(min_length=1, max_length=64)
    requirement: str = Field(min_length=1, max_length=4000)
    template_ids: list[str] = Field(min_length=1, max_length=5)
    parameters: dict[str, Any] = Field(default_factory=dict)
    environment: str = Field(default="all", min_length=1, max_length=64)


class TemplateIngestRequest(BaseModel):
    """Request to ingest a single template into pgvector."""
    template_name: str
    version: int = Field(default=1, ge=1)
    description: str
    sql_template: str
    tags: list[str] = Field(default_factory=list)
    risk_level: Optional[str] = None
    pg_version: Optional[str] = None
    status: Literal["draft", "active"] = "draft"
    approved_by: Optional[str] = None

    @model_validator(mode="after")
    def active_templates_require_an_approver(self):
        if self.status == "active" and not self.approved_by:
            raise ValueError("approved_by is required when status is active")
        return self


class TemplateIngestResponse(BaseModel):
    status: str
    template_name: str
    id: Optional[int] = None
    lifecycle_status: Literal["draft", "active", "archived"]
    version: Optional[int] = None
    created: bool = False


class TemplateApprovalRequest(BaseModel):
    approved_by: str = Field(min_length=1, max_length=255)


class TemplateSearchResponse(BaseModel):
    status: str
    results: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Top-K matching templates with similarity scores"
    )


class KnowledgeIngestRequest(BaseModel):
    document_id: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=512)
    version: str = Field(min_length=1, max_length=64)
    content: str = Field(min_length=100)
    effective_date: datetime
    status: Literal["draft", "active"] = "draft"
    approved_by: Optional[str] = None
    expiry_date: Optional[datetime] = None
    postgresql_versions: list[str] = Field(default_factory=lambda: ["15", "16", "17"])
    environment_applicability: list[str] = Field(default_factory=lambda: ["all"])
    policy_owner: str = ""
    classification: str = "internal"
    source_url: Optional[str] = None

    @model_validator(mode="after")
    def active_documents_require_an_approver(self):
        if self.status == "active" and not self.approved_by:
            raise ValueError("approved_by is required when status is active")
        return self


class KnowledgeApprovalRequest(BaseModel):
    approved_by: str = Field(min_length=1, max_length=255)


class KnowledgeSearchResult(BaseModel):
    chunk_id: int
    document_id: str
    section: str
    content: str
    source_document_title: str
    source_document_version: str
    source_url: Optional[str] = None
    postgresql_versions: list[str]
    environment_applicability: list[str]
    similarity_score: float


class KnowledgeSearchResponse(BaseModel):
    status: str = "ok"
    results: list[KnowledgeSearchResult] = Field(default_factory=list)


class KnowledgeIngestResponse(BaseModel):
    """Response for knowledge ingestion operations (e.g. XLSX upload)."""
    status: str
    document_id: str
    title: str
    chunks_created: int = 0


# ============================================================================
# ASSESS Evaluation Contracts (Offline Assessment Engine)
# ============================================================================


class FindingStatus(str, Enum):
    """Status of a control evaluation against snapshot evidence."""

    PASS = "PASS"
    """Control condition is satisfied by the snapshot evidence."""

    FAIL = "FAIL"
    """Control condition is NOT satisfied and can be remediated automatically."""

    GAPPED = "GAPPED"
    """
    Collector could not gather evidence for this control due to missing privilege,
    unsupported PostgreSQL version, or other collection limitation.
    """

    MANUAL_REVIEW = "MANUAL_REVIEW"
    """Control requires human intervention and cannot be automated."""

    NOT_APPLICABLE = "NOT_APPLICABLE"
    """
    The spec's applies_when condition is false on exact, collected evidence (for
    example a syslog control when log_destination does not include syslog).
    Unknown condition evidence is GAPPED, never NOT_APPLICABLE or PASS.
    """


# ============================================================================
# Template-driven control metadata (replaces TypedAction)
# ============================================================================

class ControlMetadata(BaseModel):
    """Metadata for a control, mapping to Jinja templates for remediation.
    
    This replaces the old TypedAction system. Controls now map directly to
    approved Jinja templates, and the AI/Hermes agent proposes by selecting
    template_id + parameters.
    """
    
    template_id: str = Field(
        description="Approved Jinja template ID for remediation"
    )
    template_version: Optional[int] = Field(
        default=None,
        description="Optional template version"
    )
    is_automatable: bool = Field(
        description="True if remediation can be automated via template rendering"
    )
    risk_level: str = Field(
        default="medium",
        description="Risk level (low, medium, high)"
    )
    requires_dba_review: bool = Field(
        default=True,
        description="Whether DBA approval is required before execution"
    )


class Finding(BaseModel):
    """Result of evaluating a single control against snapshot evidence.
    
    When status is FAIL, the finding includes control_metadata that maps
    to an approved Jinja template for remediation. The AI/Hermes agent
    proposes remediation by selecting from these approved templates.
    """

    control_id: str = Field(
        description="Unique control identifier (e.g., cis-pg17-v1.1.0:3.1.20 or DBGUARD-MD5-PASSWORDS)"
    )
    status: FindingStatus = Field(
        description="Evaluation outcome: PASS, FAIL, GAPPED, MANUAL_REVIEW or NOT_APPLICABLE"
    )
    title: str = Field(
        description="Human-readable control title"
    )
    rationale: str = Field(
        description="Explanation of why the control passed or failed"
    )
    evidence_found: Optional[Any] = Field(
        default=None,
        description="Raw evidence extracted from snapshot that determined the status"
    )
    control_metadata: Optional[ControlMetadata] = Field(
        default=None,
        description="Template mapping for remediation when status is FAIL or MANUAL_REVIEW"
    )
    is_gapped: bool = Field(
        default=False,
        description="True if the evidence was gapped (null with matching gap record)"
    )
    severity: Optional[str] = Field(
        default=None,
        description="CIS severity level (e.g., '1', '2A', '2B', '3')"
    )
    evidence_paths: Optional[list[str]] = Field(
        default=None,
        description="JSON paths of evidence fields read (e.g., settings[name='log_connections'].setting)"
    )
    cis: Optional[dict[str, str]] = Field(
        default=None,
        description="{recommendation, title} of the CIS control, for GAPPED, NOT_APPLICABLE and policy_missing findings"
    )
    explanation: Optional[dict[str, Any]] = Field(
        default=None,
        description="Structured facts (code plus spec/evidence values, never prose) explaining a GAPPED, "
                    "NOT_APPLICABLE or policy_missing finding"
    )


class AssessmentSummary(BaseModel):
    """Summary counts for an assessment report."""

    total: int = Field(description="Total controls evaluated")
    pass_count: int = Field(description="Number of PASS findings")
    fail_count: int = Field(description="Number of FAIL findings")
    gapped_count: int = Field(description="Number of GAPPED findings")
    manual_review_count: int = Field(description="Number of MANUAL_REVIEW findings")
    not_applicable_count: int = Field(default=0, description="Number of NOT_APPLICABLE findings")


class AssessmentReport(BaseModel):
    """Complete assessment report for a single snapshot."""

    snapshot_id: str = Field(
        description="Content-addressed snapshot identifier"
    )
    evaluated_at: datetime = Field(
        default_factory=datetime.now,
        description="Timestamp when evaluation completed"
    )
    summary: AssessmentSummary = Field(
        description="Aggregate counts of finding statuses"
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="Detailed findings for each evaluated control"
    )


# ============================================================================
# Twin Execution & VALIDATE Phase Contracts
# ============================================================================


class TwinExecutionStatus(str, Enum):
    """Status of twin sandbox execution."""

    SKIPPED_MANUAL_REQUIRED = "SKIPPED_MANUAL_REQUIRED"
    """Non-SQL control requiring manual intervention."""
    
    EXECUTING = "EXECUTING"
    """Remediation SQL being executed in twin."""
    
    VERIFYING = "VERIFYING"
    """Twin snapshot collected, re-evaluating controls."""
    
    VERIFIED = "VERIFIED"
    """Flip verified: FAIL -> PASS after remediation."""
    
    SANDBOX_REPRODUCTION_FAILED = "SANDBOX_REPRODUCTION_FAILED"
    """Sandbox failed to reproduce original FAIL state."""
    
    ROLLBACK_EXECUTING = "ROLLBACK_EXECUTING"
    """Rollback SQL being executed."""
    
    RESTORED = "RESTORED"
    """Container restored to clean state after rollback."""
    
    FAILED = "FAILED"
    """Execution failed with error details."""
    
    COMPATIBILITY_FAILED = "COMPATIBILITY_FAILED"
    """Compatibility check failed after remediation."""


class TwinExecutionResult(BaseModel):
    """Result of twin sandbox verification for a single proposal."""
    
    control_id: str
    status: TwinExecutionStatus
    remediation_executed: bool = False
    rollback_executed: bool = False
    rollback_verified: bool = False
    flip_verified: bool = False
    error: Optional[str] = None
    execution_log: list[str] = Field(default_factory=list)
    verification_snapshot_id: Optional[str] = None
    pre_remediation_status: Optional[FindingStatus] = None
    post_remediation_status: Optional[FindingStatus] = None
    post_rollback_status: Optional[FindingStatus] = None


class SetConfigTemplateParams(BaseModel):
    """Validated parameters for SET_CONFIG_PARAMETER template rendering."""
    
    model_config = ConfigDict(extra="forbid")
    
    param_name: str = Field(
        description="PostgreSQL GUC parameter name"
    )
    param_value: str = Field(
        description="Target value for the parameter"
    )
    
    @field_validator("param_name")
    @classmethod
    def validate_param_name(cls, v: str) -> str:
        """Validate parameter name against allowed config parameters."""
        # Allowed config parameters - extend as needed
        allowed_params = {
            "log_connections", "debug_print_parse", "ssl_min_protocol_version", "logging_collector",
            "log_checkpoints",
            "log_disconnections",
            "log_lock_waits",
            "log_min_duration_statement",
            "log_statement",
            "log_truncate_on_rotation",
            "syslog_sequence_numbers",
            "debug_print_rewritten",
            "debug_print_plan",
            "debug_pretty_print",
            "log_error_verbosity",
            "log_hostname",
            # Wave 1b (F2/F3/F4): one entry per reviewed POLICIES setting in
            # services/sandbox_poc/planning.py; values checked per setting below.
            "log_min_messages",
            "log_min_error_statement",
            "log_line_prefix",
            "log_destination",
            "log_directory",
            "log_filename",
            "log_file_mode",
            "log_rotation_age",
            "log_rotation_size",
            "syslog_facility",
            "syslog_ident",
            "log_timezone",
            "listen_addresses",
            "password_encryption",
            "max_connections",
            "shared_buffers",
            "work_mem",
            "maintenance_work_mem",
            "effective_cache_size",
            "random_page_cost",
            "default_statistics_target",
        }
        if v not in allowed_params:
            raise ValueError(f"Invalid config parameter name: {v}. Must be one of {sorted(allowed_params)}")
        return v
    
    @model_validator(mode="after")
    def validate_param_value(self) -> "SetConfigTemplateParams":
        """Validate the value with the reviewed per-setting table.

        Settings with an entry in app.services.setting_values.SETTING_ALLOWED_VALUES
        (booleans and enums) or SETTING_VALUE_RULES use that rule; every value is
        first checked against GLOBAL_FORBIDDEN. Settings without an entry keep the
        historical rule below.
        """
        from app.services.setting_values import SettingValueError, check_setting_value, has_value_rule
        v = self.param_value
        try:
            if has_value_rule(self.param_name):
                check_setting_value(self.param_name, v)
                return self
            check_setting_value(self.param_name, v, fallback=None)
        except SettingValueError as exc:
            raise ValueError(f"Invalid parameter value: {exc}") from None
        # Historical rule for settings without a reviewed entry.
        if v.lower() in ("on", "off", "true", "false", "yes", "no", "1", "0"):
            return self
        try:
            float(v)
            return self
        except ValueError:
            pass
        if "'" not in v and ";" not in v and "--" not in v and "/*" not in v:
            return self
        raise ValueError(f"Invalid parameter value: {v}")


class RevokePrivilegeTemplateParams(BaseModel):
    """Validated parameters for REVOKE_SCHEMA_PRIVILEGE template rendering."""
    
    model_config = ConfigDict(extra="forbid")
    
    privilege: str = Field(
        description="Privilege to revoke (e.g., CREATE, USAGE, SELECT)"
    )
    schema_name: str = Field(
        description="Schema name (e.g., public)"
    )
    grantee: str = Field(
        description="Grantee role name (e.g., PUBLIC)"
    )
    
    @field_validator("privilege")
    @classmethod
    def validate_privilege(cls, v: str) -> str:
        """Validate privilege type."""
        allowed_privileges = {
            "SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE",
            "REFERENCES", "TRIGGER", "CREATE", "USAGE", "TEMPORARY",
            "CONNECT", "EXECUTE", "SET", "ALTER SYSTEM"
        }
        upper_v = v.upper()
        if upper_v not in allowed_privileges:
            raise ValueError(f"Invalid privilege type: {v}. Must be one of {sorted(allowed_privileges)}")
        return upper_v
    
    @field_validator("schema_name")
    @classmethod
    def validate_schema_name(cls, v: str) -> str:
        """Validate schema name format."""
        # Allow valid PostgreSQL identifiers (letters, digits, underscore, no spaces)
        import re
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', v):
            raise ValueError(f"Invalid schema name: {v}. Must be a valid PostgreSQL identifier.")
        return v
    
    @field_validator("grantee")
    @classmethod
    def validate_grantee(cls, v: str) -> str:
        """Validate grantee role name format."""
        import re
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', v):
            raise ValueError(f"Invalid grantee name: {v}. Must be a valid PostgreSQL identifier.")
        return v


class CreateReadOnlyRoleTemplateParams(BaseModel):
    """Parameters for the create_read_only_rule template (MCP render path).

    Added so every bundled template has a schema (Wave 2a): names are checked here
    and quoted by the ``ident`` filter; database_name is filled from the snapshot
    by the API when absent.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    role_name: str
    database_name: Optional[str] = None
    schema_name: str = "public"

    @field_validator("role_name", "schema_name")
    @classmethod
    def _names(cls, v: str) -> str:
        return pg_identifier(v)

    @field_validator("database_name")
    @classmethod
    def _database(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else pg_identifier(v)

    def model_dump(self, **kwargs):  # an absent database_name stays absent
        kwargs.setdefault("exclude_none", True)
        return super().model_dump(**kwargs)


class RevokePublicSchemaAccessTemplateParams(BaseModel):
    """Parameters for the revoke_public_access template (MCP render path)."""

    model_config = ConfigDict(extra="forbid", strict=True)

    schema_name: str = "public"

    @field_validator("schema_name")
    @classmethod
    def _names(cls, v: str) -> str:
        return pg_identifier(v)


# ---- Wave 2a (F6): per-object fix templates ---------------------------------
# Parameters for the six object-fix templates. Values are never taken from a
# request: services/sandbox_poc/object_fixes.py derives them from collected
# evidence (and the approved policy profile for connection limits). These schemas
# are the second line: identifiers are checked here and quoted by ``ident``;
# keywords, privileges and argument types come only from the closed sets below.

# PostgreSQL NAMEDATALEN - 1.
PG_IDENTIFIER_MAX_BYTES = 63

# Reviewed allowlist of built-in argument types for function fixes, keyed by the
# exact pg_get_function_identity_arguments / format_type spelling. The value is the
# SQL rendered into ALTER/REVOKE ... FUNCTION: SQL-keyword types stay as keywords
# (the grammar always maps them to pg_catalog); every other type is written
# pg_catalog-qualified so a same-named type earlier in search_path cannot capture it.
# Polymorphic and pseudo-types (anyelement, record, internal, ...) are deliberately
# absent: a function using them is shown as "can't rehearse".
FUNCTION_ARG_TYPES = {
    "boolean": "boolean",
    "smallint": "smallint",
    "integer": "integer",
    "bigint": "bigint",
    "real": "real",
    "double precision": "double precision",
    "numeric": "numeric",
    "character varying": "character varying",
    "character": "character",
    "bit": "bit",
    "bit varying": "bit varying",
    "interval": "interval",
    "time without time zone": "time without time zone",
    "time with time zone": "time with time zone",
    "timestamp without time zone": "timestamp without time zone",
    "timestamp with time zone": "timestamp with time zone",
    "text": "pg_catalog.text",
    "name": "pg_catalog.name",
    "bytea": "pg_catalog.bytea",
    "date": "pg_catalog.date",
    "uuid": "pg_catalog.uuid",
    "json": "pg_catalog.json",
    "jsonb": "pg_catalog.jsonb",
    "xml": "pg_catalog.xml",
    "inet": "pg_catalog.inet",
    "cidr": "pg_catalog.cidr",
    "macaddr": "pg_catalog.macaddr",
    "money": "pg_catalog.money",
    "oid": "pg_catalog.oid",
    "regclass": "pg_catalog.regclass",
    "regtype": "pg_catalog.regtype",
    "regrole": "pg_catalog.regrole",
    "regnamespace": "pg_catalog.regnamespace",
    "regproc": "pg_catalog.regproc",
    "regprocedure": "pg_catalog.regprocedure",
    "tsvector": "pg_catalog.tsvector",
    "tsquery": "pg_catalog.tsquery",
    "pg_lsn": "pg_catalog.pg_lsn",
    "int4range": "pg_catalog.int4range",
    "int8range": "pg_catalog.int8range",
    "numrange": "pg_catalog.numrange",
    "daterange": "pg_catalog.daterange",
    "tsrange": "pg_catalog.tsrange",
    "tstzrange": "pg_catalog.tstzrange",
}
# IN is implicit in identity arguments; INOUT cannot belong to the void stub the
# sandbox recreates, so only VARIADIC (of an array type) is accepted.
FUNCTION_ARG_MODES = ("VARIADIC",)
# One canonical rendered argument: optional mode, an allowlisted SQL type, optional [].
FUNCTION_ARG_RE = re.compile(
    r"(?:(?:" + "|".join(FUNCTION_ARG_MODES) + r") )?(?:"
    + "|".join(re.escape(sql) for sql in sorted(set(FUNCTION_ARG_TYPES.values()), key=len, reverse=True))
    + r")(?:\[\])?"
)
ROLE_ATTRIBUTES = ("SUPERUSER", "CREATEROLE", "CREATEDB", "REPLICATION", "BYPASSRLS")
DML_PRIVILEGE_ORDER = ("INSERT", "UPDATE", "DELETE")


def pg_identifier(value: Any) -> str:
    """A name from evidence that ``ident`` may quote: non-empty, at most 63 bytes,
    no NUL, control, format (bidi/zero-width) or line/paragraph separator characters."""
    import unicodedata
    if not isinstance(value, str) or not value:
        raise ValueError("identifier must be a non-empty string")
    if len(value.encode("utf-8")) > PG_IDENTIFIER_MAX_BYTES:
        raise ValueError("identifier is longer than 63 bytes")
    if any(unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp") for c in value):
        raise ValueError("identifier contains a control or invisible character")
    return value


class _ObjectFixParams(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["apply", "rollback"]


class RoleConnectionLimitTemplateParams(_ObjectFixParams):
    role_name: str
    # apply: the approved profile's limit (>= 0); rollback: the prior value (-1 = unlimited).
    connection_limit: int = Field(ge=-1, le=2_147_483_647)

    @field_validator("role_name")
    @classmethod
    def _names(cls, v: str) -> str:
        return pg_identifier(v)


class RoleDropAttributeTemplateParams(_ObjectFixParams):
    role_name: str
    attribute: Literal["SUPERUSER", "CREATEROLE", "CREATEDB", "REPLICATION", "BYPASSRLS"]

    @field_validator("role_name")
    @classmethod
    def _names(cls, v: str) -> str:
        return pg_identifier(v)


class RoleNologinTemplateParams(_ObjectFixParams):
    role_name: str

    @field_validator("role_name")
    @classmethod
    def _names(cls, v: str) -> str:
        return pg_identifier(v)


class _FunctionFixParams(_ObjectFixParams):
    schema_name: str
    function_name: str
    arg_types: list[str] = Field(max_length=100)

    @field_validator("schema_name", "function_name")
    @classmethod
    def _names(cls, v: str) -> str:
        return pg_identifier(v)

    @field_validator("arg_types")
    @classmethod
    def _arg_types(cls, v: list[str]) -> list[str]:
        for item in v:
            if not isinstance(item, str) or not FUNCTION_ARG_RE.fullmatch(item):
                raise ValueError(f"argument type is not in the reviewed built-in allowlist: {item!r}")
        return v


class FunctionSecurityInvokerTemplateParams(_FunctionFixParams):
    pass


class FunctionRevokePublicExecuteTemplateParams(_FunctionFixParams):
    pass


class TableRevokeDmlTemplateParams(_ObjectFixParams):
    schema_name: str
    table_name: str
    # None means PUBLIC (rendered as the keyword, never as a quoted name).
    grantee: Optional[str]
    privileges: list[Literal["INSERT", "UPDATE", "DELETE"]] = Field(min_length=1, max_length=3)
    grant_option: bool

    @field_validator("schema_name", "table_name")
    @classmethod
    def _names(cls, v: str) -> str:
        return pg_identifier(v)

    @field_validator("grantee")
    @classmethod
    def _grantee(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else pg_identifier(v)

    @field_validator("privileges")
    @classmethod
    def _privileges(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v) or v != [p for p in DML_PRIVILEGE_ORDER if p in v]:
            raise ValueError("privileges must be unique and in the order INSERT, UPDATE, DELETE")
        return v


class ProposalReviewPackage(BaseModel):
    """Complete DBA review package for a single proposal."""
    
    snapshot_id: str = Field(
        description="Target snapshot reference"
    )
    control_id: str = Field(
        description="CIS Control identifier"
    )
    title: str = Field(
        description="Human-readable control title"
    )
    remediation_sql: Optional[str] = Field(
        default=None,
        description="Rendered and verified remediation SQL string (if executable)"
    )
    rollback_sql: Optional[str] = Field(
        default=None,
        description="Rendered and verified rollback SQL string (if executable)"
    )
    manual_procedure: Optional[list[str]] = Field(
        default=None,
        description="Step-by-step guidance list (for non-SQL controls)"
    )
    twin_verification: Optional[TwinExecutionResult] = Field(
        default=None,
        description="TwinExecutionResult containing flip proof"
    )
    rag_justification: str = Field(
        description="CIS benchmark rationale and impact analysis statement"
    )
    requires_dba_review: bool = Field(
        default=True,
        description="Whether DBA review is required before execution"
    )
    risk_level: str = Field(
        default="medium",
        description="Risk assessment level (low, medium, high)"
    )
