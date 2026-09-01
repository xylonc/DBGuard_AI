#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  DBGuardAI SQL Collector v1.0.0                                 ║
# ║  ══════════════════════════════════════════════════════════════ ║
# ║  This script is READ-ONLY. It executes only SELECT, SHOW, and   ║
# ║  system catalog queries. It never writes, alters, creates, or   ║
# ║  takes locks on the target database.                             ║
# ║                                                                  ║
# ║  It uses psql and POSIX sh/bash only. No Python, no jq, no      ║
# ║  GNU-only flags.                                                 ║
# ║                                                                  ║
# ║  It never handles or outputs credentials. Secrets are never      ║
# ║  collected, never logged, never stored.                          ║
# ╚══════════════════════════════════════════════════════════════════╝
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — override via environment
# ---------------------------------------------------------------------------
readonly COLLECTOR_VERSION="1.0.0"
readonly SCHEMA_VERSION="0.2.0"

TARGET_ID="${TARGET_ID:-unknown}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
PGDATABASE="${PGDATABASE:-postgres}"
PGUSER="${PGUSER:-}"

# ---------------------------------------------------------------------------
# Determine script directory for sourcing libs
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/probe.sh"
source "$SCRIPT_DIR/lib/bundle.sh"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
OUTPUT_DIR=""
for arg in "$@"; do
    case "$arg" in
        --output=*) OUTPUT_DIR="${arg#--output=}" ;;
        --target=*) TARGET_ID="${arg#--target=}" ;;
        --user=*)   PGUSER="${arg#--user=}" ;;
        --help)
            echo "Usage: $0 [--output=DIR] [--target=ID] [--user=USER]"
            echo ""
            echo "Environment variables:"
            echo "  TARGET_ID   Opaque identifier for the target (default: unknown)"
            echo "  PGDATABASE  Database to connect to (default: postgres)"
            echo "  PGUSER      PostgreSQL user (default: current OS user)"
            echo ""
            echo "Uses standard libpq authentication (PGPASSFILE, .pgpass, service files)."
            exit 0
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Setup output directory
# ---------------------------------------------------------------------------
TIMESTAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
if [ -n "$OUTPUT_DIR" ]; then
    BUNDLE_DIR="${OUTPUT_DIR}/dbguard-${TARGET_ID}-${TIMESTAMP}"
else
    BUNDLE_DIR="$(mktemp -d "/tmp/dbguard-${TARGET_ID}-${TIMESTAMP}.XXXXXXXXXX")"
fi
BUNDLE_FILE="${BUNDLE_DIR}.tar.gz"

mkdir -p "$BUNDLE_DIR/sections" "$BUNDLE_DIR/raw"

# Initialise tracking files
: > "$BUNDLE_DIR/collector.log"
: > "$BUNDLE_DIR/gaps.tmp"
: > "$BUNDLE_DIR/redactions.tmp"

COLLECTOR_LOG="$BUNDLE_DIR/collector.log"
GAPS_FILE="$BUNDLE_DIR/gaps.tmp"
REDACTIONS_FILE="$BUNDLE_DIR/redactions.tmp"

# ---------------------------------------------------------------------------
# Phase 1: Preflight done by probe.sh
# ---------------------------------------------------------------------------

log_info "=== DBGuardAI Collector $COLLECTOR_VERSION ==="
log_info "Target: $TARGET_ID | DB: $PGDATABASE | User: $(psql -X -A -t -q -d "$PGDATABASE" -c 'SELECT current_user;' 2>/dev/null || echo 'unknown')"
log_info "Server: $SERVER_VERSION_FULL ($SERVER_VERSION_NUM)"
log_info "Output directory: $BUNDLE_DIR"

COLLECTED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ---------------------------------------------------------------------------
# Phase 2: Core collection
# ---------------------------------------------------------------------------

collect_section() {
    local section_name="$1"
    local sql_file="$2"
    local gap_section="${3:-$section_name}"
    local remediation="${4:-}"
    local output_file="$BUNDLE_DIR/sections/${section_name}.json"

    log_info "Collecting: $section_name"

    if [ ! -f "$sql_file" ]; then
        record_gap "$gap_section" "file_not_readable" \
            "Query file not found: $sql_file" ""
        printf '%s' '{"_error":"query_file_missing"}' > "$output_file"
        return 1
    fi

    # Replace version-gated placeholders
    local sql_text
    sql_text=$(sed \
        -e "s|{{SERVER_MAJOR}}|$SERVER_MAJOR|g" \
        -e "s|{{CAN_SELECT_AUTHID}}|$CAN_SELECT_AUTHID|g" \
        -e "s|{{SERVER_VERSION_NUM}}|$SERVER_VERSION_NUM|g" \
        "$sql_file")

    local result
    result=$(run_sql "$PGDATABASE" "$sql_text" "$gap_section" "$remediation" 2>/dev/null) || true

    if [ -z "$result" ]; then
        # Empty result — could be valid (empty array []) or error
        echo '[]' > "$output_file"
    else
        printf '%s' "$result" > "$output_file"
    fi
}

collect_section_db() {
    # Like collect_section but writes to a per-database file and prepends the database name.
    # Signature: collect_section_db SECTION_NAME SQL_FILE GAP_SECTION REMEDIATION DBNAME
    local section_name="$1"
    local sql_file="$2"
    local gap_section="${3:-$section_name}"
    local remediation="${4:-}"
    local dbname="$5"
    local output_file="$BUNDLE_DIR/sections/${section_name}_db_${dbname}.json"

    log_info "Collecting: $section_name (db=$dbname)"

    if [ ! -f "$sql_file" ]; then
        record_gap "$gap_section" "file_not_readable" \
            "Query file not found: $sql_file" ""
        printf '%s' '{"_error":"query_file_missing"}' > "$output_file"
        return 1
    fi

    # Replace version-gated and database placeholders
    local sql_text
    sql_text=$(sed \
        -e "s|{{SERVER_MAJOR}}|$SERVER_MAJOR|g" \
        -e "s|{{CAN_SELECT_AUTHID}}|$CAN_SELECT_AUTHID|g" \
        -e "s|{{SERVER_VERSION_NUM}}|$SERVER_VERSION_NUM|g" \
        -e "s|{{DATABASE}}|$dbname|g" \
        "$sql_file")

    local result
    result=$(run_sql "$dbname" "$sql_text" "$gap_section" "$remediation" 2>/dev/null) || true

    if [ -z "$result" ]; then
        echo '[]' > "$output_file"
    else
        printf '%s' "$result" > "$output_file"
    fi
}

# ── §2 Instance Identity ───────────────────────────────────────────────
log_info "--- Instance Identity ---"
collect_section "instance" "$SCRIPT_DIR/queries/instance.sql" \
    "instance" "SELECT from pg_settings requires pg_read_all_settings"

# ── §3 Configuration ──────────────────────────────────────────────────
log_info "--- Configuration ---"
collect_section "settings" "$SCRIPT_DIR/queries/settings.sql" \
    "configuration.settings" "GRANT pg_read_all_settings TO dbguard_collector"

collect_section "db_role_settings" "$SCRIPT_DIR/queries/db_role_settings.sql" \
    "configuration.db_role_settings" "GRANT pg_read_all_settings TO dbguard_collector"

# ── Read config files via pg_read_file (superuser only) ────────────────
log_info "--- Config Files ---"
_config_path=""
_config_path=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SHOW config_file;" 2>/dev/null || echo "")

if [ -n "$_config_path" ] && [ -f "$_config_path" ]; then
    # Read config file content — mask credential denylist at line level
    _config_content=""
    _config_content=$(psql -X -A -t -q -d "$PGDATABASE" \
        --set ON_ERROR_STOP=off \
        -c "SELECT pg_read_file($'$_config_path', 0, 1048576)" 2>/dev/null) || _config_content=""

    if [ -n "$_config_content" ]; then
        # Mask credential denylist directives line-by-line (POSIX grep)
        _masked_config=$(printf '%s\n' "$_config_content" | while IFS= read -r line; do
            if printf '%s' "$line" | egrep -qi '^[[:space:]]*(archive_command|archive_cleanup_command|restore_command|recovery_end_command|ssl_passphrase_command|primary_conninfo)[[:space:]]*='; then
                printf '%s\n' "$line" | sed -E 's/(password|passfile)=([^ ;]+)/\1=<redacted>/gi'
            else
                printf '%s\n' "$line"
            fi
        done)
        printf '%s' "$_masked_config" > "$BUNDLE_DIR/raw/postgresql.conf"
        record_redaction "configuration.config_files" "postgresql.conf" \
            "S2_SANITISED" "credential material (denylist directives)"
    fi

    # Get file metadata via host tools
    _config_sha=""
    if [ -f "$_config_path" ]; then
        _config_sha=$(sha256sum "$_config_path" 2>/dev/null | awk '{print $1}' || echo "")
    fi
    _config_mode=""
    if [ -f "$_config_path" ]; then
        _config_mode=$(stat -c '%a' "$_config_path" 2>/dev/null || echo "")
    fi

    # Write config file metadata as a JSON array
    if [ -n "$_config_content" ]; then
        printf '[{"path":"%s","content":true,"sha256":"%s","file_mode":"%s","owner":null,"group":null,"included_from":null}]' \
            "$(json_escape "$_config_path")" \
            "$_config_sha" \
            "$_config_mode" > "$BUNDLE_DIR/sections/config_files.json"
    else
        echo '[]' > "$BUNDLE_DIR/sections/config_files.json"
    fi
fi

# Read postgresql.auto.conf
_auto_path=""
_auto_path=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SHOW hba_file;" 2>/dev/null || echo "")
if [ -n "$_auto_path" ]; then
    # Derive auto.conf path from the main conf path
    _auto_path="${_config_path/auto.conf}" 2>/dev/null || true
fi
if [ -n "$_auto_path" ] && [ -f "$_auto_path" ]; then
    _auto_content=""
    _auto_content=$(psql -X -A -t -q -d "$PGDATABASE" \
        --set ON_ERROR_STOP=off \
        -c "SELECT pg_read_file($'$_auto_path', 0, 1048576)" 2>/dev/null) || _auto_content=""

    if [ -n "$_auto_content" ]; then
        _masked_auto=$(printf '%s\n' "$_auto_content" | while IFS= read -r line; do
            if printf '%s' "$line" | egrep -qi '^[[:space:]]*(archive_command|archive_cleanup_command|restore_command|recovery_end_command|ssl_passphrase_command|primary_conninfo)[[:space:]]*='; then
                printf '%s\n' "$line" | sed -E 's/(password|passfile)=([^ ;]+)/\1=<redacted>/gi'
            else
                printf '%s\n' "$line"
            fi
        done)
        printf '%s' "$_masked_auto" > "$BUNDLE_DIR/raw/postgresql.auto.conf"
    fi
fi

# Read pg_hba.conf
_hba_path=""
_hba_path=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SHOW hba_file;" 2>/dev/null || echo "")
if [ -n "$_hba_path" ] && [ -f "$_hba_path" ]; then
    cp "$_hba_path" "$BUNDLE_DIR/raw/pg_hba.conf" 2>/dev/null || true
    record_redaction "authentication" "pg_hba.conf" "S2_SANITISED" "credential material"
fi

# Read pg_ident.conf
_ident_path=""
_ident_path=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SHOW ident_file;" 2>/dev/null || echo "")
if [ -n "$_ident_path" ] && [ -f "$_ident_path" ]; then
    cp "$_ident_path" "$BUNDLE_DIR/raw/pg_ident.conf" 2>/dev/null || true
fi

# ── §4 Authentication ─────────────────────────────────────────────────
log_info "--- Authentication ---"
collect_section "authentication" "$SCRIPT_DIR/queries/hba.sql" \
    "authentication.hba_rules" "GRANT pg_read_server_files TO dbguard_collector"

collect_section "tls" "$SCRIPT_DIR/queries/tls.sql" \
    "authentication.tls" "GRANT pg_read_all_settings TO dbguard_collector"

# Collect certificate metadata via openssl (in bash, not SQL)
log_info "--- TLS Certificate Metadata ---"
_ssl_cert_path=""
_ssl_cert_path=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SHOW ssl_cert_file;" 2>/dev/null || echo "")

if [ -n "$_ssl_cert_path" ] && [ -f "$_ssl_cert_path" ]; then
    # Verify openssl can read the cert
    if openssl x509 -noout -subject -in "$_ssl_cert_path" >/dev/null 2>&1; then
        _subject=$(openssl x509 -noout -subject -in "$_ssl_cert_path" 2>/dev/null | sed 's/subject= *//')
        _issuer=$(openssl x509 -noout -issuer -in "$_ssl_cert_path" 2>/dev/null | sed 's/issuer= *//')
        _not_before=$(openssl x509 -noout -startdate -in "$_ssl_cert_path" 2>/dev/null | sed 's/notBefore=//')
        _not_after=$(openssl x509 -noout -enddate -in "$_ssl_cert_path" 2>/dev/null | sed 's/notAfter=//')
        _key_algo=$(openssl x509 -noout -text -in "$_ssl_cert_path" 2>/dev/null | grep -m1 "Public Key Algorithm:" | sed 's/.*: //')
        _key_size=$(openssl x509 -noout -text -in "$_ssl_cert_path" 2>/dev/null | grep -m1 "Public-Key:" | sed 's/.*(//;s/).*//')
        _sig_algo=$(openssl x509 -noout -text -in "$_ssl_cert_path" 2>/dev/null | grep -m1 "Signature Algorithm:" | sed 's/.*: //')
        _fingerprint=$(openssl x509 -noout -fingerprint -sha256 -in "$_ssl_cert_path" 2>/dev/null | sed 's/.*=//;s/://g')
        _file_mode=$(stat -c '%a' "$_ssl_cert_path" 2>/dev/null || echo "")
        _file_owner=$(stat -c '%U' "$_ssl_cert_path" 2>/dev/null || echo "")

        printf '{\n' > "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '  "server_cert": {\n' >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "path": "%s",\n' "$_ssl_cert_path" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "present": true,\n' >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "subject": "%s",\n' "$(json_escape "$_subject")" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "issuer": "%s",\n' "$(json_escape "$_issuer")" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "not_before": "%s",\n' "$_not_before" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "not_after": "%s",\n' "$_not_after" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "key_algorithm": "%s",\n' "$(json_escape "$_key_algo")" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "key_size_bits": "%s",\n' "$(json_escape "$_key_size")" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "signature_algorithm": "%s",\n' "$(json_escape "$_sig_algo")" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "sha256_fingerprint": "%s",\n' "$_fingerprint" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "file_mode": "%s",\n' "$_file_mode" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '    "owner": "%s"\n' "$_file_owner" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '  }\n' >> "$BUNDLE_DIR/sections/cert_metadata.json"
        printf '}\n' >> "$BUNDLE_DIR/sections/cert_metadata.json"

        # CA cert and CRL if configured
        _ca_path=""
        _ca_path=$(psql -X -A -t -q -d "$PGDATABASE" \
            -c "SHOW ssl_ca_file;" 2>/dev/null || echo "")
        _crl_path=""
        _crl_path=$(psql -X -A -t -q -d "$PGDATABASE" \
            -c "SHOW ssl_crl_file;" 2>/dev/null || echo "")

        _cert_ca=""
        if [ -n "$_ca_path" ] && [ -f "$_ca_path" ]; then
            _cert_ca="true"
            cp "$_ca_path" "$BUNDLE_DIR/raw/ssl_ca.pem" 2>/dev/null || true
        fi

        _cert_crl=""
        if [ -n "$_crl_path" ] && [ -f "$_crl_path" ]; then
            _cert_crl="true"
            cp "$_crl_path" "$BUNDLE_DIR/raw/ssl_crl.pem" 2>/dev/null || true
        fi

        # Update cert_metadata with CA/CRL info
        if [ -n "$_cert_ca" ] || [ -n "$_cert_crl" ]; then
            printf '    "ca_file_present": %s,\n' "${_cert_ca:-false}" >> "$BUNDLE_DIR/sections/cert_metadata.json"
            printf '    "crl_file_present": %s\n' "${_cert_crl:-false}" >> "$BUNDLE_DIR/sections/cert_metadata.json"
        fi
    fi
fi

# ── §5 Roles and privileges ───────────────────────────────────────────
log_info "--- Roles ---"
collect_section "roles" "$SCRIPT_DIR/queries/roles.sql" \
    "privileges.roles" \
    "GRANT EXECUTE ON FUNCTION dbguard_password_types() TO dbguard_collector"

collect_section "memberships" "$SCRIPT_DIR/queries/memberships.sql" \
    "privileges.memberships" \
    "GRANT pg_monitor TO dbguard_collector"

# ── Per-database queries ──────────────────────────────────────────────
log_info "--- Per-database queries ---"
DBLIST=""
DBLIST=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname;" 2>/dev/null || echo "")

if [ -n "$DBLIST" ]; then
    for dbname in $DBLIST; do
        log_info "Processing database: $dbname"
        # Try to connect to this database
        if ! psql -X -A -t -q -d "$dbname" -c "SELECT 1;" >/dev/null 2>&1; then
            record_gap "structure.databases.$dbname" "insufficient_privilege" \
                "Cannot connect to database $dbname" "Check database allow_connections"
            continue
        fi

        # Run per-database queries
        for qfile in object_privileges default_acls rls_policies secdef_functions extensions; do
            local_section="privileges"
            if [ "$qfile" = "extensions" ]; then
                local_section="structure"
            fi
            collect_section_db "$qfile" "$SCRIPT_DIR/queries/${qfile}.sql" \
                "${local_section}.${qfile}.$dbname" "" "$dbname"
        done
    done
fi

# ── §6 Structure ──────────────────────────────────────────────────────
log_info "--- Databases ---"
collect_section "databases" "$SCRIPT_DIR/queries/databases.sql" \
    "structure.databases" ""

# ── §7 Replication ────────────────────────────────────────────────────
log_info "--- Replication ---"
collect_section "replication" "$SCRIPT_DIR/queries/replication.sql" \
    "replication" "GRANT pg_read_all_settings TO dbguard_collector"

# ── §8 Logging ────────────────────────────────────────────────────────
log_info "--- Logging ---"
collect_section "logging" "$SCRIPT_DIR/queries/logging.sql" \
    "logging" "GRANT pg_read_all_settings TO dbguard_collector"

# ── §9 Operational baseline ───────────────────────────────────────────
log_info "--- Operational Baseline ---"
collect_section "operational" "$SCRIPT_DIR/queries/operational.sql" \
    "operational" "GRANT pg_monitor TO dbguard_collector"

# ---------------------------------------------------------------------------
# Phase 4: Bundle and exit
# ---------------------------------------------------------------------------
log_info "=== Collection complete, building bundle ==="

# Determine final status
if [ -s "$GAPS_FILE" ]; then
    _bundle_finalise "partial"
    EXIT_CODE=10
else
    _bundle_finalise "complete"
    EXIT_CODE=0
fi

# Print summary to operator
log_info "=== Summary ==="
if [ -s "$GAPS_FILE" ]; then
    _gap_count=$(wc -l < "$GAPS_FILE" | tr -d ' ')
    log_info "Collection completed with $_gap_count gap(s)."
    log_info "Review $BUNDLE_DIR/envelope.json for details."
else
    log_info "Collection completed with no gaps."
fi

# Copy gaps and redactions to the bundle dir for the final tarball
cp "$GAPS_FILE" "$BUNDLE_DIR/gaps_final.json" 2>/dev/null || true
cp "$REDACTIONS_FILE" "$BUNDLE_DIR/redactions_final.json" 2>/dev/null || true

log_info "Done. Exit code: $EXIT_CODE"
exit $EXIT_CODE
