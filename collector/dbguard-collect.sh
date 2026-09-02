#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║  DBGuardAI SQL Collector v1.0.0 (three-CIS-control)             ║
# ║  ────────────────────────────────────────────────────────────── ║
# ║  Read-only PostgreSQL security posture snapshot.                ║
# ║  Implements CIS 5.1, 5.2, 5.3 only.                             ║
# ║                                                                   ║
# ║  No Python, no jq. Uses psql + POSIX sh/bash + GNU coreutils    ║
# ║  (sha256sum, stat, egrep).                                       ║
# ║  Never handles credentials. Hashes never leave the SECURITY      ║
# ║   DEFINER function.                                              ║
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
# Derive script directory and source libraries
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Libraries declare functions only — no side effects at source time
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/probe.sh"
source "$SCRIPT_DIR/lib/bundle.sh"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --output=*) OUTPUT_DIR="${arg#--output=}" ;;
        --target=*) TARGET_ID="${arg#--target=}" ;;
        --help)
            echo "Usage: $0 [--output=DIR] [--target=ID]"
            echo ""
            echo "Environment variables:"
            echo "  TARGET_ID   Opaque identifier (default: unknown)"
            echo "  PGDATABASE  Database to connect to (default: postgres)"
            echo "  PGUSER      PostgreSQL user (default: current OS user)"
            echo ""
            echo "Uses standard libpq authentication."
            exit 0
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Setup output directory path (not yet created)
# ---------------------------------------------------------------------------
TIMESTAMP="$(date -u '+%Y%m%dT%H%M%SZ')"
if [ -n "$OUTPUT_DIR" ]; then
    BUNDLE_DIR="${OUTPUT_DIR}/dbguard-${TARGET_ID}-${TIMESTAMP}"
    TMP_CLEANUP_DIR=""
else
    TMP_CLEANUP_DIR="$(mktemp -d "/tmp/dbguard-${TARGET_ID}-${TIMESTAMP}.XXXXXXXXXX")"
    BUNDLE_DIR="$TMP_CLEANUP_DIR"
fi

COLLECTED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ---------------------------------------------------------------------------
# Phase 1: Preflight (before any directory creation)
# ---------------------------------------------------------------------------
log_info "=== DBGuardAI Collector $COLLECTOR_VERSION ==="
log_info "Target: $TARGET_ID | DB: $PGDATABASE"

# Invoke probe function (NOT sourced-at-time)
probe_target || {
    _local_exit=$?
    log_error "Preflight failed with exit code $_local_exit."
    # Clean up any temp directory created by mktemp
    if [ -n "$TMP_CLEANUP_DIR" ] && [ -d "$TMP_CLEANUP_DIR" ]; then
        rm -rf "$TMP_CLEANUP_DIR"
    fi
    exit $_local_exit
}

log_info "Output directory: $BUNDLE_DIR"
log_info "Server: $SERVER_VERSION_FULL ($SERVER_VERSION_NUM)"

# ---------------------------------------------------------------------------
# Create output directory (only after probe passes)
# ---------------------------------------------------------------------------
mkdir -p "$BUNDLE_DIR/sections" "$BUNDLE_DIR/raw"

# Initialize tracking files
: > "$BUNDLE_DIR/collector.log"
: > "$BUNDLE_DIR/gaps.tmp"
: > "$BUNDLE_DIR/redactions.tmp"

COLLECTOR_LOG="$BUNDLE_DIR/collector.log"
GAPS_FILE="$BUNDLE_DIR/gaps.tmp"
REDACTIONS_FILE="$BUNDLE_DIR/redactions.tmp"

# ---------------------------------------------------------------------------
# Phase 2: Collect three CIS controls
# ---------------------------------------------------------------------------

collect_section() {
    # Collects a SQL query and writes its stdout to sections/<name>.json.
    # Usage: collect_section <section_name> <sql_file> <gap_key> [remediation]
    local section_name="$1"
    local sql_file="$2"
    local gap_key="${3:-}"
    local remediation="${4:-}"
    local output_file="$BUNDLE_DIR/sections/${section_name}.json"

    log_info "Collecting: $section_name"

    if [ ! -f "$sql_file" ]; then
        record_gap "$gap_key" "file_not_readable" \
            "Query file not found: $sql_file" ""
        printf '[]' > "$output_file"
        return 1
    fi

    # Read SQL and replace version-gated placeholders
    local sql_text
    sql_text=$(sed \
        -e "s|{{SERVER_MAJOR}}|$SERVER_MAJOR|g" \
        -e "s|{{CAN_SELECT_AUTHID}}|$CAN_SELECT_AUTHID|g" \
        "$sql_file")

    # Run SQL — output flows via stdout (see common.sh contract)
    local result
    if result=$(run_sql "$PGDATABASE" "$sql_text" "$gap_key" "$remediation" 2>/dev/null); then
        if [ -n "$result" ]; then
            printf '%s' "$result" > "$output_file"
        else
            printf '[]' > "$output_file"
        fi
    else
        # run_sql already recorded the gap; write empty
        printf '[]' > "$output_file"
    fi
}

# ── CIS 5.1: log_connections ──────────────────────────────────────────
log_info "--- CIS 5.1: log_connections ---"
collect_section "log_connections" \
    "$SCRIPT_DIR/queries/log_connections.sql" \
    "cis.5.1" \
    "GRANT pg_read_all_settings TO dbguard_collector"

# ── CIS 5.2: CREATE on public not granted to PUBLIC ──────────────────
log_info "--- CIS 5.2: public schema ACL ---"

# Get list of connectable databases
DBLIST=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname;" 2>/dev/null || echo "")

if [ -n "$DBLIST" ]; then
    # Collect ACL for each database, then combine into a JSON array
    : > "$BUNDLE_DIR/raw/acl_entries.tmp"
    for dbname in $DBLIST; do
        if ! psql -X -t -A -q -d "$dbname" -c "SELECT 1;" >/dev/null 2>&1; then
            record_gap "cis.5.2" "insufficient_privilege" \
                "Cannot connect to database $dbname" ""
            continue
        fi

        local_result=$(run_sql "$dbname" \
            "$(cat "$SCRIPT_DIR/queries/public_schema_acl.sql")" \
            "cis.5.2.$dbname" "" 2>/dev/null) || local_result=""

        if [ -n "$local_result" ]; then
            # Prepend database name (query doesn't include it — current_database() does)
            printf '%s\n' "$local_result" >> "$BUNDLE_DIR/raw/acl_entries.tmp"
        else
            record_gap "cis.5.2.$dbname" "error" \
                "Failed to query public schema ACL" ""
        fi
    done

    # Combine entries into a JSON array
    if [ -s "$BUNDLE_DIR/raw/acl_entries.tmp" ]; then
        # Each line is a JSON object; wrap in array
        printf '[' > "$BUNDLE_DIR/sections/public_schema_acl.json"
        first=true
        while IFS= read -r line; do
            if [ "$first" = true ]; then
                first=false
            else
                printf ',' >> "$BUNDLE_DIR/sections/public_schema_acl.json"
            fi
            printf '%s' "$line" >> "$BUNDLE_DIR/sections/public_schema_acl.json"
        done < "$BUNDLE_DIR/raw/acl_entries.tmp"
        printf ']' >> "$BUNDLE_DIR/sections/public_schema_acl.json"
    else
        printf '[]' > "$BUNDLE_DIR/sections/public_schema_acl.json"
    fi
    rm -f "$BUNDLE_DIR/raw/acl_entries.tmp"
else
    printf '[]' > "$BUNDLE_DIR/sections/public_schema_acl.json"
fi

# ── CIS 5.3: No role uses md5 password storage ───────────────────────
log_info "--- CIS 5.3: Password storage ---"
collect_section "password_storage" \
    "$SCRIPT_DIR/queries/roles_password_type.sql" \
    "cis.5.3" \
    "GRANT EXECUTE ON FUNCTION dbguard_password_types() TO dbguard_collector"

# ---------------------------------------------------------------------------
# Phase 3: Bundle
# ---------------------------------------------------------------------------
log_info "=== Building bundle ==="

# Determine final status
if [ -s "$GAPS_FILE" ]; then
    _create_bundle "partial"
    EXIT_CODE=10
else
    _create_bundle "complete"
    EXIT_CODE=0
fi

# Print summary
log_info "=== Summary ==="
if [ -s "$GAPS_FILE" ]; then
    _gap_count=$(wc -l < "$GAPS_FILE" | tr -d ' ')
    log_info "Collection completed with $_gap_count gap(s)."
else
    log_info "Collection completed with no gaps."
fi

log_info "Done. Exit code: $EXIT_CODE"
exit $EXIT_CODE
