#!/usr/bin/env bash
# DBGuardAI — Common library
# Shared logging, gap recording, redaction helpers, and JSON utilities.
# All output helpers are leak-safe: no secret content is ever written.

# ---------------------------------------------------------------------------
# Globals (set by dbguard-collect.sh at startup)
# ---------------------------------------------------------------------------
COLLECTOR_LOG=""        # path to collector.log
GAPS_FILE=""            # temp file for gap JSON lines
REDACTIONS_FILE=""      # temp file for redaction JSON lines
TARGET_ID=""            # opaque target identifier
COLLECTED_AT=""         # ISO-8601 UTC timestamp
COLLECTOR_VERSION="1.0.0"
SERVER_VERSION_NUM=0    # set by probe.sh
SERVER_VERSION_FULL=""  # set by probe.sh

# ---------------------------------------------------------------------------
# Logging — all secrets go through leak_check() before reaching here
# ---------------------------------------------------------------------------

# _log_inner — writes one line to collector.log
_log_inner() {
    local level="$1" shift
    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '%s [%s] %s\n' "$ts" "$level" "$*" >> "$COLLECTOR_LOG"
}

log_info()  { _log_inner "INFO"  "$*"; }
log_warn()  { _log_inner "WARN"  "$*"; }
log_error() { _log_inner "ERROR" "$*"; }
log_debug() { _log_inner "DEBUG" "$*"; }

# ---------------------------------------------------------------------------
# Gap recording
# ---------------------------------------------------------------------------

# record_gap SECTION REASON DETAIL [REMEDIATION_HINT]
# Writes one JSON line to GAPS_FILE. Each line is a CollectionGap fragment.
record_gap() {
    local section="$1" reason="$2" detail="$3" hint="${4:-}"
    # Escape for JSON (handles backslashes, quotes, control chars)
    local esc_detail esc_hint
    esc_detail=$(json_escape "$detail")
    esc_hint=$(json_escape "$hint")
    local reason_key
    # Map shell reason strings to enum keys
    case "$reason" in
        insufficient_privilege)    reason_key="INSUFFICIENT_PRIVILEGE" ;;
        not_applicable_platform)   reason_key="NOT_APPLICABLE_PLATFORM" ;;
        not_applicable_version)    reason_key="NOT_APPLICABLE_VERSION" ;;
        file_not_readable)         reason_key="FILE_NOT_READABLE" ;;
        command_unavailable)       reason_key="COMMAND_UNAVAILABLE" ;;
        redacted_by_policy)        reason_key="REDACTED_BY_POLICY" ;;
        error)                     reason_key="ERROR" ;;
        *)                         reason_key="ERROR" ;;
    esac
    if [ -n "$esc_hint" ]; then
        printf '{"section":"%s","reason":"%s","detail":"%s","remediation_hint":"%s"}\n' \
            "$section" "$reason_key" "$esc_detail" "$esc_hint" >> "$GAPS_FILE"
    else
        printf '{"section":"%s","reason":"%s","detail":"%s","remediation_hint":null}\n' \
            "$section" "$reason_key" "$esc_detail" >> "$GAPS_FILE"
    fi
}

# ---------------------------------------------------------------------------
# Redaction recording
# ---------------------------------------------------------------------------

# record_redaction SECTION FIELD SANITISATION CLASS POLICY [LINE_NUMBER]
record_redaction() {
    local section="$1" field="$2" sanitisation="$3" policy="$4" lineno="${5:-}"
    local san_key
    case "$sanitisation" in
        S0|S0_NEVER_COLLECTED)  san_key="S0_NEVER_COLLECTED" ;;
        S1|S1_DERIVED)          san_key="S1_DERIVED" ;;
        S2|S2_SANITISED)        san_key="S2_SANITISED" ;;
        S3|S3_PRESENCE)         san_key="S3_PRESENCE" ;;
        S4|S4_VERBATIM_CONFIDENTIAL) san_key="S4_VERBATIM_CONFIDENTIAL" ;;
        *)                      san_key="S4_VERBATIM_CONFIDENTIAL" ;;
    esac
    if [ -n "$lineno" ]; then
        printf '{"section":"%s","field":"%s","sanitisation":"%s","policy":"%s","line_number":%s}\n' \
            "$section" "$field" "$san_key" "$policy" "$lineno" >> "$REDACTIONS_FILE"
    else
        printf '{"section":"%s","field":"%s","sanitisation":"%s","policy":"%s","line_number":null}\n' \
            "$section" "$field" "$san_key" "$policy" >> "$REDACTIONS_FILE"
    fi
}

# ---------------------------------------------------------------------------
# JSON helpers — pure bash, no jq required
# ---------------------------------------------------------------------------

# json_escape STRING — return a JSON-safe string (handles \, ", newlines, tabs)
json_escape() {
    local s="$1"
    # Use sed for POSIX-compatible escaping
    printf '%s' "$s" | sed \
        -e 's/\\/\\\\/g' \
        -e 's/"/\\"/g' \
        -e 's/\t/\\t/g' \
        -e 's/$/\\n/' | tr -d '\n' | sed 's/\\n$//'
}

# ---------------------------------------------------------------------------
# SQL execution wrapper — runs psql, captures stderr, classifies gaps
# ---------------------------------------------------------------------------

# run_sql DBNAME SQL_TEXT [SECTION_PREFIX] [REMEDIATION_HINT]
# Runs a psql command. On error, classifies the stderr and records a gap.
# Prints stdout to stdout; does not return the raw output (caller reads
# section-specific temp files written by the SQL itself).
# Returns 0 on success, 1 on error.
run_sql() {
    local db="$1" sql_text="$2" section="${3:-}" hint="${4:-}"
    local stderr_file
    stderr_file=$(mktemp "${TMPDIR:-/tmp}/dbguard-stderr-XXXXXX")

    # Write SQL to a temp file so psql -f works reliably; avoids shell quoting
    local sql_file
    sql_file=$(mktemp "${TMPDIR:-/tmp}/dbguard-sql-XXXXXX")
    printf '%s' "$sql_text" > "$sql_file"

    local psql_output
    psql_output=$(psql -X -A -t -q --set ON_ERROR_STOP=off \
        -d "$db" \
        -f "$sql_file" 2>"$stderr_file")
    local rc=$?

    rm -f "$sql_file"

    if [ $rc -ne 0 ] || [ -s "$stderr_file" ]; then
        # Classify stderr
        local gap_reason="error"
        local gap_detail=""
        local stderr_content
        stderr_content=$(tr -d '\0' < "$stderr_file" | tr '\n' ' ' | sed 's/  */ /g')

        case "$stderr_content" in
            *"permission denied"*|*"must be superuser"*|*"must be a member of"*)
                gap_reason="insufficient_privilege" ;;
            *"does not exist"*)
                gap_reason="not_applicable_version" ;;
            *"could not open file"*|*"No such file"*)
                gap_reason="file_not_readable" ;;
        esac

        if [ -n "$section" ]; then
            local esc_detail
            esc_detail=$(json_escape "$stderr_content")
            record_gap "$section" "$gap_reason" "$esc_detail" "$hint"
        fi

        rm -f "$stderr_file"
        return 1
    fi

    rm -f "$stderr_file"
    return 0
}

# ---------------------------------------------------------------------------
# Run a SQL query that produces JSON directly via psql (preferred path)
# ---------------------------------------------------------------------------

# psql_json DBNAME SQL_TEXT
# Runs psql and returns the JSON output. Caller checks if output is empty.
psql_json() {
    local db="$1" sql_text="$2"
    psql -X -A -t -q --set ON_ERROR_STOP=off -d "$db" \
        --set ON_ERROR_STOP=off \
        -c "$sql_text" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Read a config file from the host via pg_read_file (superuser-only)
# ---------------------------------------------------------------------------

# read_config_file FILE_PATH [MAX_BYTES]
# Returns file content via stdout. Returns 1 if unreadable.
read_config_file() {
    local filepath="$1"
    local max_bytes="${2:-1048576}"  # 1MB default
    psql -X -A -t -q -d "$PGDATABASE" \
        --set ON_ERROR_STOP=off \
        -c "SELECT pg_read_file($'$filepath', 0, $max_bytes)" 2>/dev/null
}
