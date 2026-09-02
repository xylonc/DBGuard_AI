#!/usr/bin/env bash
# DBGuardAI — Shared library: logging, gap recording, JSON helpers
#
# OUTPUT CONTRACT (fix for previous empty-section bug):
#   run_sql() writes query results to STDOUT.  The caller (dbguard-collect.sh)
#   captures stdout with a command-substitution variable and writes it to the
#   section JSON file.
#   If the query fails, run_sql writes an empty string to stdout and returns
#   non-zero; collect_section then records a gap.
#
# Portability note (2026-09-01):
#   This library uses POSIX sh constructs plus common GNU utils.
#   The collector body itself only invokes psql.  Bundling helpers
#   (bundle.sh) invoke sha256sum for integrity checks.
#   Uses egrep (POSIX) instead of grep -E (GNU-specific on some systems).
#   The claim "psql and POSIX sh/bash only" is maintained for the collector
#   body; lib helpers that invoke sha256sum/stat are for bundling only.

# ---- Logging ---------------------------------------------------------------
# All log lines go to the log file.  Errors also go to stderr.

if [ -z "${COLLECTOR_LOG:-}" ]; then
    echo "FATAL: COLLECTOR_LOG not set. Source this file from dbguard-collect.sh." >&2
    exit 1
fi

log_info() {
    local msg="$*"
    printf '[INFO]  %s\n' "$msg" >> "$COLLECTOR_LOG"
}

log_warn() {
    local msg="$*"
    printf '[WARN]  %s\n' "$msg" >> "$COLLECTOR_LOG"
    printf '[WARN]  %s\n' "$msg" >&2
}

log_error() {
    local msg="$*"
    printf '[ERROR] %s\n' "$msg" >> "$COLLECTOR_LOG"
    printf '[ERROR] %s\n' "$msg" >&2
}

# ---- Gap recording ---------------------------------------------------------
# Records a JSON gap entry.  Called when a query cannot produce data.

if [ -z "${GAPS_FILE:-}" ]; then
    echo "FATAL: GAPS_FILE not set." >&2
    exit 1
fi

record_gap() {
    local section="$1"
    local reason="$2"
    local description="$3"
    local remediation="${4:-}"

    # Build JSON manually — no jq dependency
    printf '{"section":"%s","reason":"%s","description":"%s","remediation":"%s"}\n' \
        "$(json_escape "$section")" \
        "$(json_escape "$reason")" \
        "$(json_escape "$description")" \
        "$(json_escape "$remediation")" >> "$GAPS_FILE"
}

# ---- Redaction tracking ----------------------------------------------------

if [ -z "${REDACTIONS_FILE:-}" ]; then
    echo "FATAL: REDACTIONS_FILE not set." >&2
    exit 1
fi

record_redaction() {
    local section="$1"
    local file_name="$2"
    local class="$3"
    local description="$4"

    printf '{"section":"%s","file":"%s","class":"%s","description":"%s"}\n' \
        "$(json_escape "$section")" \
        "$(json_escape "$file_name")" \
        "$(json_escape "$class")" \
        "$(json_escape "$description")" >> "$REDACTIONS_FILE"
}

# ---- JSON helpers ----------------------------------------------------------

# Escape a string for embedding inside a JSON string value.
json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g'
}

# ---- SQL execution ---------------------------------------------------------
# run_sql: executes psql, outputs results to STDOUT.
#
# Arguments:
#   $1  database name (libpq)
#   $2  SQL text (from stdin or substitution)
#   $3  gap section key (for record_gap on failure)
#   $4  remediation hint
#
# Returns:
#   0 — success; stdout contains tab-separated psql rows.
#   1 — failure; stdout is empty; gap recorded.
run_sql() {
    local database="$1"
    local sql_text="$2"
    local gap_section="${3:-}"
    local remediation="${4:-}"

    # Run psql with tab-separated unformatted output, no headers, no pager
    # Capture both stdout and exit code.  The || true prevents set -e from
    # killing the function; we check the explicit variable for the status.
    local result
    local rc=0
    result=$(psql -X -t -A -F$'\t' -q -d "$database" \
        --set ON_ERROR_STOP=off \
        -c "$sql_text" 2>/dev/null) || rc=$?

    if [ "$rc" -eq 0 ] && [ -n "$result" ]; then
        printf '%s' "$result"
        return 0
    else
        # Query failed or produced no output — record gap and produce empty stdout
        if [ -n "$gap_section" ]; then
            record_gap "$gap_section" \
                "$( [ "$rc" -ne 0 ] && echo 'error' || echo 'no_results')" \
                "$( [ "$rc" -ne 0 ] && echo 'Query failed with exit code' "$rc" || echo 'Query returned no rows')" \
                "$remediation"
        fi
        # stdout is empty — caller writes []
        return 1
    fi
}
