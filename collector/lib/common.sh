#!/usr/bin/env bash
# DBGuardAI — Shared library: logging, gap recording, JSON helpers
#
# OUTPUT CONTRACT:
#   run_sql() writes query results to STDOUT.  The caller (dbguard-collect.sh)
#   captures stdout with a command-substitution variable and writes it to the
#   section JSON file.
#   If the query fails, run_sql writes an empty string to stdout and returns
#   non-zero; collect_section then records a gap.
#
# DESIGN: This file defines functions and nothing else.  No guards, no
#   side effects at source time.  The caller must invoke init_runtime()
#   after setting COLLECTOR_LOG, GAPS_FILE, REDACTIONS_FILE.

# ---- Logging ---------------------------------------------------------------
# All log lines go to the log file.  Errors also go to stderr.

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

# ---- Runtime initialisation ───────────────────────────────────────────────
# Called by dbguard-collect.sh after it has set the file-path variables.
# Exits 1 if paths are missing so the caller fails early with a clear message.

init_runtime() {
    if [ -z "${COLLECTOR_LOG:-}" ]; then
        echo "FATAL: COLLECTOR_LOG not set. Call init_runtime() after setting COLLECTOR_LOG." >&2
        return 1
    fi
    if [ -z "${GAPS_FILE:-}" ]; then
        echo "FATAL: GAPS_FILE not set. Call init_runtime() after setting GAPS_FILE." >&2
        return 1
    fi
    if [ -z "${REDACTIONS_FILE:-}" ]; then
        echo "FATAL: REDACTIONS_FILE not set. Call init_runtime() after setting REDACTIONS_FILE." >&2
        return 1
    fi
    return 0
}

# ---- Gap recording ---------------------------------------------------------
# Records a JSON gap entry.  Called when a query cannot produce data.

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
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e $'s/\t/\\t/g'
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
    # ON_ERROR_STOP=on: psql returns non-zero on any SQL error.
    # We capture stderr into a temp so we can report it in the gap.
    local stderr_file
    stderr_file="$(mktemp)"
    local result
    local rc=0

    result=$(psql -X -t -A -F$'\t' -q -d "$database" \
        --set ON_ERROR_STOP=on \
        -c "$sql_text" 2>"$stderr_file") || rc=$?

    if [ "$rc" -ne 0 ]; then
        # Query failed — capture stderr into the gap description
        local err_text
        err_text="$(tr '\n' ' ' < "$stderr_file" | sed 's/  */ /g; s/^ *//; s/ *$//')"
        if [ -n "$gap_section" ]; then
            record_gap "$gap_section" \
                "error" \
                "psql exit code $rc: ${err_text:-unknown error}" \
                "$remediation"
        fi
        rm -f "$stderr_file"
        return 1
    fi

    rm -f "$stderr_file"

    if [ -n "$result" ]; then
        # Query succeeded and returned rows
        printf '%s' "$result"
        return 0
    else
        # Query succeeded but returned zero rows — not an error
        # Caller decides whether to treat zero rows as a gap.
        # For this collector we return success with empty output.
        return 0
    fi
}
