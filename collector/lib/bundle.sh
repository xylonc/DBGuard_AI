#!/usr/bin/env bash
# DBGuardAI — Bundle: SHA256SUMS + tarball creation
#
# Must be sourced by dbguard-collect.sh.  Provides _create_bundle().
#
# FIXES vs previous submission:
#   - Removed: find ... -exec {} \;  (executed every file as a program)
#   - Removed: rm -rf "$BUNDLE_DIR"  (deleted dir before files copied)
#   - Removed: gaps/redactions from tarball contents (they were inside BUNDLE_DIR)

# ---------------------------------------------------------------------------
# _create_bundle: write envelope.json, SHA256SUMS, and .tar.gz
# ---------------------------------------------------------------------------
# Arguments:
#   $1  status  — "complete" or "partial"
# ---------------------------------------------------------------------------
_create_bundle() {
    local status="$1"
    local bundle_file="${BUNDLE_DIR}.tar.gz"

    # ---- Build gaps/redactions as JSON arrays ------------------------------
    _gaps_json="[]"
    if [ -s "$GAPS_FILE" ]; then
        _gaps_json="[$(cat "$GAPS_FILE" | tr '\n' ',' | sed 's/,$//')]"
    fi

    _redactions_json="[]"
    if [ -s "$REDACTIONS_FILE" ]; then
        _redactions_json="[$(cat "$REDACTIONS_FILE" | tr '\n' ',' | sed 's/,$//')]"
    fi

    # ---- envelope.json -----------------------------------------------------
    cat > "$BUNDLE_DIR/envelope.json" <<_EOF
{
  "envelope": {
    "schema_version": "0.2.0",
    "collector_version": "${COLLECTOR_VERSION}",
    "collected_at": "${COLLECTED_AT}",
    "target_id": "${TARGET_ID}",
    "server_version_full": "${SERVER_VERSION_FULL}",
    "server_version_num": ${SERVER_VERSION_NUM:-null},
    "current_user": "${CURRENT_USER:-null}",
    "status": "${status}"
  },
  "gaps": ${_gaps_json},
  "redactions": ${_redactions_json}
}
_EOF

    log_info "envelope.json written."

    # ---- SHA256SUMS --------------------------------------------------------
    # Hash all .json files in sections/ and all files in raw/
    : > "$BUNDLE_DIR/SHA256SUMS"

    (
        cd "$BUNDLE_DIR"
        find sections -maxdepth 1 -name '*.json' -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum >> SHA256SUMS 2>/dev/null || true
        find raw -maxdepth 1 -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum >> SHA256SUMS 2>/dev/null || true
    )

    if [ -s "$BUNDLE_DIR/SHA256SUMS" ]; then
        log_info "SHA256SUMS written with $(wc -l < "$BUNDLE_DIR/SHA256SUMS" | tr -d ' ') entries."
    else
        log_warn "SHA256SUMS is empty (no files to hash)."
    fi

    # ---- Tarball -----------------------------------------------------------
    # Do NOT delete BUNDLE_DIR — it contains the files we are packaging.
    (
        cd "$(dirname "$BUNDLE_DIR")"
        tar czf "$(basename "$bundle_file")" "$(basename "$BUNDLE_DIR")"
    )

    log_info "Bundle written to: $bundle_file"
}
