#!/usr/bin/env bash
# DBGuardAI — Bundle: SHA256SUMS + tarball creation
#
# Must be sourced by dbguard-collect.sh.  Provides _create_bundle().
#
# ENVELOPE SHAPE:
#   The on-disk JSON is a single object matching manifest.py's Envelope model.
#   It contains schema_version, collector_version, collected_at, target_id,
#   server_version_full, server_version_num, current_user, status,
#   gaps (JSON array), redactions (JSON array), and has_gap (bool).

# ---------------------------------------------------------------------------
# _create_bundle: write envelope.json, SHA256SUMS, and .tar.gz
# ---------------------------------------------------------------------------
# Arguments:
#   $1  status  — "complete" or "partial"
# ---------------------------------------------------------------------------
_create_bundle() {
    local status="$1"

    # ---- Build gaps/redactions as JSON arrays ------------------------------
    _gaps_json="[]"
    if [ -s "$GAPS_FILE" ]; then
        _gaps_json="[$(tr '\n' ',' < "$GAPS_FILE" | sed 's/,$//')]"
    fi

    _redactions_json="[]"
    if [ -s "$REDACTIONS_FILE" ]; then
        _redactions_json="[$(tr '\n' ',' < "$REDACTIONS_FILE" | sed 's/,$//')]"
    fi

    # ---- Determine has_gap ────────────────────────────────────────────────
    if [ -s "$GAPS_FILE" ]; then
        _has_gap="true"
    else
        _has_gap="false"
    fi

    # ---- envelope.json (single object, matches Envelope model) ────────────
    cat > "$BUNDLE_DIR/envelope.json" <<_EOF
{
  "schema_version": "${SCHEMA_VERSION}",
  "collector_version": "${COLLECTOR_VERSION}",
  "collected_at": "${COLLECTED_AT}",
  "target_id": "${TARGET_ID}",
  "server_version_full": "${SERVER_VERSION_FULL}",
  "server_version_num": ${SERVER_VERSION_NUM:-null},
  "current_user": ${CURRENT_USER:-null},
  "status": "${status}",
  "gaps": ${_gaps_json},
  "redactions": ${_redactions_json},
  "has_gap": ${_has_gap}
}
_EOF

    log_info "envelope.json written."

    # ---- SHA256SUMS --------------------------------------------------------
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
    (
        cd "$(dirname "$BUNDLE_DIR")"
        tar czf "$(basename "${BUNDLE_DIR}.tar.gz")" "$(basename "$BUNDLE_DIR")"
    )

    log_info "Bundle written to: ${BUNDLE_DIR}.tar.gz"
}
