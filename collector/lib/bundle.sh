#!/usr/bin/env bash
# DBGuardAI — Bundle helper: SHA256 checksums and tarball creation
# Must be sourced. Sets: BUNDLE_DIR, BUNDLE_FILE, EXIT_CODE.

# ---------------------------------------------------------------------------
# Checksum helper — probe for available tool
# ---------------------------------------------------------------------------

_CHECKSUM_CMD=""
_checksum_probe() {
    if command -v sha256sum >/dev/null 2>&1; then
        _CHECKSUM_CMD="sha256sum"
    elif command -v shasum >/dev/null 2>&1; then
        _CHECKSUM_CMD="shasum -a 256"
    elif command -v openssl >/dev/null 2>&1; then
        _CHECKSUM_CMD="openssl dgst -sha256"
    else
        log_error "No SHA-256 tool found (sha256sum, shasum, or openssl required)"
        return 1
    fi
    return 0
}

# _hash_file FILE — prints "hash  filename" to stdout
_hash_file() {
    local f="$1"
    case "$_CHECKSUM_CMD" in
        sha256sum)   sha256sum "$f" | awk '{print $1 "  " $2}' ;;
        *shasum*)    shasum -a 256 "$f" | awk '{print $1 "  " $2}' ;;
        *openssl*)   openssl dgst -sha256 "$f" | awk '{print $NF "  " $2}' ;;
    esac
}

# ---------------------------------------------------------------------------
# Generate SHA256SUMS
# ---------------------------------------------------------------------------

_generate_checksums() {
    cd "$BUNDLE_DIR" || return 1
    if ! _checksum_probe; then
        record_gap "bundle" "command_unavailable" \
            "No SHA-256 checksum tool found to verify bundle integrity." ""
        return 1
    fi

    # Compute checksums for all top-level files (not subdirectories, not the checksums file itself)
    : > SHA256SUMS
    for f in envelope.json collector.log; do
        if [ -f "$f" ]; then
            _hash_file "$f" >> SHA256SUMS
        fi
    done
    # Also hash section files and raw files
    # Use find to avoid glob-expansion failures when directories are empty
    find sections -maxdepth 1 -name '*.json' -type f -exec {} \; 2>/dev/null || true
    find raw -maxdepth 1 -type f -exec {} \; 2>/dev/null || true
    for f in $(find sections -maxdepth 1 -name '*.json' -type f 2>/dev/null; find raw -maxdepth 1 -type f 2>/dev/null); do
        if [ -f "$f" ]; then
            _hash_file "$f" >> SHA256SUMS
        fi
    done

    log_info "SHA256SUMS written with $(wc -l < SHA256SUMS | tr -d ' ') entries"
}

# ---------------------------------------------------------------------------
# Create tarball
# ---------------------------------------------------------------------------

_create_tarball() {
    local tarball="$BUNDLE_FILE"
    # Get the parent directory of the bundle dir for tar
    local bundle_dirname
    bundle_dirname=$(basename "$BUNDLE_DIR")
    local parent_dir
    parent_dir=$(dirname "$BUNDLE_DIR")

    cd "$parent_dir" || return 1

    if command -v tar >/dev/null 2>&1; then
        tar -czf "$tarball" "$bundle_dirname" 2>/dev/null
        if [ $? -eq 0 ]; then
            log_info "Tarball created: $tarball"
            # Clean up the uncompressed dir
            rm -rf "$BUNDLE_DIR"
        else
            log_error "Failed to create tarball"
            return 1
        fi
    else
        log_error "tar not found. Bundle directory left uncompressed."
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Finalise — write envelope, checksum, tarball, set exit code
# ---------------------------------------------------------------------------

_bundle_finalise() {
    local status="$1"

    # Write envelope.json
    _write_envelope "$status"

    # Generate checksums
    _generate_checksums || true

    # Create tarball
    _create_tarball || true

    # Set exit code
    case "$status" in
        complete) EXIT_CODE=0 ;;
        partial)  EXIT_CODE=10 ;;
        *)        EXIT_CODE=10 ;;
    esac
}

# ---------------------------------------------------------------------------
# Write envelope.json from collected data
# ---------------------------------------------------------------------------

_write_envelope() {
    local status="$1"
    local status_val
    if [ "$status" = "complete" ]; then
        status_val="COMPLETE"
    else
        status_val="PARTIAL"
    fi

    # Count gaps
    local gap_count=0
    if [ -f "$GAPS_FILE" ]; then
        gap_count=$(grep -c '.' "$GAPS_FILE" 2>/dev/null || echo 0)
    fi

    local redaction_count=0
    if [ -f "$REDACTIONS_FILE" ]; then
        redaction_count=$(grep -c '.' "$REDACTIONS_FILE" 2>/dev/null || echo 0)
    fi

    # Build gaps JSON array
    local gaps_json="[]"
    if [ "$gap_count" -gt 0 ]; then
        gaps_json="[$(tr '\n' ',' < "$GAPS_FILE" | sed 's/,$//')]"
    fi

    # Build redactions JSON array
    local redactions_json="[]"
    if [ "$redaction_count" -gt 0 ]; then
        redactions_json="[$(tr '\n' ',' < "$REDACTIONS_FILE" | sed 's/,$//')]"
    fi

    # Assemble envelope
    printf '{\n' > "$BUNDLE_DIR/envelope.json"
    printf '  "schema_version": "%s",\n' "$SCHEMA_VERSION" >> "$BUNDLE_DIR/envelope.json"
    printf '  "collector_version": "%s",\n' "$COLLECTOR_VERSION" >> "$BUNDLE_DIR/envelope.json"
    printf '  "collected_at": "%s",\n' "$COLLECTED_AT" >> "$BUNDLE_DIR/envelope.json"
    printf '  "target_id": "%s",\n' "$(json_escape "$TARGET_ID")" >> "$BUNDLE_DIR/envelope.json"
    printf '  "operator": null,\n' >> "$BUNDLE_DIR/envelope.json"
    printf '  "status": "%s",\n' "$status_val" >> "$BUNDLE_DIR/envelope.json"
    printf '  "collection_gaps": %s,\n' "$gaps_json" >> "$BUNDLE_DIR/envelope.json"
    printf '  "redactions": %s,\n' "$redactions_json" >> "$BUNDLE_DIR/envelope.json"
    printf '  "bundle_sha256": null\n' >> "$BUNDLE_DIR/envelope.json"
    printf '}\n' >> "$BUNDLE_DIR/envelope.json"

    # Update status: if there are gaps, force PARTIAL
    if [ "$gap_count" -gt 0 ]; then
        # Re-write with PARTIAL
        sed -i 's/"status": "COMPLETE"/"status": "PARTIAL"/' "$BUNDLE_DIR/envelope.json"
    fi
}
