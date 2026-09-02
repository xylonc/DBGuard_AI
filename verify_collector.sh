#!/usr/bin/env bash
# DBGuardAI collector — verification runbook
set -uo pipefail
REPO_ROOT="$(pwd)"
CONTAINER="dbguard-verify"
PGPORT_HOST=55432
OUT="$REPO_ROOT/verify-out"
PASS=0; FAIL=0; WARN=0

ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
warn() { WARN=$((WARN+1)); printf '  \033[33mWARN\033[0m  %s\n' "$1"; }
hdr()  { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }

rm -rf "$OUT"; mkdir -p "$OUT"

# ============================================================================
# 0. Static checks (no database needed)
# ============================================================================
hdr "0. Static checks (no database needed)"

# 0a. manifest.py check
echo "0a. Is manifest.py the reviewed v0.2, or did the agent regenerate one?"
if [ -f manifest.py ]; then
    ok "manifest.py exists at repo root"
    for marker in 'extra="forbid"' "extra='forbid'" 'has_gap' 'primary_conninfo'; do
        if grep -q "$marker" manifest.py; then
            ok "manifest.py contains: $marker"
        else
            bad "manifest.py MISSING: $marker  <-- likely regenerated, not the reviewed file"
        fi
    done
    if grep -q 'class SnapshotBundle' manifest.py; then
        bad "manifest.py defines SnapshotBundle (class name from the deleted Python collector)"
    fi
    echo "  --- classes defined in manifest.py ---"
    grep -n '^class ' manifest.py | sed 's/^/    /'
else
    bad "manifest.py NOT at repo root"
fi

# 0b. log-level shift bug
echo "0b. The log-level shift bug — fix is to ADD a shift, not remove it"
if grep -rn 'local level="$1" shift' collector/lib/ 2>/dev/null; then
    bad "log helper still has 'local level=\"\$1\" shift' (declares a var named shift)"
elif grep -rn 'local level="$1"; *shift' collector/lib/ 2>/dev/null; then
    ok "log helper has a real shift"
else
    warn "could not classify the log helper — inspect lib/common.sh by hand"
    grep -n -A3 'log_info\|log_warn\|log_error' collector/lib/common.sh 2>/dev/null | head -20 | sed 's/^/    /'
fi

# 0c. public schema ACL must read nspacl
echo "0c. public schema ACL — must read nspacl, not just nspowner"
if [ -f collector/queries/public_schema_acl.sql ]; then
    if grep -q 'nspacl' collector/queries/public_schema_acl.sql; then
        ok "public_schema_acl.sql reads nspacl"
    else
        bad "public_schema_acl.sql does NOT read nspacl — cannot answer 'does PUBLIC hold CREATE'"
    fi
    echo "  --- query ---"
    sed 's/^/    /' collector/queries/public_schema_acl.sql
else
    bad "collector/queries/public_schema_acl.sql not found"
fi

# 0d. Probe before mkdir
echo "0d. Does probing happen before any directory is created?"
_probe_line=$(grep -n 'probe_target' collector/dbguard-collect.sh 2>/dev/null | grep -v '^.*#' | head -1 | cut -d: -f1)
_mkdir_line=$(grep -n '^mkdir -p\|mkdir -p "\$BUNDLE_DIR"' collector/dbguard-collect.sh 2>/dev/null | head -1 | cut -d: -f1)
if [ -n "${_probe_line:-}" ] && [ -n "${_mkdir_line:-}" ]; then
    if [ "$_probe_line" -lt "$_mkdir_line" ]; then
        ok "probe_target() (line $_probe_line) runs before mkdir (line $_mkdir_line)"
    else
        bad "mkdir (line $_mkdir_line) runs before probe_target() (line $_probe_line) — refusal will leave a directory"
    fi
else
    warn "could not locate probe/mkdir ordering automatically"
fi

# 0e. Portability
echo "0e. Portability claim vs reality"
if grep -rn 'stat --format\|stat -c' collector/ >/dev/null 2>&1; then
    warn "GNU 'stat' still used at 3-control scope (no config files are read — why is it there?)"
    grep -rn 'stat --format\|stat -c' collector/ | sed 's/^/    /'
else
    ok "no GNU stat in collector"
fi
if grep -rn 'find .* -exec {} \;' collector/ >/dev/null 2>&1; then
    bad "find -exec {} still present"
else
    ok "no find -exec {}"
fi
if grep -rn 'rm -rf "\$BUNDLE_DIR"' collector/ >/dev/null 2>&1; then
    bad "rm -rf \$BUNDLE_DIR still present"
else
    ok "no rm -rf \$BUNDLE_DIR"
fi

# 0f. Syntax
echo "0f. Syntax"
for f in collector/dbguard-collect.sh collector/lib/*.sh; do
    bash -n "$f" 2>/dev/null && ok "bash -n $f" || bad "bash -n $f"
done
if command -v shellcheck >/dev/null 2>&1; then
    echo "  --- shellcheck (informational) ---"
    shellcheck -S warning collector/dbguard-collect.sh collector/lib/*.sh 2>&1 | head -40 | sed 's/^/    /'
fi

# ============================================================================
# 1. Start PostgreSQL 16
# ============================================================================
hdr "1. Start PostgreSQL 16"

docker rm -f "$CONTAINER" >/dev/null 2>&1
docker run -d --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=verifypass \
    -e POSTGRES_USER=testuser \
    -e POSTGRES_DB=testdb \
    -p ${PGPORT_HOST}:5432 postgres:16 >/dev/null 2>&1 || {
    bad "docker run failed";
    echo "  Docker daemon not available — skipping DB-dependent tests";
    SKIP_DB=1;
}
if [ "${SKIP_DB:-0}" = "0" ]; then
    export PGHOST=127.0.0.1 PGPORT=$PGPORT_HOST PGUSER=testuser PGDATABASE=testdb PGPASSWORD=verifypass
    for i in $(seq 1 30); do
        psql -X -q -c 'SELECT 1' >/dev/null 2>&1 && break
        sleep 1
    done
    psql -X -q -c 'SELECT version()' >/dev/null 2>&1 && \
        ok "PG16 up on port $PGPORT_HOST" || {
        bad "PG never became ready";
        docker logs "$CONTAINER" 2>&1 | tail -20;
    }
fi

# ============================================================================
# 2. Apply grant_collector_role.sql
# ============================================================================
hdr "2. Apply grant_collector_role.sql"
if [ "${SKIP_DB:-0}" = "0" ]; then
    if psql -X -v ON_ERROR_STOP=1 -f collector/grant_collector_role.sql > "$OUT/grant.log" 2>&1; then
        ok "grant script applied cleanly"
    else
        bad "grant script failed";
        sed 's/^/    /' "$OUT/grant.log"
    fi

    _has_exec=$(psql -X -A -t -c "SELECT has_function_privilege('dbguard_collector','dbguard_password_types()','EXECUTE');" 2>/dev/null)
    if [ "$_has_exec" = "t" ]; then
        ok "dbguard_collector can EXECUTE dbguard_password_types()"
    else
        bad "dbguard_collector CANNOT execute dbguard_password_types() (got: '${_has_exec:-error}')"
    fi

    psql -X -q -c "SET password_encryption='md5'; CREATE ROLE md5_canary LOGIN PASSWORD 'canary123';" >/dev/null 2>&1 && \
        ok "md5 canary role created" || warn "could not create md5 canary (PG16 may refuse md5)"
else
    warn "SKIPPED — no database available"
fi

# ============================================================================
# 3. Run collector as SUPERUSER
# ============================================================================
hdr "3. Run collector as SUPERUSER"
if [ "${SKIP_DB:-0}" = "0" ]; then
    set +e
    bash collector/dbguard-collect.sh --target=verify-super --output="$OUT/super" > "$OUT/super.stdout" 2> "$OUT/super.stderr"
    RC_SUPER=$?
    set -e
    echo "  exit code: $RC_SUPER"
    echo "  --- stdout ---"; sed 's/^/    /' "$OUT/super.stdout" | head -40
    echo "  --- stderr ---"; sed 's/^/    /' "$OUT/super.stderr" | head -40

    case $RC_SUPER in
        0)  ok "exit 0 (complete, no gaps)" ;;
        10) warn "exit 10 (partial — gaps recorded; check they are legitimate)" ;;
        *)  bad "unexpected exit $RC_SUPER" ;;
    esac

    BUNDLE=$(find "$OUT/super" -maxdepth 1 -type d -name 'dbguard-*' 2>/dev/null | head -1)
    if [ -z "$BUNDLE" ]; then
        BUNDLE=$(find "$OUT/super" -maxdepth 1 -name 'dbguard-.tar.gz' 2>/dev/null | head -1)
        if [ -n "$BUNDLE" ]; then
            tar -xzf "$BUNDLE" -C "$OUT/super"
            BUNDLE=$(find "$OUT/super" -maxdepth 1 -type d -name 'dbguard-*' | head -1)
            ok "bundle tarball extracted"
        fi
    fi

    if [ -n "$BUNDLE" ]; then
        ok "bundle at $BUNDLE"

        echo "  --- envelope.json ---"
        python3 -m json.tool "$BUNDLE/envelope.json" 2>/dev/null | sed 's/^/    /' || {
            bad "envelope.json is not valid JSON";
            sed 's/^/    /' "$BUNDLE/envelope.json";
        }

        # THE key check: sections must contain real data, not []
        for s in "$BUNDLE"/sections/*.json; do
            [ -f "$s" ] || continue
            _name=$(basename "$s")
            _bytes=$(wc -c < "$s" | tr -d ' ')
            _content=$(tr -d '[:space:]' < "$s")
            if [ "${_content}" = "{}" ] || [ "$_bytes" -lt 5 ]; then
                bad "section $_name is EMPTY — the run_sql/collect_section contract is still broken"
            else
                ok "section $_name ($_bytes bytes)"
            fi
            echo "  --- $_name ---"
            python3 -m json.tool "$s" 2>/dev/null | sed 's/^/    /' | head -30 || \
                sed 's/^/    /' "$s" | head -10
        done

        # Content assertions
        if grep -q 'log_connections' "$BUNDLE"/sections/*.json 2>/dev/null; then
            ok "log_connections present"
        else
            bad "log_connections missing from all sections"
        fi

        if grep -qi 'md5\|scram' "$BUNDLE"/sections/*.json 2>/dev/null; then
            ok "password type values present"
        else
            bad "no password types collected"
        fi

        # NOTHING may look like a password hash
        if grep -qE 'SCRAM-SHA-256\$[0-9]+:|md5[0-9a-f]{32}' "$BUNDLE"/sections/*.json "$BUNDLE/envelope.json" 2>/dev/null; then
            bad "PASSWORD HASH MATERIAL FOUND IN BUNDLE — S0 violation"
            grep -oE 'SCRAM-SHA-256\$[0-9]+:|md5[0-9a-f]{32}' "$BUNDLE"/sections/*.json | head -5 | sed 's/^/    /'
        else
            ok "no password hash material in bundle"
        fi

        if grep -q 'verifypass' -r "$BUNDLE" 2>/dev/null; then
            bad "connection password leaked into bundle"
        else
            ok "no connection password in bundle"
        fi

        # Temp files must not ship
        if ls "$BUNDLE"/*.tmp >/dev/null 2>&1; then
            bad "temp files (.tmp) shipped inside bundle"
        else
            ok "no .tmp files in bundle"
        fi

        if [ -f "$BUNDLE/SHA256SUMS" ]; then
            ok "SHA256SUMS written"
        else
            bad "SHA256SUMS missing"
        fi
    else
        bad "NO BUNDLE PRODUCED"
    fi
else
    warn "SKIPPED — no database available"
    BUNDLE=""
fi

# ============================================================================
# 4. Validate against manifest.py
# ============================================================================
hdr "4. Validate against manifest.py"
if [ -n "${BUNDLE:-}" ] && [ -f collector/test/validate_schema.py ]; then
    set +e
    python3 collector/test/validate_schema.py "$BUNDLE" > "$OUT/validate.log" 2>&1
    RC_VAL=$?
    set -e
    echo "  --- validator output ---"
    sed 's/^/    /' "$OUT/validate.log"
    if [ $RC_VAL -eq 0 ]; then
        ok "bundle validates against manifest.py"
    else
        bad "schema validation failed (exit $RC_VAL)"
    fi
else
    warn "skipped schema validation"
fi

# ============================================================================
# 5. Run as least-privilege dbguard_collector role
# ============================================================================
hdr "5. Run as least-privilege dbguard_collector role"
if [ "${SKIP_DB:-0}" = "0" ]; then
    psql -X -q -c "ALTER ROLE dbguard_collector LOGIN PASSWORD 'collectorpass';" >/dev/null 2>&1
    psql -X -q -c "GRANT CONNECT ON DATABASE testdb TO dbguard_collector;" >/dev/null 2>&1
    set +e
    PGUSER=dbguard_collector PGPASSWORD=collectorpass \
        bash collector/dbguard-collect.sh --target=verify-limited --output="$OUT/limited" \
        > "$OUT/limited.stdout" 2> "$OUT/limited.stderr"
    RC_LIMITED=$?
    set -e
    echo "  exit code: $RC_LIMITED"
    echo "  --- stderr ---"; sed 's/^/    /' "$OUT/limited.stderr" | head -20

    case $RC_LIMITED in
        0|10) ok "least-privilege run produced a bundle (exit $RC_LIMITED)" ;;
        *)    bad "least-privilege run failed with exit $RC_LIMITED — should degrade, not die" ;;
    esac

    _lim=$(find "$OUT/limited" -name 'envelope.json' 2>/dev/null | head -1)
    if [ -n "$_lim" ]; then
        echo "  --- gaps recorded ---"
        python3 -c "
import json, sys
e = json.load(open('$_lim'))
g = e.get('collection_gaps') or e.get('envelope', {}).get('collection_gaps', [])
if not g:
    print('    none')
else:
    for x in g:
        print(f\"    {x.get('section')} -> {x.get('reason')}\")
" 2>/dev/null || echo "    (could not parse gaps)"
    fi
else
    warn "SKIPPED — no database available"
fi

# ============================================================================
# 6. Managed-platform refusal (exit 20, nothing written)
# ============================================================================
hdr "6. Managed-platform refusal (exit 20, nothing written)"
if [ "${SKIP_DB:-0}" = "0" ]; then
    psql -X -q -c "CREATE ROLE rdsadmin NOLOGIN;" >/dev/null 2>&1 && \
        ok "rdsadmin decoy created" || warn "could not create rdsadmin"

    set +e
    bash collector/dbguard-collect.sh --target=verify-managed --output="$OUT/managed" \
        > "$OUT/managed.stdout" 2> "$OUT/managed.stderr"
    RC_MANAGED=$?
    set -e
    echo "  exit code: $RC_MANAGED"
    echo "  --- stderr ---"; sed 's/^/    /' "$OUT/managed.stderr" | head -20

    if [ $RC_MANAGED -eq 20 ]; then
        ok "exit 20 on managed platform"
    else
        bad "expected exit 20, got $RC_MANAGED"
    fi

    if [ -d "$OUT/managed" ] && [ -n "$(ls -A "$OUT/managed" 2>/dev/null)" ]; then
        bad "refusal path wrote output:"
        ls -la "$OUT/managed" | sed 's/^/    /'
    else
        ok "refusal wrote nothing"
    fi

    psql -X -q -c "DROP ROLE rdsadmin;" >/dev/null 2>&1
else
    warn "SKIPPED — no database available"
fi

# ============================================================================
# Summary
# ============================================================================
hdr "Summary"
printf '  PASS: %d   FAIL: %d   WARN: %d\n' "$PASS" "$FAIL" "$WARN"
echo "  Artifacts in: $OUT"
echo
echo "  Teardown:  docker rm -f $CONTAINER"
if [ $FAIL -eq 0 ]; then
    echo "  -> Ready to review the code properly."
else
    echo "  -> Not mergeable. Send the FAIL lines back with the transcript."
fi
if [ $FAIL -eq 0 ]; then
    exit 0
else
    exit 1
fi
