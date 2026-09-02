#!/usr/bin/env bash
# DBGuardAI — Acceptance test matrix (three-CIS-control variant)
# Runs the collector against Docker containers and asserts correctness.
#
# Requirements:
#   - Docker
#   - Python 3 with pydantic (for schema validation)
#
# Usage: ./test/run_matrix.sh

set -euo pipefail

PASS=0
FAIL=0
FAILURES=""

pass_test() { PASS=$((PASS+1)); echo "  ✓ PASS: $1"; }
fail_test() { FAIL=$((FAIL+1)); FAILURES="$FAILURES\n  ✗ FAIL: $1"; }

COLLECTOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "=== DBGuardAI Collector — Acceptance Test Matrix ==="
echo ""

# ---------------------------------------------------------------------------
# Helper: start a Postgres container, run collector, stop container
# ---------------------------------------------------------------------------

run_test_container() {
    local image="$1" tag="$2"
    local container_name="dbguard-test-${tag}"

    docker run -d --name "$container_name" \
        -e POSTGRES_PASSWORD=testpass \
        -e POSTGRES_USER=testuser \
        -e POSTGRES_DB=testdb \
        -p 55432:5432 \
        "$image" >/dev/null 2>&1
    sleep 3  # wait for startup

    run_test "$tag"
    docker stop -t 5 "$container_name" >/dev/null 2>&1
    docker rm "$container_name" >/dev/null 2>&1
}

run_test() {
    local tag="$1"
    local container_name="dbguard-test-${tag}"
    local host_port=55432
    local tmpdir
    tmpdir=$(mktemp -d "/tmp/dbguard-test-XXXXXX")
    local bundle_dir="$tmpdir/bundle"

    export PGHOST=127.0.0.1
    export PGPORT=55432
    export PGUSER=testuser
    export PGDATABASE=testdb
    export PGPASSWORD=testpass
    export TARGET_ID="test-${tag}"

    echo "--- Test: $tag ---"

    # ---------------------------------------------------------------------------
    # Test 1: Postgres 16, superuser → exit 0, no gaps
    # ---------------------------------------------------------------------------
    if [ "$tag" = "16-superuser" ]; then
        echo "  Running collector as superuser..."
        bash "$COLLECTOR_DIR/dbguard-collect.sh" --output="$bundle_dir"
        local rc=$?

        if [ $rc -eq 0 ]; then
            pass_test "$tag: exit code 0 (no gaps)"
        else
            fail_test "$tag: expected exit 0, got $rc"
        fi

        # Check the three sections present
        for section in log_connections public_schema_acl password_storage; do
            if [ -f "$bundle_dir/sections/${section}.json" ]; then
                pass_test "$tag: section ${section}.json present"
            else
                fail_test "$tag: section ${section}.json missing"
            fi
        done

        # Check envelope
        if [ -f "$bundle_dir/envelope.json" ]; then
            _status=$(grep '"status"' "$bundle_dir/envelope.json" | tr -d ' "')
            if [ "$_status" = 'COMPLETE' ]; then
                pass_test "$tag: envelope status is COMPLETE"
            else
                fail_test "$tag: envelope status is $_status (expected COMPLETE)"
            fi
        else
            fail_test "$tag: envelope.json missing"
        fi

    # ---------------------------------------------------------------------------
    # Test 2: Postgres 16, limited role → exit 10, gaps recorded
    # ---------------------------------------------------------------------------
    elif [ "$tag" = "16-limited" ]; then
        echo "  Setting up limited-role database..."
        psql -h 127.0.0.1 -p 55432 -U postgres -d testdb -c "
            CREATE ROLE limited_role WITH LOGIN PASSWORD 'testpass';
            GRANT pg_monitor TO limited_role;
        " 2>/dev/null || true

        echo "  Running collector as limited role..."
        export PGUSER=limited_role
        bash "$COLLECTOR_DIR/dbguard-collect.sh" --output="$bundle_dir"
        local rc=$?

        if [ $rc -eq 10 ]; then
            pass_test "$tag: exit code 10 (partial)"
        else
            fail_test "$tag: expected exit 10, got $rc"
        fi

        if [ -f "$bundle_dir/envelope.json" ]; then
            if grep -q '"gaps"' "$bundle_dir/envelope.json"; then
                _gap_count=$(python3 -c "import json; d=json.load(open('$bundle_dir/envelope.json')); print(len(d.get('envelope',{}).get('gaps',[])))" 2>/dev/null || echo "unknown")
                pass_test "$tag: gaps recorded in envelope ($_gap_count gaps)"
            else
                fail_test "$tag: no gaps in envelope"
            fi
        fi

    # ---------------------------------------------------------------------------
    # Test 3: Managed platform (create rdsadmin role) → exit 20
    # ---------------------------------------------------------------------------
    elif [ "$tag" = "managed-refused" ]; then
        echo "  Creating rdsadmin role to simulate managed platform..."
        psql -h 127.0.0.1 -p 55432 -U postgres -d testdb -c "
            CREATE ROLE rdsadmin NOLOGIN;
        " 2>/dev/null || true

        echo "  Running collector (should refuse with exit 20)..."
        bash "$COLLECTOR_DIR/dbguard-collect.sh" --output="$bundle_dir"
        local rc=$?

        if [ $rc -eq 20 ]; then
            pass_test "$tag: exit code 20 (managed platform refused)"
        else
            fail_test "$tag: expected exit 20, got $rc"
        fi

        # Verify no bundle was written
        if [ ! -f "$bundle_dir/envelope.json" ]; then
            pass_test "$tag: no envelope written (managed refusal)"
        else
            fail_test "$tag: envelope.json exists despite managed refusal"
        fi

    fi

    # ---------------------------------------------------------------------------
    # Test 6: Secret scan
    # ---------------------------------------------------------------------------
    if [ -d "$bundle_dir" ]; then
        echo "  Scanning bundle for secrets..."
        _secret_found=false
        for pattern in 'SCRAM-SHA-256\$\|' 'md5[0-9a-f]\{32\}' 'BEGIN.*PRIVATE KEY' 'password=' 'ldapbindpasswd'; do
            if grep -rq "$pattern" "$bundle_dir" >/dev/null 2>&1; then
                echo "    ⚠ SECRET FOUND: $pattern"
                _secret_found=true
            fi
        done
        if [ "$_secret_found" = false ]; then
            pass_test "$tag: no secrets in bundle"
        else
            fail_test "$tag: secrets found in bundle"
        fi
    fi

    # ---------------------------------------------------------------------------
    # Schema validation
    # ---------------------------------------------------------------------------
    if [ -d "$bundle_dir" ] && [ -f "$bundle_dir/envelope.json" ]; then
        echo "  Validating schema..."
        python3 "$COLLECTOR_DIR/test/validate_schema.py" "$bundle_dir" 2>/dev/null
        if [ $? -eq 0 ]; then
            pass_test "$tag: schema valid"
        else
            fail_test "$tag: schema invalid"
        fi
    fi

    rm -rf "$tmpdir"
    echo ""
}

# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------

echo "Starting test containers..."

run_test_container "postgres:16" "16-superuser"
run_test_container "postgres:16" "16-limited"
run_test_container "postgres:16" "managed-refused"

echo "=== Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
if [ $FAIL -gt 0 ]; then
    echo -e "$FAILURES"
    exit 1
fi
echo "  All tests passed!"
exit 0
