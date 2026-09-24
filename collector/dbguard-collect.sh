#!/usr/bin/env bash
# DBGuardAI collector — wrapper around collect.sql
#
# Usage:
#   ./dbguard-collect.sh                       # writes ./dbguard-<target>-<ts>.json
#   ./dbguard-collect.sh -o bundle.json
#   ./dbguard-collect.sh -t prod-db-01 -d mydb -o bundle.json
#   ./dbguard-collect.sh -m checks.json -o bundle.json   # also answer a check manifest
#
# The manifest (-m) is a plain JSON list of settings to read. It is data only:
# nothing in it is executed. Without -m, only the baseline is collected.
#
# Connection uses standard libpq environment: PGHOST, PGPORT, PGUSER,
# PGDATABASE, PGPASSFILE, PGSERVICE. This script never handles a password.
#
# Exit codes:
#   0   bundle written
#   20  managed platform (RDS / Cloud SQL / Azure) — nothing written
#   30  could not connect, or psql / sha256sum missing
#   1   other failure — nothing written

set -euo pipefail

TARGET_ID="${TARGET_ID:-$(hostname -s 2>/dev/null || echo unknown)}"
OUTFILE=""
MANIFEST_FILE=""
DB="${PGDATABASE:-postgres}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SQL_FILE="$SCRIPT_DIR/collect.sql"

while getopts ":o:t:d:m:h" opt; do
    case "$opt" in
        o) OUTFILE="$OPTARG" ;;
        t) TARGET_ID="$OPTARG" ;;
        d) DB="$OPTARG" ;;
        m) MANIFEST_FILE="$OPTARG" ;;
        h) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "Unknown option. Use -h." >&2; exit 1 ;;
    esac
done

command -v psql >/dev/null 2>&1 || { echo "ERROR: psql not found in PATH." >&2; exit 30; }
command -v sha256sum >/dev/null 2>&1 || { echo "ERROR: sha256sum not found in PATH (coreutils)." >&2; exit 30; }
[ -f "$SQL_FILE" ] || { echo "ERROR: collect.sql not found beside this script." >&2; exit 1; }

if [ -z "$OUTFILE" ]; then
    OUTFILE="dbguard-${TARGET_ID}-$(date -u '+%Y%m%dT%H%M%SZ').json"
fi

# Validate manifest file if provided
if [ -n "$MANIFEST_FILE" ]; then
    [ -f "$MANIFEST_FILE" ] || { echo "ERROR: manifest file does not exist: $MANIFEST_FILE" >&2; exit 1; }
    [ -r "$MANIFEST_FILE" ] || { echo "ERROR: manifest file not readable: $MANIFEST_FILE" >&2; exit 1; }
fi

# Fail before doing anything if we cannot connect.
if ! psql -X -q -A -t -d "$DB" -c 'SELECT 1' >/dev/null 2>&1; then
    echo "ERROR: cannot connect to database '$DB'. Check PGHOST/PGPORT/PGUSER/PGPASSFILE." >&2
    exit 30
fi

# Provenance. Hash the files themselves, not $(cat ...) output: command
# substitution strips trailing newlines, which would change the hash.
# JSON is never parsed here -- the SQL reads the manifest's fields itself.
COLLECTOR_SHA256="$(sha256sum "$SQL_FILE" | cut -d' ' -f1)"
if [ -n "$MANIFEST_FILE" ]; then
    MANIFEST_SHA256="$(sha256sum "$MANIFEST_FILE" | cut -d' ' -f1)"
    MANIFEST_TEXT="$(cat "$MANIFEST_FILE")"
else
    MANIFEST_TEXT='{"manifest_version":1,"checks":[]}'
    MANIFEST_SHA256="$(printf '%s' "$MANIFEST_TEXT" | sha256sum | cut -d' ' -f1)"
fi

TMP="$(mktemp "${TMPDIR:-/tmp}/dbguard.XXXXXXXX")"
ERR="$(mktemp "${TMPDIR:-/tmp}/dbguard-err.XXXXXXXX")"
cleanup() { rm -f "$TMP" "$ERR"; }
trap cleanup EXIT

set +e
psql -X -q -A -t \
     -v ON_ERROR_STOP=1 \
     -v target_id="$TARGET_ID" \
     -v manifest="$MANIFEST_TEXT" \
     -v collector_sha256="$COLLECTOR_SHA256" \
     -v manifest_sha256="$MANIFEST_SHA256" \
     -d "$DB" \
     -f "$SQL_FILE" > "$TMP" 2> "$ERR"
RC=$?
set -e

if [ $RC -ne 0 ]; then
    if grep -q 'MANAGED_PLATFORM_DETECTED' "$ERR"; then
        echo "REFUSED: managed platform detected. No bundle written." >&2
        grep 'MANAGED_PLATFORM_DETECTED' "$ERR" >&2
        exit 20
    fi
    echo "ERROR: collection failed (psql exit $RC). No bundle written." >&2
    sed 's/^/  /' "$ERR" >&2
    exit 1
fi

if [ ! -s "$TMP" ]; then
    echo "ERROR: collection produced no output. No bundle written." >&2
    exit 1
fi

mv "$TMP" "$OUTFILE"
trap - EXIT
rm -f "$ERR"

echo "Bundle written: $OUTFILE ($(wc -c < "$OUTFILE" | tr -d ' ') bytes)"

# Report gaps on stderr so the operator sees them without parsing the file.
if command -v python3 >/dev/null 2>&1; then
    python3 - "$OUTFILE" <<'PY' >&2 || true
import json, sys
b = json.load(open(sys.argv[1]))
g = (b.get("baseline") or {}).get("gaps") or []
if g:
    print(f"  {len(g)} gap(s) recorded:")
    for x in g:
        print(f"    - {x.get('section')}: {x.get('reason')}")
else:
    print("  No gaps.")
PY
fi
