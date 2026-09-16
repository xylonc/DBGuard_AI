#!/usr/bin/env bash
# Capture real collector bundles for assessment tests.
#   tests/fixtures/bundles/pg16_insecure.json   log_connections=off, PUBLIC CREATE on public, one md5 role
#   tests/fixtures/bundles/pg16_hardened.json   log_connections=on,  no PUBLIC CREATE,          no md5 roles
#   tests/fixtures/bundles/pg16_lowpriv.json    insecure target, collected by a least-privilege role
# Run from the repo root in Git Bash:  bash scripts/capture_assess_fixtures.sh

set -euo pipefail
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

IMG="postgres:16"
OUT_DIR="tests/fixtures/bundles"
mkdir -p "$OUT_DIR"

wait_ready() {
    local c="$1"
    for _ in $(seq 1 60); do
        docker exec "$c" psql -U postgres -tAc 'SELECT 1' >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "ERROR: $c never became ready" >&2; exit 1
}

start_pg() {
    local c="$1"
    docker rm -f "$c" >/dev/null 2>&1 || true
    docker run -d --name "$c" -e POSTGRES_PASSWORD=testpass "$IMG" >/dev/null
    wait_ready "$c"; sleep 5; wait_ready "$c"
    docker exec "$c" mkdir -p /collector
    docker cp collector/collect.sql        "$c:/collector/collect.sql"
    docker cp collector/dbguard-collect.sh "$c:/collector/dbguard-collect.sh"
    docker exec "$c" sh -c "sed -i 's/\r$//' /collector/collect.sql /collector/dbguard-collect.sh"
}

su_psql() {
    local c="$1"; shift
    docker exec -e PGPASSWORD=testpass "$c" psql -X -q -v ON_ERROR_STOP=1 -U postgres -d postgres "$@"
}

collect() {
    local c="$1" user="$2" pass="$3" tag="$4" out="$5"
    docker exec -e PGPASSWORD="$pass" -e PGUSER="$user" -e PGDATABASE=postgres \
        "$c" bash /collector/dbguard-collect.sh -t "$tag" -o /tmp/bundle.json
    docker exec "$c" cat /tmp/bundle.json > "$out"
    echo "  wrote $out ($(wc -c < "$out" | tr -d ' ') bytes)"
}

echo "=== insecure target ==="
start_pg dbguard-fx-insecure
su_psql dbguard-fx-insecure -c "SET password_encryption='md5'; CREATE ROLE md5_user LOGIN PASSWORD 'fixture_md5_pw';"
su_psql dbguard-fx-insecure -c "GRANT CREATE ON SCHEMA public TO PUBLIC;"
su_psql dbguard-fx-insecure -c "ALTER SYSTEM SET log_connections = off;" -c "SELECT pg_reload_conf();"
su_psql dbguard-fx-insecure -c "CREATE ROLE lowpriv LOGIN PASSWORD 'lowprivpass';" \
                            -c "GRANT CONNECT, TEMP ON DATABASE postgres TO lowpriv;"
echo -n "  log_connections (new session): "; su_psql dbguard-fx-insecure -tAc "SHOW log_connections;"
collect dbguard-fx-insecure postgres testpass    fixture-insecure "$OUT_DIR/pg16_insecure.json"
collect dbguard-fx-insecure lowpriv  lowprivpass fixture-lowpriv  "$OUT_DIR/pg16_lowpriv.json"

echo "=== hardened target ==="
start_pg dbguard-fx-hardened
su_psql dbguard-fx-hardened -c "CREATE ROLE app_user LOGIN PASSWORD 'fixture_scram_pw';"
su_psql dbguard-fx-hardened -c "REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
su_psql dbguard-fx-hardened -c "ALTER SYSTEM SET log_connections = on;" -c "SELECT pg_reload_conf();"
echo -n "  log_connections (new session): "; su_psql dbguard-fx-hardened -tAc "SHOW log_connections;"
collect dbguard-fx-hardened postgres testpass fixture-hardened "$OUT_DIR/pg16_hardened.json"

docker rm -f dbguard-fx-insecure dbguard-fx-hardened >/dev/null

echo "=== secrets check (must print 'clean') ==="
if grep -n -i -E 'md5[0-9a-f]{32}|SCRAM-SHA-256\$|fixture_md5_pw|fixture_scram_pw|testpass|lowprivpass' "$OUT_DIR"/*.json; then
    echo "SECRETS FOUND - do not commit" >&2; exit 1
else
    echo "clean"
fi

echo "=== gitignore check (must print nothing) ==="
git check-ignore -v "$OUT_DIR"/*.json || true

echo "=== evidence the three rules read ==="
python - <<'PY'
import json
for name in ("pg16_insecure", "pg16_hardened", "pg16_lowpriv"):
    b = json.load(open(f"tests/fixtures/bundles/{name}.json"))
    s = b.get("settings")
    lc = [x.get("setting") for x in s if x.get("name") == "log_connections"] if isinstance(s, list) else s
    sc = b.get("schemas")
    pub = [x.get("public_has_create") for x in sc if x.get("nspname") == "public"] if isinstance(sc, list) else sc
    pt = b.get("password_types")
    types = sorted({x.get("password_type") for x in pt}) if isinstance(pt, list) else pt
    gaps = [g.get("section") for g in (b.get("gaps") or [])]
    print(f"{name}: log_connections={lc} public_has_create={pub} password_types={types} gaps={gaps}")
PY
