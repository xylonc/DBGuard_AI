#!/usr/bin/env bash
# DBGuardAI collector — acceptance test harness (v2)
#
# Requires: docker on the host. psql runs inside the container.
# Works on Linux, macOS, and Git Bash / MINGW64 on Windows.
#
# Usage:  ./run_tests.sh [path-to-collector-dir]      default: ./collector

set -uo pipefail

# Git Bash rewrites /container/paths into C:/Program Files/Git/... before
# docker sees them. Both variables are needed; harmless elsewhere.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

COLLECTOR="${1:-./collector}"
CONTAINER="dbguard-test"
IMG="postgres:16"
OUT="$(pwd)/test-out"
OUTREL="test-out"   # relative form, for the Windows python interpreter
PASS=0; FAIL=0

ok()  { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; }
hdr() { printf '\n\033[1m=== %s ===\033[0m\n' "$1"; }

dpsql() { docker exec -e PGPASSWORD=testpass "$CONTAINER" \
            psql -X -q -A -t -U postgres -d postgres "$@"; }

# Run the collector inside the container as a given role.
# Exit 127 means the harness could not invoke it — never a real result.
run_collector() {
    local user="$1" pass="$2" tag="$3" outfile="$4"
    docker exec -e PGPASSWORD="$pass" -e PGUSER="$user" -e PGDATABASE=postgres \
        "$CONTAINER" bash /collector/dbguard-collect.sh -t "$tag" -o "$outfile"
}

[ -f "$COLLECTOR/collect.sql" ] || { echo "collect.sql not found in $COLLECTOR"; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT"

# ---------------------------------------------------------------------------
hdr "0. Start PostgreSQL 16"
docker rm -f "$CONTAINER" >/dev/null 2>&1
docker run -d --name "$CONTAINER" -e POSTGRES_PASSWORD=testpass "$IMG" >/dev/null || {
    echo "docker run failed — is the daemon running?"; exit 1; }

for i in $(seq 1 40); do dpsql -c 'SELECT 1' >/dev/null 2>&1 && break; sleep 1; done
dpsql -c 'SELECT 1' >/dev/null 2>&1 && ok "PG16 ready" || { bad "PG never came up"; exit 1; }

# ---------------------------------------------------------------------------
hdr "0b. Copy collector into container — HARNESS GATE"
docker exec "$CONTAINER" rm -rf /collector >/dev/null 2>&1
docker exec "$CONTAINER" mkdir -p /collector >/dev/null 2>&1
docker cp "$COLLECTOR/collect.sql"          "$CONTAINER:/collector/collect.sql"          >/dev/null 2>&1
docker cp "$COLLECTOR/dbguard-collect.sh"   "$CONTAINER:/collector/dbguard-collect.sh"   >/dev/null 2>&1
docker exec "$CONTAINER" chmod +x /collector/dbguard-collect.sh >/dev/null 2>&1

# Git on Windows checks out with CRLF. bash then chokes on the trailing \r.
docker exec "$CONTAINER" sh -c \
  "sed -i 's/\r$//' /collector/dbguard-collect.sh /collector/collect.sql" >/dev/null 2>&1
if docker exec "$CONTAINER" sh -c "grep -qU \$'\r' /collector/dbguard-collect.sh" 2>/dev/null; then
    bad "CRLF still present in wrapper after strip"
else
    ok "line endings normalised to LF"
fi

# Nothing below is meaningful unless this passes.
if docker exec "$CONTAINER" test -f /collector/dbguard-collect.sh \
   && docker exec "$CONTAINER" test -f /collector/collect.sql; then
    ok "collector present inside container"
    docker exec "$CONTAINER" ls -la /collector | sed 's/^/    /'
else
    bad "collector NOT inside container — harness broken, aborting"
    docker exec "$CONTAINER" ls -la / 2>&1 | sed 's/^/    /'
    echo "  (If this fails on Git Bash, run from PowerShell or WSL instead.)"
    exit 1
fi

# ---------------------------------------------------------------------------
hdr "Setup: canary roles"
dpsql -c "SET password_encryption='md5'; CREATE ROLE md5_canary LOGIN PASSWORD 'canary_md5_pw';" >/dev/null 2>&1 \
    && ok "md5_canary created" || bad "could not create md5 role"
dpsql -c "SET password_encryption='scram-sha-256'; CREATE ROLE scram_canary LOGIN PASSWORD 'canary_scram_pw';" >/dev/null 2>&1 \
    && ok "scram_canary created" || bad "could not create scram role"
dpsql -c "CREATE ROLE lowpriv LOGIN PASSWORD 'lowprivpass';
          GRANT CONNECT, TEMP ON DATABASE postgres TO lowpriv;" >/dev/null 2>&1 \
    && ok "lowpriv role created" || bad "could not create lowpriv role"

# ---------------------------------------------------------------------------
hdr "1. Superuser run"
run_collector postgres testpass testbox /tmp/bundle.json \
    > "$OUT/super.stdout" 2> "$OUT/super.stderr"
RC=$?
echo "  exit code: $RC"
sed 's/^/    /' "$OUT/super.stdout"
sed 's/^/    /' "$OUT/super.stderr" | head -30

SUPER_OK=0
if   [ $RC -eq 127 ]; then bad "exit 127 — harness could not invoke the wrapper"
elif [ $RC -eq 2 ] && grep -q "command not found\|invalid option" "$OUT/super.stderr" 2>/dev/null; then
                           bad "wrapper did not start (shell error, not a collector result)"
elif [ $RC -eq 0 ];   then ok  "exit 0"; SUPER_OK=1
else                       bad "expected exit 0, got $RC"; fi

if docker exec "$CONTAINER" test -f /tmp/bundle.json; then
    docker exec "$CONTAINER" cat /tmp/bundle.json > "$OUT/bundle.json" 2>/dev/null
    [ -s "$OUT/bundle.json" ] && ok "bundle retrieved ($(wc -c < "$OUT/bundle.json" | tr -d ' ') bytes)" \
                             || bad "bundle exists in container but came out empty"
else
    bad "no bundle produced"
fi

# ---------------------------------------------------------------------------
hdr "2. Valid JSON"
if [ -f "$OUT/bundle.json" ]; then
    python3 -m json.tool "$OUTREL/bundle.json" > /dev/null 2>"$OUT/json.err" \
        && ok "valid JSON ($(wc -c < "$OUT/bundle.json" | tr -d ' ') bytes)" \
        || { bad "invalid JSON"; sed 's/^/    /' "$OUT/json.err"; head -c 400 "$OUT/bundle.json"; }
else bad "skipped — no bundle"; fi

# ---------------------------------------------------------------------------
hdr "3. Password types — md5 AND scram must differ"
if [ -f "$OUT/bundle.json" ]; then
    python3 - "$OUTREL/bundle.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1]))
pt=b.get("password_types")
if pt is None:
    print("    password_types is null — see gaps"); sys.exit(1)
types={r["rolname"]:r["password_type"] for r in pt}
for k,v in sorted(types.items()): print(f"    {k:20s} {v}")
if types.get("scram_canary")!="scram-sha-256":
    print(f"    scram_canary reports {types.get('scram_canary')!r}"); sys.exit(1)
if "md5_canary" in types and types["md5_canary"]==types.get("scram_canary"):
    print("    md5 and scram roles report the SAME type — wrong catalog"); sys.exit(1)
sys.exit(0)
PY
    [ $? -eq 0 ] && ok "password types differentiate correctly" || bad "password type detection wrong"
else bad "skipped — no bundle"; fi

# ---------------------------------------------------------------------------
hdr "4. No hash material"
if [ -f "$OUT/bundle.json" ]; then
    HITS=$(grep -oE 'SCRAM-SHA-256\$[0-9]+:|md5[0-9a-f]{32}' "$OUT/bundle.json")
    [ -z "$HITS" ] && ok "no hash material" || { bad "HASH LEAKED"; echo "$HITS" | head -5 | sed 's/^/    /'; }
else bad "skipped — no bundle"; fi

# ---------------------------------------------------------------------------
hdr "5. No plaintext passwords"
if [ -f "$OUT/bundle.json" ]; then
    LEAK=""
    for p in testpass canary_md5_pw canary_scram_pw lowprivpass; do
        grep -q "$p" "$OUT/bundle.json" && LEAK="$LEAK $p"
    done
    [ -z "$LEAK" ] && ok "no plaintext passwords" || bad "LEAKED:$LEAK"
else bad "skipped — no bundle"; fi

# ---------------------------------------------------------------------------
hdr "6. Non-superuser run (CONNECT + TEMP only)"
run_collector lowpriv lowprivpass lowpriv /tmp/low.json \
    > "$OUT/low.stdout" 2> "$OUT/low.stderr"
RCL=$?
echo "  exit code: $RCL"
sed 's/^/    /' "$OUT/low.stderr" | head -20

if   [ $RCL -eq 127 ]; then bad "exit 127 — harness fault"
elif [ $RCL -eq 0 ];   then ok  "exit 0 (degraded, did not crash)"
else                        bad "expected exit 0, got $RCL"; fi

if docker exec "$CONTAINER" test -f /tmp/low.json \
   && docker exec "$CONTAINER" cat /tmp/low.json > "$OUT/low.json" 2>/dev/null \
   && [ -s "$OUT/low.json" ]; then
    python3 - "$OUTREL/low.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1]))
g=b.get("gaps") or []
if not g:
    print("    no gaps recorded on a CONNECT-only role"); sys.exit(1)
for x in g: print(f"    {x.get('section')}: {x.get('reason')}")
sys.exit(0)
PY
    [ $? -eq 0 ] && ok "gaps recorded" || bad "no gaps on restricted role"
else bad "low-priv run produced no bundle"; fi

# ---------------------------------------------------------------------------
hdr "7. Negative test — broken SQL fails loudly, writes nothing"
if [ "$SUPER_OK" != "1" ]; then
    bad "skipped — the collector has not had a successful run, so a failure here proves nothing"
else
docker exec "$CONTAINER" bash -c \
  "cp /collector/collect.sql /tmp/collect.bak && sed -i \"s/'databases', (/'databases' (/\" /collector/collect.sql"
if docker exec "$CONTAINER" diff -q /tmp/collect.bak /collector/collect.sql >/dev/null 2>&1; then
    bad "could not corrupt collect.sql — negative test not exercised"
else
    ok "collect.sql corrupted for the test"
    run_collector postgres testpass broken /tmp/broken.json \
        > "$OUT/broken.stdout" 2> "$OUT/broken.stderr"
    RCB=$?
    echo "  exit code: $RCB"
    sed 's/^/    /' "$OUT/broken.stderr" | head -10
    if   [ $RCB -eq 127 ]; then bad "exit 127 — harness fault, negative test invalid"
    elif [ $RCB -ne 0 ];   then ok  "non-zero exit on SQL error"
    else                        bad "returned 0 on broken SQL — ON_ERROR_STOP not working"; fi
    docker exec "$CONTAINER" test -f /tmp/broken.json \
        && bad "wrote output despite failing" || ok "wrote no output file"
fi
docker exec "$CONTAINER" cp /tmp/collect.bak /collector/collect.sql >/dev/null 2>&1 \
    && ok "collect.sql restored" || bad "could not restore collect.sql"
fi

# ---------------------------------------------------------------------------
hdr "8. Managed platform refusal"
dpsql -c "CREATE ROLE rdsadmin NOLOGIN;" >/dev/null 2>&1
run_collector postgres testpass managed /tmp/managed.json \
    > "$OUT/managed.stdout" 2> "$OUT/managed.stderr"
RCM=$?
echo "  exit code: $RCM"
sed 's/^/    /' "$OUT/managed.stderr" | head -5
if   [ $RCM -eq 127 ]; then bad "exit 127 — harness fault"
elif [ $RCM -eq 20 ];  then ok  "exit 20 on managed platform"
else                        bad "expected exit 20, got $RCM"; fi
if [ "$SUPER_OK" = "1" ]; then
    docker exec "$CONTAINER" test -f /tmp/managed.json \
        && bad "wrote output despite refusing" || ok "refusal wrote nothing"
else
    bad "skipped — no successful baseline run, so 'wrote nothing' proves nothing"
fi
dpsql -c "DROP ROLE rdsadmin;" >/dev/null 2>&1

# ---------------------------------------------------------------------------
hdr "9. Section coverage"
if [ -f "$OUT/bundle.json" ]; then
python3 - "$OUTREL/bundle.json" <<'PY'
import json,sys
b=json.load(open(sys.argv[1]))
gapped={g.get("section") for g in (b.get("gaps") or [])}
filled=[k for k,v in b.items() if v not in (None,[],{})]
empty=[k for k,v in b.items() if v in (None,[],{})]
print(f"    populated: {len(filled)}")
print(f"    empty:     {len(empty)}  {empty if empty else ''}")
print(f"    gaps:      {sorted(gapped) if gapped else 'none'}")
un=[k for k in empty if k not in gapped and k!='gaps']
if un: print(f"    WARN empty with no gap recorded: {un}")
PY
else bad "skipped — no bundle"; fi

# ---------------------------------------------------------------------------
hdr "Summary"
printf '  PASS: %d   FAIL: %d\n' "$PASS" "$FAIL"
echo "  Artifacts: $OUT"
echo "  Teardown:  docker rm -f $CONTAINER"
[ $FAIL -eq 0 ] && echo "  -> Collector verified." || echo "  -> Send the FAIL lines and $OUT/*.stderr back."
exit $([ $FAIL -eq 0 ] && echo 0 || echo 1)
