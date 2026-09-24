#!/usr/bin/env bash
# Run the live tests against the disposable pg-target container.
#
#   bash scripts/run_live_tests.sh [extra pytest args]
#
# Uses PG_TARGET_URL from the environment if it is non-empty, otherwise loads
# it from .env in the repo root. Refuses to run unless the URL's host is exactly
# 'pg-target': these tests run ALTER SYSTEM against whatever they connect to.

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2   # repo root, from anywhere

if [ -z "${PG_TARGET_URL:-}" ] && [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi
if [ -z "${PG_TARGET_URL:-}" ]; then
    echo "ERROR: PG_TARGET_URL is not set (checked the environment and ./.env)" >&2
    exit 2
fi

# scheme://[user[:password]@]host[:port][/db] -- the host is capture group 3
re='^postgres(ql)?://([^@/]*@)?([^:/?]+)'
host=""
if [[ "$PG_TARGET_URL" =~ $re ]]; then
    host="${BASH_REMATCH[3]}"
fi
if [ "$host" != "pg-target" ]; then
    echo "ERROR: PG_TARGET_URL host must be 'pg-target', got '${host}'" >&2
    exit 2
fi

exec uv run pytest tests/live -m live "$@"
