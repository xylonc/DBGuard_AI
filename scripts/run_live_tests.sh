#!/bin/bash
# Run live tests against pg-target
# Refuses to run unless PG_TARGET_URL host is 'pg-target'

# Check PG_TARGET_URL before sourcing .env (command line takes precedence)
if [ -z "${PG_TARGET_URL+x}" ]; then
    echo "ERROR: PG_TARGET_URL is not set" >&2
    exit 2
fi

# Extract host from PG_TARGET_URL using Python
host=$(python3 -c "import sys; u=\"$PG_TARGET_URL\"; print(u.split('@')[1].split(':')[0] if '@' in u else '')")
if [ "$host" != "pg-target" ]; then
    echo "ERROR: PG_TARGET_URL host must be 'pg-target', got '$host'" >&2
    exit 2
fi

# Source .env for other variables (database_url, etc.)
set -a
. ./.env
set +a

# Run pytest with the live marker
uv run pytest tests/live -m live -v "$@"
