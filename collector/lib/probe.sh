#!/usr/bin/env bash
# DBGuardAI — Probe: version, platform, and privilege detection
# Must be sourced by dbguard-collect.sh after setting COLLECTOR_LOG, etc.
# Exits 20 (managed), 21 (version), or 30 (psql missing) on failure.
# On success, sets: SERVER_VERSION_NUM, SERVER_VERSION_FULL, SERVER_MAJOR,
#   DEPLOYMENT_TYPE, PLATFORM_PROBE_EVIDENCE, IS_SUPERUSER, HAS_PG_MONITOR,
#   HAS_PG_READ_ALL_SETTINGS, HAS_PG_READ_SERVER_FILES, CAN_SELECT_AUTHID.

# ---------------------------------------------------------------------------
# Probe 1: psql presence and minimum version
# ---------------------------------------------------------------------------

if ! command -v psql >/dev/null 2>&1; then
    log_error "psql not found in PATH. Cannot proceed."
    exit 30
fi

# Check client version >= 12
PSQL_VERSION_STR=$(psql --version 2>/dev/null | sed 's/.* //' )
PSQL_CLIENT_VER_NUM=$(printf '%s' "$PSQL_VERSION_STR" | awk -F. '{printf "%d%02d", $1, $2}')
if [ -z "$PSQL_CLIENT_VER_NUM" ] || [ "$PSQL_CLIENT_VER_NUM" -lt 1200 ]; then
    log_error "psql client version too old: $PSQL_VERSION_STR (need >= 12)"
    exit 30
fi

# ---------------------------------------------------------------------------
# Probe 2: Connect and get server version
# ---------------------------------------------------------------------------

SERVER_VERSION_FULL=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SELECT version();" 2>/dev/null | sed 's/^ *//;s/ *$//')

if [ -z "$SERVER_VERSION_FULL" ]; then
    log_error "Could not connect to the database or read server version."
    exit 30
fi

SERVER_VERSION_NUM=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SELECT server_version_num();" 2>/dev/null)

if [ -z "$SERVER_VERSION_NUM" ] || [ "$SERVER_VERSION_NUM" -lt 120000 ] 2>/dev/null; then
    log_error "PostgreSQL version $SERVER_VERSION_NUM is below minimum (120000)."
    exit 21
fi

SERVER_MAJOR=$(( SERVER_VERSION_NUM / 10000 ))

# ---------------------------------------------------------------------------
# Probe 3: Platform detection — managed platform refusal
# ---------------------------------------------------------------------------

DEPLOYMENT_TYPE="unknown"
PLATFORM_PROBE_EVIDENCE=""

# Check for known managed platform roles
_MANAGED_ROLES=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SELECT rolname FROM pg_roles WHERE rolname IN (
        'rdsadmin', 'rdsrepladmin', 'rds_superuser',
        'cloudsqladmin', 'cloudsqlsuperuser',
        'azure_superuser', 'azure_pg_admin'
    );" 2>/dev/null)

if [ -n "$_MANAGED_ROLES" ]; then
    DEPLOYMENT_TYPE="managed"
    PLATFORM_PROBE_EVIDENCE="role $(_MANAGED_ROLES | tr '\n' ', ')"
fi

# Check for managed platform settings
if [ "$DEPLOYMENT_TYPE" = "unknown" ]; then
    _MANAGED_SETTINGS=$(psql -X -A -t -q -d "$PGDATABASE" \
        -c "SELECT name FROM pg_settings WHERE name LIKE 'rds.%%'
             OR name LIKE 'cloudsql.%%'
             OR name LIKE 'azure.%%'
         LIMIT 1;" 2>/dev/null)
    if [ -n "$_MANAGED_SETTINGS" ]; then
        DEPLOYMENT_TYPE="managed"
        PLATFORM_PROBE_EVIDENCE="setting $(_MANAGED_SETTINGS)"
    fi
fi

# Check for rdsadmin database
if [ "$DEPLOYMENT_TYPE" = "unknown" ]; then
    _RDS_DB=$(psql -X -A -t -q -d "$PGDATABASE" \
        -c "SELECT datname FROM pg_database WHERE datname = 'rdsadmin' LIMIT 1;" 2>/dev/null)
    if [ -n "$_RDS_DB" ]; then
        DEPLOYMENT_TYPE="managed"
        PLATFORM_PROBE_EVIDENCE="database $(_RDS_DB)"
    fi
fi

# Refuse managed platforms — write nothing
if [ "$DEPLOYMENT_TYPE" = "managed" ]; then
    log_error "Managed platform detected: $PLATFORM_PROBE_EVIDENCE. " \
        "DBGuardAI collector does not support managed platforms because " \
        "host-level controls cannot be assessed and the sandbox cannot " \
        "represent the platform. Exit 20."
    exit 20
fi

# ---------------------------------------------------------------------------
# Probe 4: Privilege probe
# ---------------------------------------------------------------------------

IS_SUPERUSER=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SELECT rolsuper FROM pg_roles WHERE rolname = current_user;" 2>/dev/null)

HAS_PG_MONITOR=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SELECT EXISTS(SELECT 1 FROM pg_auth_members m
                       JOIN pg_authid r ON r.oid = m.roleid
                       WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
                       AND r.rolname = 'pg_monitor');" 2>/dev/null)

HAS_PG_READ_ALL_SETTINGS=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SELECT EXISTS(SELECT 1 FROM pg_auth_members m
                       JOIN pg_authid r ON r.oid = m.roleid
                       WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
                       AND r.rolname = 'pg_read_all_settings');" 2>/dev/null)

HAS_PG_READ_SERVER_FILES=$(psql -X -A -t -q -d "$PGDATABASE" \
    -c "SELECT EXISTS(SELECT 1 FROM pg_auth_members m
                       JOIN pg_authid r ON r.oid = m.roleid
                       WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
                       AND r.rolname = 'pg_read_server_files');" 2>/dev/null)

CAN_SELECT_AUTHID="false"
if [ "$IS_SUPERUSER" = "t" ]; then
    # Superusers can always access pg_authid
    CAN_SELECT_AUTHID="true"
else
    _auth_check=$(psql -X -A -t -q -d "$PGDATABASE" \
        -c "SELECT 1 FROM pg_authid LIMIT 1;" 2>/dev/null)
    if [ -n "$_auth_check" ]; then
        CAN_SELECT_AUTHID="true"
    fi
fi

log_info "Probe complete: version=$SERVER_VERSION_FULL ($SERVER_VERSION_NUM), " \
    "superuser=$IS_SUPERUSER, can_select_authid=$CAN_SELECT_AUTHID"
