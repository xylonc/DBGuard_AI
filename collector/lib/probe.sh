#!/usr/bin/env bash
# DBGuardAI — Preflight probe (version, platform, privilege detection)
#
# IMPORTANT: This file does NOT execute on source.  Its logic is wrapped in
# the probe_target() function below.  The caller must invoke probe_target()
# after COLLECTOR_LOG, BUNDLE_DIR, TARGET_ID, and PGDATABASE are set.
#
# probe_target() sets the following variables on success:
#   SERVER_VERSION_NUM      (e.g. 160003)
#   SERVER_VERSION_FULL     (free-text version string)
#   SERVER_MAJOR            (e.g. 16)
#   DEPLOYMENT_TYPE         (self-managed | managed)
#   IS_SUPERUSER            (true | false)
#   CAN_SELECT_AUTHID       (true | false)
#   CURRENT_USER            (rolname)

# ---------------------------------------------------------------------------
# probe_target: all logic in a single function
# ---------------------------------------------------------------------------
probe_target() {
    # ---- 1. psql presence and minimum client version -----------------------

    if ! command -v psql >/dev/null 2>&1; then
        log_error "psql not found in PATH. Cannot proceed."
        return 30
    fi

    local psql_ver
    psql_ver=$(psql --version 2>/dev/null | sed 's/.* //')
    local psql_ver_num
    psql_ver_num=$(printf '%s' "$psql_ver" | awk -F. '{printf "%d%02d", $1, $2}')

    if [ -z "$psql_ver_num" ] || [ "$psql_ver_num" -lt 1200 ] 2>/dev/null; then
        log_error "psql client version too old: $psql_ver (need >= 12)"
        return 30
    fi

    # ---- 2. Connect and get server version ---------------------------------

    SERVER_VERSION_FULL=$(psql -X -A -t -q -d "$PGDATABASE" \
        -c "SELECT version();" 2>/dev/null | sed 's/^ *//;s/ *$//')

    if [ -z "$SERVER_VERSION_FULL" ]; then
        log_error "Could not connect to the database or read server version."
        return 30
    fi

    SERVER_VERSION_NUM=$(psql -X -A -t -q -d "$PGDATABASE" \
        -c "SELECT server_version_num();" 2>/dev/null)

    if [ -z "$SERVER_VERSION_NUM" ] || [ "$SERVER_VERSION_NUM" -lt 120000 ] 2>/dev/null; then
        log_error "PostgreSQL version $SERVER_VERSION_NUM is below minimum (120000)."
        return 21
    fi

    SERVER_MAJOR=$(( SERVER_VERSION_NUM / 10000 ))

    # ---- 3. Current user ---------------------------------------------------

    CURRENT_USER=$(psql -X -A -t -q -d "$PGDATABASE" \
        -c "SELECT current_user;" 2>/dev/null | sed 's/^ *//;s/ *$//')

    # ---- 4. Managed platform detection -------------------------------------

    DEPLOYMENT_TYPE="self-managed"

    # Check for known managed roles
    local _managed_roles
    _managed_roles=$(psql -X -A -t -q -d "$PGDATABASE" \
        -c "SELECT rolname FROM pg_roles WHERE rolname IN (
            'rdsadmin', 'rdsrepladmin', 'rds_superuser',
            'cloudsqladmin', 'cloudsqlsuperuser',
            'azure_superuser', 'azure_pg_admin'
        );" 2>/dev/null)

    if [ -n "$_managed_roles" ]; then
        DEPLOYMENT_TYPE="managed"
    fi

    # Check for managed platform settings
    if [ "$DEPLOYMENT_TYPE" = "self-managed" ]; then
        local _managed_settings
        _managed_settings=$(psql -X -A -t -q -d "$PGDATABASE" \
            -c "SELECT name FROM pg_settings WHERE name LIKE 'rds.%'
                 OR name LIKE 'cloudsql.%'
                 OR name LIKE 'azure.%'
             LIMIT 1;" 2>/dev/null)
        if [ -n "$_managed_settings" ]; then
            DEPLOYMENT_TYPE="managed"
        fi
    fi

    # Check for rdsadmin database
    if [ "$DEPLOYMENT_TYPE" = "self-managed" ]; then
        local _rds_db
        _rds_db=$(psql -X -A -t -q -d "$PGDATABASE" \
            -c "SELECT datname FROM pg_database WHERE datname = 'rdsadmin' LIMIT 1;" 2>/dev/null)
        if [ -n "$_rds_db" ]; then
            DEPLOYMENT_TYPE="managed"
        fi
    fi

    # Refuse managed platforms — write nothing, exit 20
    if [ "$DEPLOYMENT_TYPE" = "managed" ]; then
        log_error "Managed platform detected. DBGuardAI collector does not support managed platforms. Exit 20."
        return 20
    fi

    # ---- 5. Privilege probe ------------------------------------------------

    local _super_check
    _super_check=$(psql -X -A -t -q -d "$PGDATABASE" \
        -c "SELECT rolsuper FROM pg_roles WHERE rolname = current_user;" 2>/dev/null)

    if [ "$_super_check" = "t" ]; then
        IS_SUPERUSER="true"
    else
        IS_SUPERUSER="false"
    fi

    CAN_SELECT_AUTHID="false"
    if [ "$IS_SUPERUSER" = "true" ]; then
        CAN_SELECT_AUTHID="true"
    else
        local _auth_check
        _auth_check=$(psql -X -A -t -q -d "$PGDATABASE" \
            -c "SELECT 1 FROM pg_authid LIMIT 1;" 2>/dev/null)
        if [ -n "$_auth_check" ]; then
            CAN_SELECT_AUTHID="true"
        fi
    fi

    log_info "Probe complete: version=$SERVER_VERSION_FULL ($SERVER_VERSION_NUM), " \
        "superuser=$IS_SUPERUSER, can_select_authid=$CAN_SELECT_AUTHID"
    return 0
}
