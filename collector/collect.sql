-- ===========================================================================
-- DBGuardAI evidence collector
-- ---------------------------------------------------------------------------
-- Emits ONE JSON document on stdout. Read-only. Never returns a password,
-- a password hash, a private key, or a connection string containing a secret.
--
-- Run with:   psql -X -q -A -t -v ON_ERROR_STOP=1 -f collect.sql
--
-- Degradation: sections the current role cannot read come back as null with
-- an entry in "gaps". A null NEVER means "off" or "absent" -- it means
-- "not collected". Only "gaps" explains why.
-- ===========================================================================

\set QUIET on
\pset pager off
\pset tuples_only on
\pset format unaligned

-- ---------------------------------------------------------------------------
-- 0. Refuse managed platforms before collecting anything.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    v_hit text;
BEGIN
    SELECT rolname INTO v_hit
    FROM pg_roles
    WHERE rolname IN ('rdsadmin','rds_superuser','rdsrepladmin',
                      'cloudsqladmin','cloudsqlsuperuser',
                      'azure_superuser','azure_pg_admin')
    LIMIT 1;

    IF v_hit IS NOT NULL THEN
        RAISE EXCEPTION
            'MANAGED_PLATFORM_DETECTED: found role "%". DBGuardAI supports self-managed PostgreSQL only. Nothing was collected.',
            v_hit;
    END IF;

    IF EXISTS (SELECT 1 FROM pg_database WHERE datname = 'rdsadmin') THEN
        RAISE EXCEPTION
            'MANAGED_PLATFORM_DETECTED: rdsadmin database present. Nothing was collected.';
    END IF;

    IF EXISTS (SELECT 1 FROM pg_settings
               WHERE name LIKE 'rds.%' OR name LIKE 'cloudsql.%' OR name LIKE 'azure.%') THEN
        RAISE EXCEPTION
            'MANAGED_PLATFORM_DETECTED: platform-specific GUCs present. Nothing was collected.';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- 1. Helpers, created in pg_temp (session-local, dropped on disconnect).
--    Requires no privileges beyond TEMP on the database.
-- ---------------------------------------------------------------------------

-- Mask credentials inside a shell command or connection string, preserving
-- structure. "pgbackrest --stanza=main archive-push %p" survives intact;
-- "cp %p rclone://tok:s3cr3t@bucket" has the secret replaced.
CREATE FUNCTION pg_temp.mask_secrets(v text) RETURNS text AS $$
    SELECT CASE WHEN $1 IS NULL THEN NULL ELSE
        regexp_replace(
        regexp_replace(
        regexp_replace(
        regexp_replace($1,
            '(password\s*=\s*)(''[^'']*''|"[^"]*"|\S+)', '\1***REDACTED***', 'gi'),
            '(passfile\s*=\s*)(\S+)',                    '\1***REDACTED***', 'gi'),
            '(--password[= ])(\S+)',                     '\1***REDACTED***', 'gi'),
            '://([^:/@\s]+):([^@/\s]+)@',                '://\1:***REDACTED***@', 'g')
    END;
$$ LANGUAGE sql IMMUTABLE;

-- Settings whose raw value can carry a secret.
CREATE FUNCTION pg_temp.sanitise_setting(p_name text, p_value text)
RETURNS text AS $$
    SELECT CASE
        WHEN $1 IN ('archive_command','restore_command','archive_cleanup_command',
                    'recovery_end_command','primary_conninfo',
                    'ssl_passphrase_command','krb_server_keyfile')
        THEN pg_temp.mask_secrets($2)
        ELSE $2
    END;
$$ LANGUAGE sql IMMUTABLE;

-- Parse a libpq conninfo string into keys, dropping "password" entirely.
CREATE FUNCTION pg_temp.parse_conninfo(v text) RETURNS jsonb AS $$
DECLARE
    kv   text[];
    part text;
    k    text;
    val  text;
    out  jsonb := '{}'::jsonb;
BEGIN
    IF v IS NULL OR v = '' THEN RETURN NULL; END IF;
    kv := regexp_split_to_array(v, '\s+');
    FOREACH part IN ARRAY kv LOOP
        IF position('=' in part) > 0 THEN
            k   := lower(split_part(part, '=', 1));
            val := substring(part from position('=' in part) + 1);
            IF k NOT IN ('password','passfile') THEN
                out := out || jsonb_build_object(k, trim(both '''"' from val));
            END IF;
        END IF;
    END LOOP;
    RETURN out;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Run a query that may not parse on this major version, or that the role may
-- not be allowed to run. Returns NULL instead of aborting the collection.
CREATE FUNCTION pg_temp.try_jsonb(p_sql text) RETURNS jsonb AS $$
DECLARE r jsonb;
BEGIN
    EXECUTE p_sql INTO r;
    RETURN r;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Same, but reports why it failed so the caller can record a gap.
CREATE FUNCTION pg_temp.try_reason(p_sql text) RETURNS text AS $$
DECLARE r jsonb;
BEGIN
    EXECUTE p_sql INTO r;
    RETURN NULL;
EXCEPTION WHEN insufficient_privilege THEN
    RETURN 'insufficient_privilege';
WHEN undefined_table OR undefined_function OR undefined_column THEN
    RETURN 'not_applicable_version';
WHEN OTHERS THEN
    RETURN 'error: ' || SQLERRM;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- 2. Version-gated / privilege-gated SQL fragments, as text.
--    Kept as strings so PostgreSQL never parses them on a version where the
--    catalog does not exist.
-- ---------------------------------------------------------------------------

CREATE FUNCTION pg_temp.sql_password_types() RETURNS text AS $$
    SELECT $q$
        SELECT jsonb_agg(jsonb_build_object(
            'rolname', rolname,
            'password_type', CASE
                WHEN rolpassword IS NULL                      THEN 'none'
                WHEN rolpassword LIKE 'SCRAM-SHA-256$%'       THEN 'scram-sha-256'
                WHEN rolpassword LIKE 'md5%'                  THEN 'md5'
                ELSE 'other' END,
            'rolvaliduntil', rolvaliduntil
        ) ORDER BY rolname)
        FROM pg_authid WHERE rolcanlogin
    $q$;
$$ LANGUAGE sql IMMUTABLE;

CREATE FUNCTION pg_temp.sql_hba() RETURNS text AS $$
    SELECT $q$
        SELECT jsonb_agg(jsonb_build_object(
            'line_number', line_number,
            'type',        type,
            'database',    database,
            'user_name',   user_name,
            'address',     address,
            'netmask',     netmask,
            'auth_method', auth_method,
            'options',     (SELECT jsonb_agg(
                                CASE WHEN o ~* '^(ldapbindpasswd|radiussecrets?)='
                                     THEN split_part(o,'=',1) || '=***REDACTED***'
                                     ELSE o END)
                            FROM unnest(coalesce(options,'{}'::text[])) o),
            'error',       error
        ) ORDER BY line_number)
        FROM pg_hba_file_rules
    $q$;
$$ LANGUAGE sql IMMUTABLE;

CREATE FUNCTION pg_temp.sql_ident() RETURNS text AS $$
    SELECT $q$
        SELECT jsonb_agg(to_jsonb(t) ORDER BY t.line_number)
        FROM pg_ident_file_mappings t
    $q$;
$$ LANGUAGE sql IMMUTABLE;

CREATE FUNCTION pg_temp.sql_file_settings() RETURNS text AS $$
    SELECT $q$
        SELECT jsonb_agg(jsonb_build_object(
            'sourcefile', sourcefile,
            'sourceline', sourceline,
            'name',       name,
            'setting',    pg_temp.sanitise_setting(name, setting),
            'applied',    applied,
            'error',      error
        ) ORDER BY sourcefile, sourceline)
        FROM pg_file_settings
    $q$;
$$ LANGUAGE sql IMMUTABLE;

-- ===========================================================================
-- 3. The bundle.
-- ===========================================================================
SELECT jsonb_pretty(jsonb_build_object(

-- ---- envelope -------------------------------------------------------------
'envelope', jsonb_build_object(
    'schema_version',      '0.2.0',
    'collector_version',   '2.0.0-sql',
    'collected_at',        to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'target_id',           :'target_id',
    'database',            current_database(),
    'collected_by',        current_user,
    'is_superuser',        (SELECT rolsuper FROM pg_roles WHERE rolname = current_user),
    'has_pg_monitor',      pg_has_role(current_user,'pg_monitor','MEMBER'),
    'has_read_all_settings', pg_has_role(current_user,'pg_read_all_settings','MEMBER'),
    'can_read_pg_authid',  has_table_privilege('pg_authid','SELECT'),
    'deployment_type',     'self-managed'
),

-- ---- identity: fixed at initdb, must match for a faithful sandbox ---------
'identity', (SELECT jsonb_build_object(
    'version_full',       version(),
    'server_version_num', current_setting('server_version_num')::int,
    'server_encoding',    current_setting('server_encoding'),
    'lc_collate',         (SELECT datcollate FROM pg_database WHERE datname = current_database()),
    'lc_ctype',           (SELECT datctype   FROM pg_database WHERE datname = current_database()),
    'block_size',         current_setting('block_size')::int,
    'wal_segment_size',   current_setting('wal_segment_size'),
    'data_checksums',     current_setting('data_checksums'),
    'data_directory',     pg_temp.try_jsonb($q$SELECT to_jsonb(current_setting('data_directory'))$q$),
    'system_identifier',  pg_temp.try_jsonb($q$SELECT to_jsonb(system_identifier::text) FROM pg_control_system()$q$)
)),

-- ---- settings: everything not left at its default, plus the security set --
'settings', (
    SELECT jsonb_agg(jsonb_build_object(
        'name',            s.name,
        'setting',         pg_temp.sanitise_setting(s.name, s.setting),
        'unit',            s.unit,
        'category',        s.category,
        'context',         s.context,
        'vartype',         s.vartype,
        'source',          s.source,
        'sourcefile',      s.sourcefile,
        'sourceline',      s.sourceline,
        'boot_val',        s.boot_val,
        'reset_val',       pg_temp.sanitise_setting(s.name, s.reset_val),
        'pending_restart', s.pending_restart,
        'sanitised',       s.name IN ('archive_command','restore_command',
                                      'archive_cleanup_command','recovery_end_command',
                                      'primary_conninfo','ssl_passphrase_command',
                                      'krb_server_keyfile')
    ) ORDER BY s.name)
    FROM pg_settings s
    WHERE s.source <> 'default'
       OR s.name IN (
            'log_connections','log_disconnections','log_statement','log_destination',
            'logging_collector','log_directory','log_filename','log_file_mode',
            'log_line_prefix','log_hostname','log_min_messages','log_min_error_statement',
            'log_min_duration_statement','log_error_verbosity','log_truncate_on_rotation',
            'log_rotation_age','log_rotation_size','log_checkpoints','log_lock_waits',
            'log_temp_files','log_autovacuum_min_duration','syslog_facility','syslog_ident',
            'password_encryption','ssl','ssl_cert_file','ssl_key_file','ssl_ca_file',
            'ssl_crl_file','ssl_ciphers','ssl_min_protocol_version','ssl_prefer_server_ciphers',
            'listen_addresses','port','unix_socket_directories','unix_socket_permissions',
            'unix_socket_group','authentication_timeout','krb_server_keyfile',
            'db_user_namespace','row_security','backslash_quote',
            'shared_preload_libraries','session_preload_libraries','local_preload_libraries',
            'dynamic_library_path','statement_timeout','idle_in_transaction_session_timeout',
            'wal_level','archive_mode','archive_command','archive_timeout',
            'max_wal_senders','max_replication_slots','hot_standby','synchronous_standby_names',
            'restore_command','primary_conninfo','recovery_target_timeline',
            'fsync','full_page_writes','wal_log_hints','data_checksums',
            'work_mem','max_connections','superuser_reserved_connections',
            'temp_file_limit','track_activities','track_counts','track_io_timing',
            'update_process_title','debug_print_parse','debug_print_rewritten',
            'debug_print_plan','debug_pretty_print',
            'pgaudit.log','pgaudit.log_catalog','pgaudit.log_parameter',
            'pgaudit.log_relation','pgaudit.log_statement_once','pgaudit.role',
            'client_min_messages','lc_messages','timezone','log_timezone'
       )
),

-- ---- roles ----------------------------------------------------------------
-- pg_roles.rolpassword is ALWAYS the literal '********'. It is not a password
-- type and must never be interpreted as one. Real password types come from
-- the pg_authid section below, which is privilege-gated.
'roles', (
    SELECT jsonb_agg(jsonb_build_object(
        'rolname',        r.rolname,
        'oid',            r.oid,
        'rolsuper',       r.rolsuper,
        'rolinherit',     r.rolinherit,
        'rolcreaterole',  r.rolcreaterole,
        'rolcreatedb',    r.rolcreatedb,
        'rolcanlogin',    r.rolcanlogin,
        'rolreplication', r.rolreplication,
        'rolbypassrls',   r.rolbypassrls,
        'rolconnlimit',   r.rolconnlimit,
        'rolvaliduntil',  r.rolvaliduntil,
        'is_predefined',  r.rolname LIKE 'pg\_%'
    ) ORDER BY r.rolname)
    FROM pg_roles r
),

'role_memberships', (
    SELECT jsonb_agg(jsonb_build_object(
        'role',         g.rolname,
        'member',       m.rolname,
        'grantor',      a.rolname,
        'admin_option', am.admin_option
    ) ORDER BY g.rolname, m.rolname)
    FROM pg_auth_members am
    JOIN pg_roles g ON g.oid = am.roleid
    JOIN pg_roles m ON m.oid = am.member
    LEFT JOIN pg_roles a ON a.oid = am.grantor
),

-- Password TYPE only. The hash itself is never selected, never returned.
'password_types', pg_temp.try_jsonb(pg_temp.sql_password_types()),

'role_settings', (
    SELECT jsonb_agg(jsonb_build_object(
        'role',     coalesce(r.rolname,'ALL'),
        'database', coalesce(d.datname,'ALL'),
        'settings', s.setconfig
    ))
    FROM pg_db_role_setting s
    LEFT JOIN pg_roles r    ON r.oid = s.setrole
    LEFT JOIN pg_database d ON d.oid = s.setdatabase
),

-- ---- structure: names, owners, ACLs. Never rows. --------------------------
'databases', (
    SELECT jsonb_agg(jsonb_build_object(
        'datname',      d.datname,
        'owner',        pg_get_userbyid(d.datdba),
        'encoding',     pg_encoding_to_char(d.encoding),
        'datcollate',   d.datcollate,
        'datctype',     d.datctype,
        'datallowconn', d.datallowconn,
        'datconnlimit', d.datconnlimit,
        'datistemplate',d.datistemplate,
        'datacl',       d.datacl::text[]
    ) ORDER BY d.datname)
    FROM pg_database d
),

'schemas', (
    SELECT jsonb_agg(jsonb_build_object(
        'nspname', n.nspname,
        'owner',   pg_get_userbyid(n.nspowner),
        'nspacl',  n.nspacl::text[],
        'public_has_create', has_schema_privilege('public', n.oid, 'CREATE'),
        'public_has_usage',  has_schema_privilege('public', n.oid, 'USAGE')
    ) ORDER BY n.nspname)
    FROM pg_namespace n
    WHERE n.nspname NOT LIKE 'pg\_temp%'
      AND n.nspname NOT LIKE 'pg\_toast%'
),

-- Only objects that actually carry an ACL. A sandbox reproduces these as
-- stubs -- correct name, type, schema, owner. No columns, no data.
'object_acls', (
    SELECT jsonb_agg(jsonb_build_object(
        'schema',   n.nspname,
        'name',     c.relname,
        'kind',     c.relkind,
        'owner',    pg_get_userbyid(c.relowner),
        'acl',      c.relacl::text[],
        'rls',      c.relrowsecurity,
        'rls_forced', c.relforcerowsecurity
    ) ORDER BY n.nspname, c.relname)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog','information_schema')
      AND n.nspname NOT LIKE 'pg\_toast%'
      AND (c.relacl IS NOT NULL OR c.relrowsecurity)
),

'default_acls', (
    SELECT jsonb_agg(jsonb_build_object(
        'owner',     pg_get_userbyid(d.defaclrole),
        'schema',    n.nspname,
        'objtype',   d.defaclobjtype,
        'acl',       d.defaclacl::text[]
    ))
    FROM pg_default_acl d
    LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
),

'rls_policies', (
    SELECT jsonb_agg(jsonb_build_object(
        'schema', schemaname, 'table', tablename, 'policy', policyname,
        'permissive', permissive, 'roles', roles, 'cmd', cmd,
        'qual', qual, 'with_check', with_check
    ) ORDER BY schemaname, tablename, policyname)
    FROM pg_policies
),

'extensions', (
    SELECT jsonb_agg(jsonb_build_object(
        'extname', e.extname,
        'version', e.extversion,
        'schema',  n.nspname,
        'owner',   pg_get_userbyid(e.extowner)
    ) ORDER BY e.extname)
    FROM pg_extension e
    LEFT JOIN pg_namespace n ON n.oid = e.extnamespace
),

'tablespaces', pg_temp.try_jsonb($q$
    SELECT jsonb_agg(jsonb_build_object(
        'spcname',  t.spcname,
        'owner',    pg_get_userbyid(t.spcowner),
        'acl',      t.spcacl::text[],
        'location', pg_tablespace_location(t.oid)
    ) ORDER BY t.spcname)
    FROM pg_tablespace t $q$),

'foreign_servers', (
    SELECT jsonb_agg(jsonb_build_object(
        'srvname', s.srvname,
        'owner',   pg_get_userbyid(s.srvowner),
        'fdw',     w.fdwname,
        'acl',     s.srvacl::text[]
    ) ORDER BY s.srvname)
    FROM pg_foreign_server s
    JOIN pg_foreign_data_wrapper w ON w.oid = s.srvfdw
),

'event_triggers', (
    SELECT jsonb_agg(jsonb_build_object(
        'evtname', evtname, 'event', evtevent,
        'owner', pg_get_userbyid(evtowner), 'enabled', evtenabled
    ) ORDER BY evtname)
    FROM pg_event_trigger
),

-- ---- authentication -------------------------------------------------------
-- ldapbindpasswd and radiussecret are masked in options.
'hba_rules',        pg_temp.try_jsonb(pg_temp.sql_hba()),
'ident_mappings',   pg_temp.try_jsonb(pg_temp.sql_ident()),
'file_settings',    pg_temp.try_jsonb(pg_temp.sql_file_settings()),

-- ---- replication ----------------------------------------------------------
'replication', jsonb_build_object(
    'slots', pg_temp.try_jsonb($q$
              SELECT jsonb_agg(jsonb_build_object(
                  'slot_name', slot_name, 'plugin', plugin, 'slot_type', slot_type,
                  'database', database, 'temporary', temporary, 'active', active)
              ORDER BY slot_name) FROM pg_replication_slots $q$),
    'publications', (SELECT jsonb_agg(jsonb_build_object(
                  'pubname', pubname, 'owner', pg_get_userbyid(pubowner),
                  'puballtables', puballtables, 'pubinsert', pubinsert,
                  'pubupdate', pubupdate, 'pubdelete', pubdelete)
              ORDER BY pubname) FROM pg_publication),
    -- subscription conninfo is parsed, password dropped
    'subscriptions', pg_temp.try_jsonb($q$
            SELECT jsonb_agg(jsonb_build_object(
                'subname', subname,
                'owner', pg_get_userbyid(subowner),
                'enabled', subenabled,
                'conninfo_parsed', pg_temp.parse_conninfo(subconninfo))
            ORDER BY subname) FROM pg_subscription $q$),
    'primary_conninfo_parsed',
        pg_temp.parse_conninfo(nullif(current_setting('primary_conninfo', true), '')),
    'in_recovery', pg_is_in_recovery()
),

-- ---- operational baseline: aggregated, no query text ever ----------------
'connections', pg_temp.try_jsonb($q$
    SELECT jsonb_agg(jsonb_build_object(
        'application_name', coalesce(nullif(application_name,''),'(none)'),
        'usename',          usename,
        'datname',          datname,
        'client_addr_class', CASE
             WHEN client_addr IS NULL                  THEN 'unix_socket'
             WHEN client_addr << inet '127.0.0.0/8'    THEN 'loopback'
             WHEN client_addr << inet '10.0.0.0/8'
               OR client_addr << inet '172.16.0.0/12'
               OR client_addr << inet '192.168.0.0/16' THEN 'private'
             ELSE 'public' END,
        'count', count(*)
    ))
    FROM (SELECT application_name, usename, datname, client_addr
          FROM pg_stat_activity WHERE backend_type = 'client backend') a
    GROUP BY application_name, usename, datname, client_addr $q$),

'uptime', jsonb_build_object(
    'postmaster_start_time', pg_postmaster_start_time(),
    'uptime_seconds', extract(epoch FROM now() - pg_postmaster_start_time())::bigint
),

-- ---- provenance: what could not be collected, and why -------------------
'gaps', (
    SELECT coalesce(jsonb_agg(g), '[]'::jsonb) FROM (
        SELECT jsonb_build_object(
                   'section','password_types',
                   'reason', pg_temp.try_reason(pg_temp.sql_password_types()),
                   'remediation','Run grant_collector_role.sql, or grant the collector membership of a role that can read pg_authid.'
               ) AS g
        WHERE pg_temp.try_reason(pg_temp.sql_password_types()) IS NOT NULL
        UNION ALL
        SELECT jsonb_build_object(
                   'section','hba_rules',
                   'reason', pg_temp.try_reason(pg_temp.sql_hba()),
                   'remediation','pg_hba_file_rules requires superuser or explicit SELECT.'
               )
        WHERE pg_temp.try_reason(pg_temp.sql_hba()) IS NOT NULL
        UNION ALL
        SELECT jsonb_build_object(
                   'section','ident_mappings',
                   'reason', pg_temp.try_reason(pg_temp.sql_ident()),
                   'remediation','pg_ident_file_mappings requires PostgreSQL 15+ and superuser.'
               )
        WHERE pg_temp.try_reason(pg_temp.sql_ident()) IS NOT NULL
        UNION ALL
        SELECT jsonb_build_object(
                   'section','file_settings',
                   'reason', pg_temp.try_reason(pg_temp.sql_file_settings()),
                   'remediation','pg_file_settings requires superuser or pg_read_all_settings.'
               )
        WHERE pg_temp.try_reason(pg_temp.sql_file_settings()) IS NOT NULL
        UNION ALL
        SELECT jsonb_build_object(
                   'section','settings.sourcefile',
                   'reason','insufficient_privilege',
                   'remediation','GRANT pg_read_all_settings -- without it sourcefile and sourceline are null and remediation cannot tell ALTER SYSTEM from postgresql.conf.'
               )
        WHERE NOT pg_has_role(current_user,'pg_read_all_settings','MEMBER')
          AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
    ) q
),

-- ---- what was deliberately withheld -------------------------------------
'redactions', jsonb_build_array(
    jsonb_build_object('field','pg_authid.rolpassword','class','S0',
        'note','Password verifiers are never selected. Only the derived type is returned.'),
    jsonb_build_object('field','pg_settings.archive_command','class','S2',
        'note','Command structure preserved; embedded credentials masked.'),
    jsonb_build_object('field','pg_settings.primary_conninfo','class','S2',
        'note','Parsed to keys; password and passfile dropped.'),
    jsonb_build_object('field','pg_subscription.subconninfo','class','S2',
        'note','Parsed to keys; password and passfile dropped.'),
    jsonb_build_object('field','pg_hba_file_rules.options','class','S2',
        'note','ldapbindpasswd and radiussecret masked; rule structure preserved.'),
    jsonb_build_object('field','pg_stat_activity.query','class','S0',
        'note','Query text can contain plaintext credentials from DDL. Never selected.')
),

-- ---- what a database connection structurally cannot see -----------------
-- These are host facts. Score them from the target, never from a sandbox:
-- a fresh container will look clean because nobody has used it yet.
'host_not_collected', jsonb_build_array(
    'pgdata_directory_permissions','postgres_os_user_umask','systemd_unit_hardening',
    'log_file_permissions_on_disk','.pgpass_presence_and_mode','PGPASSWORD_in_environment',
    'password_on_process_command_line','psql_history_state','pg_service.conf_password',
    'package_installation_source','selinux_state','filesystem_mount_options',
    'tls_private_key_file_mode','certificate_contents'
)

)) AS bundle;
