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

-- Pin name resolution before running anything. A target can set search_path
-- per role or database; without this, objects it creates could shadow the
-- built-ins called below. pg_temp goes last so temporary objects cannot
-- shadow pg_catalog either; the helpers are always called as pg_temp.*.
-- Side effect: the search_path row in "settings" shows source 'session'
-- with this value; its reset_val holds the target's configured search_path.
SET search_path = pg_catalog, pg_temp;
-- A target can also turn standard_conforming_strings off per role or
-- database. Backslashes in '...' literals would then become escapes and break
-- the masking patterns below (\s, \S+, \1), leaking secrets. Same side effect
-- on the settings row as search_path.
SET standard_conforming_strings = on;

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
-- Like libpq, backslash escapes apply in quoted and unquoted values (\', \ ),
-- a URI may carry a password with an empty user name (postgresql://:pw@host),
-- and a URI password may contain '/', '?' or '#'. Over-redaction is preferred.
CREATE FUNCTION pg_temp.mask_secrets(v text) RETURNS text AS $$
    SELECT CASE WHEN $1 IS NULL THEN NULL ELSE
        regexp_replace(
        regexp_replace(
        regexp_replace(
        regexp_replace(
        regexp_replace($1,
            '(password\s*=\s*)(''(?:[^''\\]|\\.)*''|"(?:[^"\\]|\\.)*"|(?:[^\s\\]|\\.)+)', '\1***REDACTED***', 'gi'),
            '(passfile\s*=\s*)(\S+)',                    '\1***REDACTED***', 'gi'),
            '(--password[= ])(\S+)',                     '\1***REDACTED***', 'gi'),
            '://([^:/@\s]*):([^@\s]+)@',                 '://\1:***REDACTED***@', 'g'),
            -- libpq percent-decodes URI keywords, so pass%77ord= is a password:
            -- mask the value of any query parameter whose name contains '%'.
            '([?&][^=&\s]*%[^=&\s]*=)[^&\s]*',          '\1***REDACTED***', 'g')
    END;
$$ LANGUAGE sql IMMUTABLE;

-- Settings whose raw value can carry a secret.
-- Their text is never shipped: only whether a value is set and its length.
-- Masking free text was shown to miss real credential formats (spaces in URI
-- passwords, cloud keys in commands), so nothing is guessed. Names compare
-- case-insensitively, as current_setting() does.
-- Also every custom or extension setting (a dotted name such as
-- pgrst.jwt_secret or app.jwt_key) except an exact list of reviewed extension
-- settings whose values CIS checks need and which carry no secrets. Exact
-- names, not prefixes: a planted pgaudit.jwt_secret is still redacted. Names are
-- lower-cased under the C collation, as PostgreSQL compares setting names, so
-- look-alike characters (U+212A, U+0130) cannot match a reviewed name.
CREATE FUNCTION pg_temp.is_secret_setting(p_name text) RETURNS boolean AS $$
    SELECT lower($1 COLLATE "C") IN ('archive_command','restore_command','archive_cleanup_command',
                         'recovery_end_command','primary_conninfo',
                         'ssl_passphrase_command','krb_server_keyfile')
        OR (position('.' in $1) > 0
            AND lower($1 COLLATE "C") NOT IN (
                'pgaudit.log','pgaudit.log_catalog','pgaudit.log_client',
                'pgaudit.log_level','pgaudit.log_parameter',
                'pgaudit.log_parameter_max_size','pgaudit.log_relation',
                'pgaudit.log_rows','pgaudit.log_statement',
                'pgaudit.log_statement_once','pgaudit.role',
                'set_user.block_alter_system','set_user.block_copy_program',
                'set_user.block_log_statement','set_user.exit_on_error',
                'set_user.nosuperuser_target_allowlist',
                'set_user.superuser_allowlist','set_user.superuser_audit_tag',
                'pg_stat_statements.max','pg_stat_statements.track',
                'pg_stat_statements.track_utility','pg_stat_statements.track_planning',
                'pg_stat_statements.save',
                'plpgsql.variable_conflict','plpgsql.print_strict_params',
                'plpgsql.check_asserts','plpgsql.extra_warnings','plpgsql.extra_errors'))
        -- A plain name the server does not know (a config-file line such as
        -- jwt_secret = '...' or a typo like restore_comand) is unreviewed text.
        OR (position('.' in $1) = 0
            AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_settings p
                            WHERE lower(p.name COLLATE "C") = lower($1 COLLATE "C")));
$$ LANGUAGE sql STABLE;

CREATE FUNCTION pg_temp.sanitise_setting(p_name text, p_value text)
RETURNS text AS $$
    SELECT CASE
        -- A missing name fails closed.
        WHEN coalesce(pg_temp.is_secret_setting($1), true)
        THEN CASE
            WHEN $2 IS NULL THEN NULL
            WHEN $2 IN ('', '(disabled)') THEN $2
            ELSE '***REDACTED*** (set, ' || length($2) || ' characters)'
        END
        ELSE $2
    END;
$$ LANGUAGE sql STABLE;

-- Parse a libpq conninfo string into keys, dropping "password" entirely.
CREATE FUNCTION pg_temp.parse_conninfo(v text) RETURNS jsonb AS $$
DECLARE
    m      text[];
    k      text;
    val    text;
    out    jsonb := '{}'::jsonb;
    -- Keys that carry secrets are never returned, in either form.
    secret text[] := ARRAY['password','passfile','sslpassword'];
    -- Only these known connection keys are returned; anything else is dropped.
    allowed text[] := ARRAY['host','hostaddr','port','user','dbname','application_name',
        'sslmode','sslrootcert','sslcert','sslkey','sslcrl','sslcrldir','sslsni',
        'gssencmode','channel_binding','target_session_attrs','load_balance_hosts',
        'connect_timeout','keepalives','keepalives_idle','keepalives_interval',
        'keepalives_count','tcp_user_timeout','krbsrvname','service','requiressl',
        'replication','ssl_min_protocol_version','ssl_max_protocol_version',
        'require_auth','sslcertmode','sslnegotiation','sslcompression',
        'gssdelegation','fallback_application_name'];
BEGIN
    IF v IS NULL OR v = '' THEN RETURN NULL; END IF;
    IF v ~* '^postgres(ql)?://' THEN
        -- URI form: postgresql://[user[:password]@][hostspec][/dbname][?k=v&...]
        -- Like libpq, the userinfo ends only at '@' or '/', so a password may
        -- contain '?' or '#'. Only the user name is kept from it.
        m := regexp_match(v, '^[A-Za-z]+://(?:([^@/]*)@)?([^/?#]*)(?:/([^?#]*))?(?:\?([^#]*))?');
        -- An '@' left anywhere after the userinfo means the URI cannot be read
        -- safely (e.g. a '/' inside the password); report it, never guess.
        -- Whitespace or '=' in the user, host or dbname means a mixed or
        -- malformed string (e.g. '.../postgres password=x'): also unparsed.
        IF m IS NULL
           OR position('@' in coalesce(m[2], '') || coalesce(m[3], '') || coalesce(m[4], '')) > 0
           OR coalesce(split_part(m[1], ':', 1), '') || coalesce(m[2], '') || coalesce(m[3], '') ~ '[\s=]'
           -- A query parameter with whitespace or a second '=' is malformed too.
           OR coalesce(m[4], '') ~ '\s|=[^&]*=' THEN
            RETURN jsonb_build_object('unparsed', true);
        END IF;
        IF m[1] IS NOT NULL AND split_part(m[1], ':', 1) <> '' THEN
            out := out || jsonb_build_object('user', split_part(m[1], ':', 1));
        END IF;
        IF m[2] <> '' THEN out := out || jsonb_build_object('host', m[2]); END IF;
        IF coalesce(m[3], '') <> '' THEN out := out || jsonb_build_object('dbname', m[3]); END IF;
        IF m[4] IS NOT NULL THEN
            FOREACH val IN ARRAY string_to_array(m[4], '&') LOOP
                k := lower(split_part(val, '=', 1));
                -- libpq percent-decodes keywords too, so an encoded key could
                -- name a secret: drop any key containing '%'.
                IF k = ANY (allowed) AND k <> ALL (secret) AND position('%' in k) = 0 THEN
                    out := out || jsonb_build_object(k,
                        pg_temp.mask_secrets(substring(val from position('=' in val) + 1)));
                END IF;
            END LOOP;
        END IF;
        RETURN out;
    END IF;
    -- Keyword/value form. Like libpq, backslash escapes apply in quoted and
    -- unquoted values, so a value containing spaces, quotes or '=' is consumed
    -- whole. Returned values still pass through mask_secrets.
    FOR m IN SELECT regexp_matches(v,
            '([A-Za-z_]+)\s*=\s*(''(?:[^''\\]|\\.)*''|(?:[^\s''\\]|\\.)(?:[^\s\\]|\\.)*)', 'g') LOOP
        k := lower(m[1]);
        IF k = ANY (allowed) AND k <> ALL (secret) THEN
            out := out || jsonb_build_object(k, pg_temp.mask_secrets(trim(both '''' from m[2])));
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
-- Only these degrade to a gap. Everything else is a bug in this file and
-- must abort the run: a collector that reports its own defects as absent
-- data is worse than one that refuses to finish.
EXCEPTION
    WHEN insufficient_privilege THEN RETURN NULL;
    WHEN undefined_table OR undefined_function OR undefined_column
                               OR undefined_object THEN RETURN NULL;
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
-- 1b. Check runner. Answers the questions in the check manifest.
--
-- The manifest is DATA. Nothing in it is ever executed as SQL: for kind
-- 'setting' the name is passed to current_setting() as an argument, so a
-- hostile name is just a setting that does not exist.
--
-- Two kinds of failure, handled differently:
--   * Malformed manifest (missing field, duplicate id, wrong version)
--       -> RAISE: the whole run refuses. The manifest builder never produces
--          these, so one means a broken or tampered file.
--   * Runtime problem on THIS server (unknown setting, missing privilege,
--     a kind this collector version does not support)
--       -> status 'error' for that check only; the rest still run.
--
-- Every value passes through sanitise_setting(), exactly like the baseline
-- 'settings' section. A second route to the same data must keep every
-- protection of the first.
-- ---------------------------------------------------------------------------
CREATE FUNCTION pg_temp.run_checks(p_manifest jsonb) RETURNS jsonb AS $$
DECLARE
    v_out     jsonb := '{}'::jsonb;
    v_check   jsonb;
    v_pos     int   := 0;
    v_spec_id text;
    v_hash    text;
    v_kind    text;
    v_query   text;
    v_name    text;
    v_result  text;
    v_error   text;
BEGIN
    IF p_manifest->'manifest_version' IS DISTINCT FROM '1'::jsonb THEN
        RAISE EXCEPTION 'MANIFEST_INVALID: manifest_version must be 1, got %',
            coalesce(p_manifest->>'manifest_version', 'null');
    END IF;
    IF jsonb_typeof(p_manifest->'checks') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'MANIFEST_INVALID: checks must be an array';
    END IF;

    FOR v_check IN SELECT e FROM jsonb_array_elements(p_manifest->'checks') AS e LOOP
        v_pos    := v_pos + 1;
        v_result := NULL;          -- reset every iteration: no value may leak
        v_error  := NULL;          -- from one check into the next

        IF jsonb_typeof(v_check) IS DISTINCT FROM 'object' THEN
            RAISE EXCEPTION 'MANIFEST_INVALID: entry % is not an object', v_pos;
        END IF;

        v_spec_id := nullif(v_check->>'spec_id',   '');
        v_hash    := nullif(v_check->>'spec_hash', '');
        v_kind    := nullif(v_check->>'kind',      '');
        v_query   := nullif(v_check->>'query',     '');
        v_name    := nullif(v_check->>'setting_name', '');

        IF v_spec_id IS NULL THEN
            RAISE EXCEPTION 'MANIFEST_INVALID: entry % has no spec_id', v_pos;
        ELSIF v_out ? v_spec_id THEN
            RAISE EXCEPTION 'MANIFEST_INVALID: entry % repeats spec_id %', v_pos, v_spec_id;
        ELSIF v_hash IS NULL THEN
            RAISE EXCEPTION 'MANIFEST_INVALID: entry % (%) has no spec_hash', v_pos, v_spec_id;
        ELSIF v_kind IS NULL THEN
            RAISE EXCEPTION 'MANIFEST_INVALID: entry % (%) has no kind', v_pos, v_spec_id;
        ELSIF v_query IS NULL THEN
            RAISE EXCEPTION 'MANIFEST_INVALID: entry % (%) has no query', v_pos, v_spec_id;
        END IF;

        IF v_kind = 'setting' THEN
            IF v_name IS NULL THEN
                RAISE EXCEPTION 'MANIFEST_INVALID: entry % (%) has no setting_name', v_pos, v_spec_id;
            END IF;
            BEGIN
                v_result := pg_temp.sanitise_setting(v_name, current_setting(v_name));
            EXCEPTION WHEN OTHERS THEN
                v_error := SQLERRM;
            END;
        ELSE
            v_error := 'unsupported kind: ' || v_kind;
        END IF;

        v_out := v_out || jsonb_build_object(v_spec_id,
            CASE WHEN v_error IS NULL
                 THEN jsonb_build_object('spec_hash', v_hash, 'query', v_query,
                                         'status', 'ok',    'result', v_result)
                 ELSE jsonb_build_object('spec_hash', v_hash, 'query', v_query,
                                         'status', 'error', 'error',  v_error)
            END);
    END LOOP;

    RETURN v_out;
END;
$$ LANGUAGE plpgsql;


-- ---------------------------------------------------------------------------
-- 2. Version-gated / privilege-gated SQL fragments, as text.
--    Kept as strings so PostgreSQL never parses them on a version where the
--    catalog does not exist.
-- ---------------------------------------------------------------------------

CREATE FUNCTION pg_temp.sql_password_types() RETURNS text AS $$
    SELECT $q$
        SELECT coalesce(jsonb_agg(jsonb_build_object(
            'rolname', rolname,
            'password_type', CASE
                WHEN rolpassword IS NULL                      THEN 'none'
                WHEN rolpassword LIKE 'SCRAM-SHA-256$%'       THEN 'scram-sha-256'
                WHEN rolpassword LIKE 'md5%'                  THEN 'md5'
                ELSE 'other' END,
            'rolvaliduntil', rolvaliduntil
        ) ORDER BY rolname), '[]'::jsonb)
        FROM pg_authid WHERE rolcanlogin
    $q$;
$$ LANGUAGE sql IMMUTABLE;

CREATE FUNCTION pg_temp.sql_hba() RETURNS text AS $$
    SELECT $q$
        SELECT coalesce(jsonb_agg(jsonb_build_object(
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
        ) ORDER BY line_number), '[]'::jsonb)
        FROM pg_hba_file_rules
    $q$;
$$ LANGUAGE sql IMMUTABLE;

CREATE FUNCTION pg_temp.sql_ident() RETURNS text AS $$
    SELECT $q$
        SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.line_number), '[]'::jsonb)
        FROM pg_ident_file_mappings t
    $q$;
$$ LANGUAGE sql IMMUTABLE;

CREATE FUNCTION pg_temp.sql_file_settings() RETURNS text AS $$
    SELECT $q$
        SELECT coalesce(jsonb_agg(jsonb_build_object(
            'sourcefile', sourcefile,
            'sourceline', sourceline,
            'name',       name,
            'setting',    pg_temp.sanitise_setting(name, setting),
            'applied',    applied,
            'error',      error
        ) ORDER BY sourcefile, sourceline), '[]'::jsonb)
        FROM pg_file_settings
    $q$;
$$ LANGUAGE sql IMMUTABLE;

-- Functions that run with elevated privileges or pinned settings (CIS 4.5).
-- Same predicate as the CIS audit query. Never prosrc: a function body can
-- embed credentials. Of proconfig only the setting NAMES are returned, plus
-- the search_path value, which is what makes a SECURITY DEFINER function
-- safe or hijackable. Every other value is withheld.
CREATE FUNCTION pg_temp.sql_functions() RETURNS text AS $$
    SELECT $q$
        SELECT coalesce(jsonb_agg(jsonb_build_object(
            'schema',        n.nspname,
            'name',          p.proname,
            'identity_args', pg_get_function_identity_arguments(p.oid),
            'kind',          p.prokind,
            'language',      l.lanname,
            'prosecdef',     p.prosecdef,
            'config_names',  coalesce((SELECT jsonb_agg(split_part(c, '=', 1) ORDER BY ord)
                              FROM unnest(p.proconfig) WITH ORDINALITY AS u(c, ord)), '[]'::jsonb),
            'search_path',   (SELECT substring(c from position('=' in c) + 1)
                              FROM unnest(p.proconfig) c
                              WHERE split_part(c, '=', 1) = 'search_path' LIMIT 1),
            'owner',         pg_get_userbyid(p.proowner),
            -- A NULL proacl is the default, in which PUBLIC may EXECUTE; it is
            -- expanded so null never stands for "no grants".
            'acl',           coalesce(p.proacl, acldefault('f', p.proowner))::text[],
            'extension',     (SELECT e.extname FROM pg_depend d
                              JOIN pg_extension e ON e.oid = d.refobjid
                              WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid
                                AND d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e')
        ) ORDER BY n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)), '[]'::jsonb)
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_language  l ON l.oid = p.prolang
        WHERE p.prosecdef OR p.proconfig IS NOT NULL
    $q$;
$$ LANGUAGE sql IMMUTABLE;

-- WAL archiving state (CIS 7.4). archive_command is a shell command and is
-- NEVER returned, masked or not: only whether it is set. SHOW reports
-- '(disabled)' while archive_mode is off, exactly as the CIS query expects.
-- archive_library does not exist before PG15; it is then null, not an error.
CREATE FUNCTION pg_temp.sql_archiving() RETURNS text AS $$
    SELECT $q$
        SELECT jsonb_build_object(
            'archive_mode',           current_setting('archive_mode'),
            'archive_library',        current_setting('archive_library', true),
            'archive_command_is_set', current_setting('archive_command') NOT IN ('', '(disabled)'),
            'stat_archiver', (SELECT jsonb_build_object(
                'archived_count',     archived_count,
                'last_archived_wal',  last_archived_wal,
                'last_archived_time', last_archived_time,
                'failed_count',       failed_count,
                'last_failed_wal',    last_failed_wal,
                'last_failed_time',   last_failed_time,
                'stats_reset',        stats_reset)
              FROM pg_stat_archiver)
        )
    $q$;
$$ LANGUAGE sql IMMUTABLE;

-- ===========================================================================
-- 3. The bundle.
-- ===========================================================================
SELECT jsonb_pretty(jsonb_build_object(

-- ---- envelope -------------------------------------------------------------
'envelope', jsonb_build_object(
    'schema_version',      '0.3.0',
    'collector_version',   '2.0.0-sql',
    'collected_at',        to_char(now() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'target_id',           :'target_id',
    'database',            current_database(),
    'collected_by',        current_user,
    'is_superuser',        (SELECT rolsuper FROM pg_roles WHERE rolname = current_user),
    'has_pg_monitor',      pg_has_role(current_user,'pg_monitor','MEMBER'),
    'has_read_all_settings', pg_has_role(current_user,'pg_read_all_settings','MEMBER'),
    'can_read_pg_authid',  has_table_privilege('pg_authid','SELECT'),
    'deployment_type',     'self-managed',
    -- provenance: exactly which code and which question list produced this
    'collector_sha256',    :'collector_sha256',
    'manifest', jsonb_build_object(
        'sha256',           :'manifest_sha256',
        'manifest_version', mf.m->'manifest_version',
        'benchmark_id',     mf.m->'benchmark_id',
        'check_count',      CASE WHEN jsonb_typeof(mf.m->'checks') = 'array'
                                 THEN jsonb_array_length(mf.m->'checks') END
    )
),

-- ---- baseline: the fixed picture, the same for every benchmark -----------
-- Everything below up to 'checks' is unchanged from 0.2.0, just nested.
'baseline', jsonb_build_object(

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
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'name',            s.name,
        'setting',         pg_temp.sanitise_setting(s.name, s.setting),
        'unit',            s.unit,
        'category',        s.category,
        'context',         s.context,
        'vartype',         s.vartype,
        'source',          s.source,
        'sourcefile',      s.sourcefile,
        'sourceline',      s.sourceline,
        'boot_val',        pg_temp.sanitise_setting(s.name, s.boot_val),
        'reset_val',       pg_temp.sanitise_setting(s.name, s.reset_val),
        'pending_restart', s.pending_restart,
        'sanitised',       pg_temp.is_secret_setting(s.name)
    ) ORDER BY s.name), '[]'::jsonb)
    FROM pg_settings s
    WHERE s.source <> 'default'
       OR s.name IN (
            'log_connections','log_disconnections','log_statement','log_destination',
            'logging_collector','log_directory','log_filename','log_file_mode',
            'log_line_prefix','log_hostname','log_min_messages','log_min_error_statement',
            'log_min_duration_statement','log_error_verbosity','log_truncate_on_rotation',
            'log_rotation_age','log_rotation_size','log_checkpoints','log_lock_waits',
            'log_temp_files','log_autovacuum_min_duration','syslog_facility','syslog_ident',
            'syslog_sequence_numbers','syslog_split_messages','log_replication_commands',
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
    SELECT coalesce(jsonb_agg(jsonb_build_object(
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
    ) ORDER BY r.rolname), '[]'::jsonb)
    FROM pg_roles r
),

'role_memberships', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'role',         g.rolname,
        'member',       m.rolname,
        'grantor',      a.rolname,
        'admin_option', am.admin_option
    ) ORDER BY g.rolname, m.rolname), '[]'::jsonb)
    FROM pg_auth_members am
    JOIN pg_roles g ON g.oid = am.roleid
    JOIN pg_roles m ON m.oid = am.member
    LEFT JOIN pg_roles a ON a.oid = am.grantor
),

-- Password TYPE only. The hash itself is never selected, never returned.
'password_types', pg_temp.try_jsonb(pg_temp.sql_password_types()),

'role_settings', pg_temp.try_jsonb($q$
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'role',     coalesce(r.rolname,'ALL'),
        'database', coalesce(d.datname,'ALL'),
        -- Each name=value entry keeps its name; its value goes through
        -- sanitise_setting like every other setting value.
        'settings', (SELECT jsonb_agg(
                        split_part(c, '=', 1) || '=' ||
                        pg_temp.sanitise_setting(split_part(c, '=', 1),
                                                 substring(c from position('=' in c) + 1))
                        ORDER BY ord)
                     FROM unnest(s.setconfig) WITH ORDINALITY AS u(c, ord))
    )), '[]'::jsonb)
    FROM pg_db_role_setting s
    LEFT JOIN pg_roles r    ON r.oid = s.setrole
    LEFT JOIN pg_database d ON d.oid = s.setdatabase $q$),

-- ---- structure: names, owners, ACLs. Never rows. --------------------------
'databases', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'datname',      d.datname,
        'owner',        pg_get_userbyid(d.datdba),
        'encoding',     pg_encoding_to_char(d.encoding),
        'datcollate',   d.datcollate,
        'datctype',     d.datctype,
        'datallowconn', d.datallowconn,
        'datconnlimit', d.datconnlimit,
        'datistemplate',d.datistemplate,
        'datacl',       d.datacl::text[]
    ) ORDER BY d.datname), '[]'::jsonb)
    FROM pg_database d
),

'schemas', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'nspname', n.nspname,
        'owner',   pg_get_userbyid(n.nspowner),
        'nspacl',  n.nspacl::text[],
        'public_has_create', has_schema_privilege('public', n.oid, 'CREATE'),
        'public_has_usage',  has_schema_privilege('public', n.oid, 'USAGE')
    ) ORDER BY n.nspname), '[]'::jsonb)
    FROM pg_namespace n
    WHERE n.nspname NOT LIKE 'pg\_temp%'
      AND n.nspname NOT LIKE 'pg\_toast%'
),

-- Only objects that actually carry an ACL. A sandbox reproduces these as
-- stubs -- correct name, type, schema, owner. No columns, no data.
'object_acls', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'schema',   n.nspname,
        'name',     c.relname,
        'kind',     c.relkind,
        'owner',    pg_get_userbyid(c.relowner),
        'acl',      c.relacl::text[],
        'rls',      c.relrowsecurity,
        'rls_forced', c.relforcerowsecurity
    ) ORDER BY n.nspname, c.relname), '[]'::jsonb)
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog','information_schema')
      AND n.nspname NOT LIKE 'pg\_toast%'
      AND (c.relacl IS NOT NULL OR c.relrowsecurity)
),

'default_acls', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'owner',     pg_get_userbyid(d.defaclrole),
        'schema',    n.nspname,
        'objtype',   d.defaclobjtype,
        'acl',       d.defaclacl::text[]
    )), '[]'::jsonb)
    FROM pg_default_acl d
    LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
),

'rls_policies', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'schema', schemaname, 'table', tablename, 'policy', policyname,
        'permissive', permissive, 'roles', roles, 'cmd', cmd,
        -- Policy expressions can embed literals (USING (api_key = 'x')):
        -- only whether one is set and its length ship.
        'qual',       CASE WHEN qual IS NULL THEN NULL
                           ELSE '***REDACTED*** (set, ' || length(qual) || ' characters)' END,
        'with_check', CASE WHEN with_check IS NULL THEN NULL
                           ELSE '***REDACTED*** (set, ' || length(with_check) || ' characters)' END
    ) ORDER BY schemaname, tablename, policyname), '[]'::jsonb)
    FROM pg_policies
),

'extensions', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'extname', e.extname,
        'version', e.extversion,
        'schema',  n.nspname,
        'owner',   pg_get_userbyid(e.extowner)
    ) ORDER BY e.extname), '[]'::jsonb)
    FROM pg_extension e
    LEFT JOIN pg_namespace n ON n.oid = e.extnamespace
),

'tablespaces', pg_temp.try_jsonb($q$
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'spcname',  t.spcname,
        'owner',    pg_get_userbyid(t.spcowner),
        'acl',      t.spcacl::text[],
        'location', pg_tablespace_location(t.oid)
    ) ORDER BY t.spcname), '[]'::jsonb)
    FROM pg_tablespace t $q$),

'foreign_servers', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'srvname', s.srvname,
        'owner',   pg_get_userbyid(s.srvowner),
        'fdw',     w.fdwname,
        'acl',     s.srvacl::text[]
    ) ORDER BY s.srvname), '[]'::jsonb)
    FROM pg_foreign_server s
    JOIN pg_foreign_data_wrapper w ON w.oid = s.srvfdw
),

'event_triggers', (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
        'evtname', evtname, 'event', evtevent,
        'owner', pg_get_userbyid(evtowner), 'enabled', evtenabled
    ) ORDER BY evtname), '[]'::jsonb)
    FROM pg_event_trigger
),

-- Functions with SECURITY DEFINER or a SET clause. Names, owner, ACL only.
'functions',        pg_temp.try_jsonb(pg_temp.sql_functions()),

-- ---- authentication -------------------------------------------------------
-- ldapbindpasswd and radiussecret are masked in options.
'hba_rules',        pg_temp.try_jsonb(pg_temp.sql_hba()),
'ident_mappings',   pg_temp.try_jsonb(pg_temp.sql_ident()),
'file_settings',    pg_temp.try_jsonb(pg_temp.sql_file_settings()),

-- ---- replication ----------------------------------------------------------
'replication', jsonb_build_object(
    'slots', pg_temp.try_jsonb($q$
              SELECT coalesce(jsonb_agg(jsonb_build_object(
                  'slot_name', slot_name, 'plugin', plugin, 'slot_type', slot_type,
                  'database', database, 'temporary', temporary, 'active', active)
              ORDER BY slot_name), '[]'::jsonb) FROM pg_replication_slots $q$),
    'publications', (SELECT coalesce(jsonb_agg(jsonb_build_object(
                  'pubname', pubname, 'owner', pg_get_userbyid(pubowner),
                  'puballtables', puballtables, 'pubinsert', pubinsert,
                  'pubupdate', pubupdate, 'pubdelete', pubdelete)
              ORDER BY pubname), '[]'::jsonb) FROM pg_publication),
    -- subscription conninfo is parsed, password dropped
    'subscriptions', pg_temp.try_jsonb($q$
            SELECT coalesce(jsonb_agg(jsonb_build_object(
                'subname', subname,
                'owner', pg_get_userbyid(subowner),
                'enabled', subenabled,
                'conninfo_parsed', pg_temp.parse_conninfo(subconninfo))
            ORDER BY subname), '[]'::jsonb) FROM pg_subscription $q$),
    'primary_conninfo_parsed', pg_temp.try_jsonb($q$
        SELECT pg_temp.parse_conninfo(nullif(current_setting('primary_conninfo', true), '')) $q$),
    'in_recovery', pg_is_in_recovery()
),

-- ---- WAL archiving: mode, library, command presence, archiver counters ---
'archiving',        pg_temp.try_jsonb(pg_temp.sql_archiving()),

-- ---- operational baseline: aggregated, no query text ever ----------------
'connections', pg_temp.try_jsonb($q$
    SELECT coalesce(jsonb_agg(to_jsonb(g)), '[]'::jsonb)
    FROM (
        SELECT coalesce(nullif(application_name,''),'(none)') AS application_name,
               usename,
               datname,
               CASE
                 WHEN client_addr IS NULL                  THEN 'unix_socket'
                 WHEN client_addr << inet '127.0.0.0/8'    THEN 'loopback'
                 WHEN client_addr << inet '10.0.0.0/8'
                   OR client_addr << inet '172.16.0.0/12'
                   OR client_addr << inet '192.168.0.0/16' THEN 'private'
                 ELSE 'public' END                          AS client_addr_class,
               count(*)                                     AS connection_count
        FROM pg_stat_activity
        WHERE backend_type = 'client backend'
        GROUP BY 1,2,3,4
    ) g $q$),

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
                   'section','replication.primary_conninfo_parsed',
                   'reason','insufficient_privilege',
                   'remediation','primary_conninfo requires pg_read_all_settings. Null here does NOT mean the server is a primary.'
               )
        WHERE NOT pg_has_role(current_user,'pg_read_all_settings','MEMBER')
          AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
        UNION ALL
        SELECT jsonb_build_object(
                   'section','settings.sourcefile',
                   'reason','insufficient_privilege',
                   'remediation','GRANT pg_read_all_settings -- without it sourcefile and sourceline are null and remediation cannot tell ALTER SYSTEM from postgresql.conf.'
               )
        WHERE NOT pg_has_role(current_user,'pg_read_all_settings','MEMBER')
          AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
        UNION ALL
        SELECT jsonb_build_object(
                   'section','functions',
                   'reason', pg_temp.try_reason(pg_temp.sql_functions()),
                   'remediation','pg_proc is readable by every role by default; restore SELECT on pg_proc, pg_namespace, pg_language, pg_depend and pg_extension.'
               )
        WHERE pg_temp.try_reason(pg_temp.sql_functions()) IS NOT NULL
        UNION ALL
        SELECT jsonb_build_object(
                   'section','archiving',
                   'reason', pg_temp.try_reason(pg_temp.sql_archiving()),
                   'remediation','archive_mode, archive_library, archive_command or pg_stat_archiver could not be read. Null here does NOT mean archiving is off.'
               )
        WHERE pg_temp.try_reason(pg_temp.sql_archiving()) IS NOT NULL
    ) q
),

-- ---- what was deliberately withheld -------------------------------------
'redactions', jsonb_build_array(
    jsonb_build_object('field','pg_authid.rolpassword','class','S0',
        'note','Password verifiers are never selected. Only the derived type is returned.'),
    jsonb_build_object('field','pg_settings.archive_command','class','S0',
        'note','Never shipped (also restore_command, archive_cleanup_command, recovery_end_command, ssl_passphrase_command, krb_server_keyfile): only whether a value is set and its length.'),
    jsonb_build_object('field','pg_settings.primary_conninfo','class','S0',
        'note','Raw value never shipped (only whether it is set and its length). Parsed to allowlisted connection keys only (host, port, user, dbname, sslmode and similar), values masked; anything that cannot be read safely is reported as unparsed.'),
    jsonb_build_object('field','pg_subscription.subconninfo','class','S2',
        'note','Parsed to allowlisted connection keys only, values masked; never password, passfile or sslpassword; anything that cannot be read safely is reported as unparsed.'),
    jsonb_build_object('field','custom and extension settings','class','S0',
        'note','Values of dotted settings (e.g. pgrst.jwt_secret) are never shipped in settings, file_settings or role_settings, except an exact list of reviewed pgaudit, set_user, pg_stat_statements and plpgsql settings.'),
    jsonb_build_object('field','pg_policies.qual and with_check','class','S0',
        'note','Policy expressions can embed literals: only whether one is set and its length.'),
    jsonb_build_object('field','pg_hba_file_rules.options','class','S2',
        'note','ldapbindpasswd and radiussecret masked; rule structure preserved.'),
    jsonb_build_object('field','pg_proc.prosrc','class','S0',
        'note','Function bodies are never selected.'),
    jsonb_build_object('field','pg_proc.proconfig','class','S2',
        'note','Setting names only; the search_path value is the one value returned, unmasked.'),
    jsonb_build_object('field','archiving.archive_command','class','S0',
        'note','Never returned in the archiving section; only archive_command_is_set (boolean).'),
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

), -- end baseline

-- ---- checks: answers to the manifest's questions, keyed by spec_id -------
'checks', pg_temp.run_checks(mf.m)

)) AS bundle
-- The manifest is parsed once, here. The wrapper always passes it as a psql
-- variable (an empty manifest when run without -m), quoted as a literal.
FROM (SELECT :'manifest'::jsonb AS m) AS mf;
