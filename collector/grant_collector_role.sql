-- DBGuardAI — Grant collector role
-- Run this AS SUPERUSER on the target database before running the collector.
--
-- Creates:
--   1. dbguard_password_types() — SECURITY DEFINER function that derives
--      password_type from pg_authid without exposing the hash (S0).
--   2. dbguard_collector role — minimal privileges for the collector.

-- ── 1. SECURITY DEFINER function ──────────────────────────────────────────
-- Returns one row per role with its password type.  Never returns the hash.
-- Uses pg_authid (only visible to superusers and SECURITY DEFINER functions).
DROP FUNCTION IF EXISTS dbguard_password_types() CASCADE;

CREATE OR REPLACE FUNCTION dbguard_password_types()
RETURNS TABLE(rolname text, password_type text)
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT r.rolname,
           CASE
               WHEN r.rolpassword IS NULL THEN 'none'
               WHEN r.rolpassword LIKE 'SCRAM-SHA-256%' THEN 'scram-sha-256'
               WHEN r.rolpassword LIKE 'md5%' THEN 'md5'
               ELSE 'plain'
           END AS password_type
    FROM pg_authid r;
END;
$$;

-- Lock down the function: revoke all from PUBLIC, then grant only to
-- the collector role (created below).
REVOKE ALL ON FUNCTION dbguard_password_types() FROM PUBLIC;

-- ── 2. Collector role ────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbguard_collector') THEN
        CREATE ROLE dbguard_collector LOGIN;
    END IF;
END
$$;

-- Use dynamic SQL so CONNECT works without psql variable substitution
DO $$
DECLARE
    _db_name text;
BEGIN
    _db_name := current_database();
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO dbguard_collector', _db_name);
END
$$;
GRANT USAGE ON SCHEMA pg_catalog TO dbguard_collector;

-- Catalog reads needed for the three CIS controls
-- NOTE: We do NOT grant SELECT ON pg_authid directly.
-- pg_authid access lives inside dbguard_password_types() in the definer's context.
GRANT SELECT ON pg_roles          TO dbguard_collector;
GRANT SELECT ON pg_namespace      TO dbguard_collector;
GRANT SELECT ON pg_database       TO dbguard_collector;
GRANT SELECT ON pg_settings       TO dbguard_collector;
GRANT SELECT ON pg_auth_members   TO dbguard_collector;

-- EXECUTE on the SECURITY DEFINER function (this is the critical grant)
GRANT EXECUTE ON FUNCTION dbguard_password_types() TO dbguard_collector;

-- Grant pg_monitor / pg_read_all_settings unconditionally when the running
-- user is a superuser, because superusers hold these privileges implicitly
-- (they are not members of the role in pg_auth_members).
DO $$
BEGIN
    IF (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        -- Running as superuser: grant the roles directly
        BEGIN
            GRANT pg_monitor TO dbguard_collector;
        EXCEPTION WHEN insufficient_privilege THEN NULL;
        END;
        BEGIN
            GRANT pg_read_all_settings TO dbguard_collector;
        EXCEPTION WHEN insufficient_privilege THEN NULL;
        END;
    ELSE
        -- Running as non-superuser: grant only if we are a member
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_auth_members m
                JOIN pg_roles r ON r.oid = m.roleid
                WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
                  AND r.rolname = 'pg_monitor'
            ) THEN
                GRANT pg_monitor TO dbguard_collector;
            END IF;
        EXCEPTION WHEN insufficient_privilege THEN NULL;
        END;

        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_auth_members m
                JOIN pg_roles r ON r.oid = m.roleid
                WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
                  AND r.rolname = 'pg_read_all_settings'
            ) THEN
                GRANT pg_read_all_settings TO dbguard_collector;
            END IF;
        EXCEPTION WHEN insufficient_privilege THEN NULL;
        END;
    END IF;
END
$$;
