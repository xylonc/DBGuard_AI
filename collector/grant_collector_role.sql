-- DBGuardAI — Grant collector role
-- Run this AS SUPERUSER on the target database before running the collector.
-- This creates a SECURITY DEFINER function and a limited-privilege role
-- for the collector to run under.
--
-- The function dbguard_password_types() reads pg_authid in SECURITY DEFINER
-- mode, which is structurally incapable of returning a password hash —
-- it only returns the prefix-derived type. This is far easier for a DBA
-- to approve than granting direct SELECT on pg_authid.

-- ---------------------------------------------------------------------------
-- 1. Create the SECURITY DEFINER function for password type derivation
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION dbguard_password_types()
RETURNS TABLE (rolname name, password_type text)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog
AS $$
  SELECT rolname,
         CASE WHEN rolpassword IS NULL THEN 'none'
              WHEN left(rolpassword, 4) = 'SCRA' THEN 'scram-sha-256'
              WHEN left(rolpassword, 3) = 'md5'  THEN 'md5'
              ELSE 'unknown' END
  FROM pg_authid;
$$;

-- Revoke public execute
REVOKE EXECUTE ON FUNCTION dbguard_password_types() FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- 2. Create the collector role (or alter if it exists)
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    -- Create role if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbguard_collector') THEN
        CREATE ROLE dbguard_collector LOGIN;
    END IF;
END
$$;

-- Grant login (revoke if you want a non-login role for use with --role)
-- ALTER ROLE dbguard_collector NOLOGIN;

-- ---------------------------------------------------------------------------
-- 3. Grant privileges — these are the minimum for full coverage
--    The collector will gracefully degrade if some are missing.
-- ---------------------------------------------------------------------------

-- Required: read settings
GRANT pg_monitor TO dbguard_collector;

-- Optional but recommended:
-- For config file reading (postgresql.conf, pg_hba.conf, pg_ident.conf):
-- GRANT pg_read_server_files TO dbguard_collector;

-- For HBA rules (superuser-only in PG 10+):
-- GRANT pg_read_all_settings TO dbguard_collector;

-- For SELECT on pg_authid via the function (already covered by SECURITY DEFINER):
-- The function handles this; no direct grant needed.

-- ---------------------------------------------------------------------------
-- 4. Usage
-- ---------------------------------------------------------------------------
-- After running this file, the collector can be run as:
--   PGUSER=dbguard_collector PGDATABASE=postgres ./dbguard-collect.sh --target=myserver
--
-- Or with any role that has the above grants. The script will still work
-- with a superuser role — no restrictions on the connecting role, but the
-- SECURITY DEFINER function ensures password hashes never leak.
