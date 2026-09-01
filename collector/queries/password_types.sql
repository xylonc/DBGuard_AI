-- §5. password_types — SECURITY DEFINER function to derive password type
-- from pg_authid without exposing the hash (S1).
-- This must be created by grant_collector_role.sql.
-- It uses SECURITY DEFINER so the calling role never needs
-- direct SELECT on pg_authid.
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

-- Revoke public execute; only the collector role runs this
REVOKE EXECUTE ON FUNCTION dbguard_password_types() FROM PUBLIC;
