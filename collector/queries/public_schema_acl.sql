-- CIS 5.2: CREATE on schema public not granted to PUBLIC
-- Collects the ACL on schema public, per database.
-- Requires: SELECT on information_schema.table_privileges (or catalog)
--
-- We query the information_schema for schema-level privileges on "public".
-- This is safe because information_schema is readable by any role with
-- USAGE on the database.

SELECT jsonb_build_object(
    'database',         current_database(),
    'schema_name',      'public',
    'owner',            n.nspowner::regrole::text,
    'acl',              nspacl::text
)
FROM pg_namespace n
WHERE n.nspname = 'public';
