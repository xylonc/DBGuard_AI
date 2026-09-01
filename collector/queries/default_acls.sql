-- §5. Default ACLs — pg_default_acl (per-database)
-- Collects default ACL templates that will apply to future objects.
-- Requires: SELECT from pg_default_acl (S4)
SELECT jsonb_agg(
    jsonb_build_object(
        'role',       CASE WHEN r.rolname = 'NULL'::text THEN NULL ELSE r.rolname END,
        'schema_name', CASE WHEN ns.nspname = 'NULL'::text THEN NULL ELSE ns.nspname END,
        'object_type', da.defaclclass::regclass::text,
        'acl',        jsonb_agg(da.defaclacl ORDER BY da.defaclacl)
    )
)
FROM pg_default_acl da
LEFT JOIN pg_roles r ON r.oid = da.defaclrole
LEFT JOIN pg_namespace ns ON ns.oid = da.defaclnamespace
GROUP BY da.defaclnamespace, da.defaclclass, r.rolname
