-- §5. Object privileges — per-database
-- Collects only ACL deviations from owner-defaults.
-- Requires: SELECT on catalog tables in the target database (S4)
SELECT jsonb_agg(
    jsonb_build_object(
        'object_type',   class.relkind::text,
        'database',      NULL,  -- filled by bash wrapper
        'schema_name',   nsp.nspname,
        'object_name',   class.relname,
        'owner',         rol.rolname,
        'acl',           CASE
                            WHEN class.relacl IS NOT NULL
                            THEN jsonb_agg(
                                jsonb_build_object(
                                    'grantee', ae.grantee::text,
                                    'grantor', ae.grantor::text,
                                    'privileges', ae.privs,
                                    'grantable', ae.grantable
                                )
                            )
                            ELSE '[]'::jsonb
                        END,
        'acl_is_default', class.relacl IS NULL
    )
)
FROM pg_class class
JOIN pg_namespace nsp ON nsp.oid = class.relnamespace
JOIN pg_roles rol ON rol.oid = class.relowner
CROSS JOIN LATERAL jsonb_to_recordset(class.relacl::jsonb) AS ae(
    grantee regrole,
    grantor regrole,
    privs text[],
    grantable boolean[]
)
WHERE class.relacl IS NOT NULL
  AND nsp.nspname NOT IN ('pg_catalog', 'information_schema')
  -- Exclude system tables that don't need ACL assessment
  AND class.relkind IN ('r', 'v', 'm', 'S', 'f', 'p')
