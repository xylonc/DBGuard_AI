-- §5. SECURITY DEFINER functions — pg_proc
-- Collects function signatures, owners, and config.
-- Function bodies (prosrc) are NEVER collected (S0).
-- Requires: SELECT from pg_proc (superuser or function owner) (S4)
SELECT jsonb_agg(
    jsonb_build_object(
        'database',        NULL,   -- filled by bash wrapper
        'schema_name',     n.nspname,
        'function_name',   p.proname,
        'owner',           rol.rolname,
        'language',        lan.lanname,
        'config',          CASE WHEN p.proconfig IS NOT NULL
                                THEN jsonb_agg(p.proconfig)
                                ELSE '[]'::jsonb
                            END
    )
)
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_roles rol ON rol.oid = p.proowner
JOIN pg_language lan ON lan.oid = p.lanoid
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
GROUP BY p.oid, n.nspname, p.proname, rol.rolname, lan.lanname
