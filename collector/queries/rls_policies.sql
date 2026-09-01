-- §5. RLS policies — pg_policies (per-database)
-- Collects Row Level Security policy definitions.
-- Policy expressions (using_expr, with_check_expr) are S4 metadata,
-- not row data — they are safe to collect.
-- Requires: SELECT from pg_policies (superuser or object owner) (S4)
SELECT jsonb_agg(
    jsonb_build_object(
        'database',        NULL,  -- filled by bash wrapper
        'schema_name',     pol.polnamespace,
        'table_name',      pol.polrelname,
        'policy_name',     pol.polname,
        'permissive',      CASE WHEN pol.polpermissive = 'p' THEN true ELSE false END,
        'roles',           pol.polroles,
        'command',         pol.polcmd,
        'using_expr',      pol.polqual,
        'with_check_expr', pol.polwithcheck
    )
)
FROM (
    SELECT p.polname,
           p.polrelid,
           n.nspname AS polnamespace,
           c.relname AS polrelname,
           CASE p.polcmd WHEN 'r' THEN 'SELECT'
                          WHEN 'w' THEN 'UPDATE'
                          WHEN 'd' THEN 'DELETE'
                          WHEN '*' THEN 'ALL' END AS polcmd,
           p.polroles::text[] AS polroles,
           p.polpermissive,
           pg_get_expr(p.polqual, p.polrelid) AS polqual,
           pg_get_expr(p.polwithcheck, p.polrelid) AS polwithcheck
    FROM pg_policy p
    JOIN pg_class c ON c.oid = p.polrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
) pol
ORDER BY pol.polnamespace, pol.polrelname, pol.polname
