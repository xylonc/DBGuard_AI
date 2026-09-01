-- §6. Extensions — pg_extension (per-database)
-- Collects installed extensions with their metadata.
-- Requires: pg_monitor (S4)
SELECT jsonb_agg(
    jsonb_build_object(
        'database',           current_database(),
        'name',               ext.extname,
        'installed_version',  ext.extversion,
        'default_version',    (SELECT extdefaultversion FROM pg_extension e2 WHERE e2.extname = ext.extname LIMIT 1),
        'schema_name',        n.nspname,
        'owner',              rol.rolname,
        'trusted',            CASE
                                WHEN {{SERVER_MAJOR}} >= 13 THEN ext.exttrusted
                                ELSE NULL
                            END,
        'relocatable',        ext.extrelocatable
    )
)
FROM pg_extension ext
JOIN pg_namespace n ON n.oid = ext.extnamespace
JOIN pg_roles rol ON rol.oid = ext.extowner
ORDER BY ext.extname
