-- §3. DbRoleSetting — ALTER DATABASE/ROLE ... SET
-- Silently overrides cluster-level hardening.
-- Requires: pg_monitor (SELECT from pg_db_role_setting) (S4)
SELECT jsonb_agg(
    jsonb_build_object(
        'database',  CASE WHEN d.datname = 'NULL'::text THEN NULL ELSE d.datname END,
        'role',      CASE WHEN r.rolname = 'NULL'::text THEN NULL ELSE r.rolname END,
        'settings',  s.settings
    )
)
FROM pg_db_role_setting s
LEFT JOIN pg_database d ON d.oid = s.setdatabaseid
LEFT JOIN pg_roles r ON r.oid = s.setroleid
WHERE (s.setdatabaseid IS NULL AND s.setroleid IS NULL)  -- per-cluster
   OR (s.setdatabaseid IS NOT NULL AND d.datallowconn = true)
   OR (s.setroleid IS NOT NULL AND r.rolcanlogin = true)
