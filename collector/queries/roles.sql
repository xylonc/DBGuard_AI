-- §5. Roles — pg_roles
-- Collects role attributes. Password hash is NEVER collected (S0).
-- Uses the dbguard_password_types() SECURITY DEFINER function for
-- password_type derivation (S1). Falls back to pg_authid if superuser.
-- Requires: pg_monitor or superuser (S4 for role attrs, S1 for password_type)
SELECT jsonb_agg(
    jsonb_build_object(
        'name',       r.rolname,
        'oid',        r.oid,
        'superuser',  r.rolsuper,
        'inherit',    r.rolinherit,
        'create_role', r.rolcreaterole,
        'create_db',  r.rolcreatedb,
        'can_login',  r.rolcanlogin,
        'replication', r.rolreplication,
        'bypass_rls', r.rolbypassrls,
        'conn_limit', r.rolconnlimit,
        'valid_until', r.rolvaliduntil,
        'password_type', CASE
            WHEN '{{CAN_SELECT_AUTHID}}' = 'true' THEN (
                SELECT pt.password_type
                FROM dbguard_password_types() pt
                WHERE pt.rolname = r.rolname
            )
            ELSE 'unknown'
        END,
        'config',      CASE WHEN r.rolconfig IS NOT NULL
                       THEN jsonb_agg(r.rolconfig) OVER ()
                       ELSE '[]'::jsonb
                   END
    )
)
FROM pg_roles r
ORDER BY r.rolname
