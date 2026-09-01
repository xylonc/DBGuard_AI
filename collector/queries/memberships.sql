-- §5. Role memberships — pg_auth_members
-- Collects role memberships with grant/inherit/set options.
-- Requires: superuser or pg_monitor (S4)
SELECT jsonb_agg(
    jsonb_build_object(
        'member',     mem.rolname,
        'grantor',    CASE WHEN g.rolname = 'NULL'::text THEN NULL ELSE g.rolname END,
        'role',       r.rolname,
        'admin_option', am.admin_option,
        'inherit_option', CASE
            WHEN {{SERVER_MAJOR}} >= 16 THEN am.inherit_option
            ELSE NULL
        END,
        'set_option',   CASE
            WHEN {{SERVER_MAJOR}} >= 16 THEN am.set_option
            ELSE NULL
        END
    )
)
FROM pg_auth_members am
JOIN pg_roles mem ON mem.oid = am.member
JOIN pg_roles r ON r.oid = am.roleid
LEFT JOIN pg_roles g ON g.oid = am.grantor
ORDER BY mem.rolname, r.rolname
