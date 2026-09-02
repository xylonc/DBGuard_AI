-- CIS 5.3: No role uses md5 password storage
-- Collects per-role login-capable flag and derived password type.
-- Hash is NEVER collected (S0).  The dbguard_password_types() SECURITY
-- DEFINER function returns password_type without exposing the hash.
-- Requires: EXECUTE on dbguard_password_types() granted to the collector role.

SELECT jsonb_agg(
    jsonb_build_object(
        'rolname',         r.rolname,
        'rolcanlogin',     r.rolcanlogin,
        'password_type',   pt.password_type
    )
    ORDER BY r.rolname
)
FROM pg_roles r
LEFT JOIN LATERAL dbguard_password_types() pt ON pt.rolname = r.rolname
WHERE r.rolcanlogin;
