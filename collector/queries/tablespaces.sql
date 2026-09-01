-- §6. Tablespaces — pg_tablespace
-- Collects tablespace definitions with ACLs.
-- Requires: SELECT from pg_tablespace (superuser) (S4)
SELECT jsonb_agg(
    jsonb_build_object(
        'name',        spcname,
        'owner',       rol.rolname,
        'location',    spclocation,
        'acl',         CASE
                          WHEN spcacl IS NOT NULL
                          THEN jsonb_agg(
                              jsonb_build_object(
                                  'grantee', ae.grantee::text,
                                  'grantor', ae.grantor::text,
                                  'privileges', ae.privs,
                                  'grantable', ae.grantable
                              )
                          )
                          ELSE '[]'::jsonb
                      END
    )
)
FROM pg_tablespace t
JOIN pg_roles rol ON rol.oid = t.spcowner
CROSS JOIN LATERAL jsonb_to_recordset(t.spcacl::jsonb) AS ae(
    grantee regrole,
    grantor regrole,
    privs text[],
    grantable boolean[]
)
GROUP BY t.oid, t.spcname, rol.rolname, t.spclocation
ORDER BY t.spcname
