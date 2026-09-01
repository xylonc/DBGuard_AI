-- §6. Databases — pg_database
-- Lists all databases with connection settings.
-- Requires: pg_monitor (S4)
SELECT jsonb_agg(
    jsonb_build_object(
        'name',            d.datname,
        'owner',           rol.rolname,
        'encoding',        (SELECT setting FROM pg_settings WHERE name = 'server_encoding' LIMIT 1),
        'collate',         d.datcollate,
        'ctype',           d.datctype,
        'is_template',     d.datistemplate,
        'allow_connections', d.datallowconn,
        'connection_limit', d.datconnlimit,
        'tablespace',      ts.spcname,
        'collected',       true
    )
)
FROM pg_database d
LEFT JOIN pg_roles rol ON rol.oid = d.datdba
LEFT JOIN pg_tablespace ts ON ts.oid = d.dattablespace
WHERE NOT d.datistemplate
ORDER BY d.datname
