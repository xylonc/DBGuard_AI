-- §4. Ident mappings — pg_ident_file_mappings
-- PG 16+ only. Below that, the collector falls back to parsing pg_ident.conf via bash.
-- Requires: superuser or pg_read_all_files (S4)
SELECT CASE
    WHEN server_version_num() >= 160000 THEN (
        SELECT jsonb_agg(
            jsonb_build_object(
                'line_number', line_number,
                'map_name',    map_name,
                'sys_name',    sys_name,
                'pg_username', pg_username,
                'error',       error
            )
        )
        FROM pg_ident_file_mappings
    )
    ELSE NULL::jsonb
END
