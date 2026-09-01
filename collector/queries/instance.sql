-- §2. Instance Identity
-- Collects version, encoding, checksums, paths, recovery status.
-- Requires: pg_monitor, pg_read_all_settings (S4)
SELECT jsonb_build_object(
    'version_full',          version(),
    'version_num',           server_version_num(),
    'major_version',         server_version_num() / 10000,
    'distribution',          NULL::text,        -- determined by host probe
    'deployment_type',       'UNKNOWN'::text,   -- determined by platform probe
    'platform_probe_evidence', '[]'::jsonb,     -- determined by platform probe
    'os_distribution',       NULL::text,        -- host probe
    'os_version',            NULL::text,        -- host probe
    'kernel',                NULL::text,        -- host probe
    'architecture',          NULL::text,        -- host probe
    'server_encoding',       (SELECT setting FROM pg_settings WHERE name = 'server_encoding'),
    'lc_collate',            (SELECT setting FROM pg_settings WHERE name = 'lc_collate'),
    'lc_ctype',              (SELECT setting FROM pg_settings WHERE name = 'lc_ctype'),
    'icu_locale',            (SELECT setting FROM pg_settings WHERE name = 'icu_locale'),
    'default_collation',     (SELECT setting FROM pg_settings WHERE name = 'default_collation'),
    'data_checksums',        (SELECT setting::bool FROM pg_settings WHERE name = 'data_checksums'),
    'block_size',            (SELECT setting::int FROM pg_settings WHERE name = 'block_size'),
    'wal_segment_size',      (SELECT setting::int FROM pg_settings WHERE name = 'wal_segment_size'),
    'paths', (
        jsonb_build_object(
            'data_directory',            (SELECT setting FROM pg_settings WHERE name = 'data_directory'),
            'config_file',               (SELECT setting FROM pg_settings WHERE name = 'config_file'),
            'hba_file',                  (SELECT setting FROM pg_settings WHERE name = 'hba_file'),
            'ident_file',                (SELECT setting FROM pg_settings WHERE name = 'ident_file'),
            'external_pid_file',         (SELECT setting FROM pg_settings WHERE name = 'external_pid_file'),
            'unix_socket_directories',   (SELECT setting FROM pg_settings WHERE name = 'unix_socket_directories')
        )
    ),
    'is_in_recovery',        pg_is_in_recovery()
)
