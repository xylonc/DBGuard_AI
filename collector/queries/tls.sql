-- §4. TLS — SSL settings from pg_settings
-- Collects SSL configuration. Certificate metadata is collected via
-- openssl in bash (not SQL). Private keys are never read (S0).
-- Requires: pg_read_all_settings (S4)
SELECT jsonb_build_object(
    'ssl_enabled',        (SELECT setting::bool FROM pg_settings WHERE name = 'ssl'),
    'ssl_ciphers',        (SELECT setting FROM pg_settings WHERE name = 'ssl_ciphers'),
    'ssl_min_protocol_version', (SELECT setting FROM pg_settings WHERE name = 'ssl_min_protocol_version'),
    'ssl_max_protocol_version', (SELECT setting FROM pg_settings WHERE name = 'ssl_max_protocol_version'),
    'ssl_prefer_server_ciphers', (SELECT setting::bool FROM pg_settings WHERE name = 'ssl_prefer_server_ciphers'),
    'ssl_ecdh_curve',     (SELECT setting FROM pg_settings WHERE name = 'ssl_ecdh_curve'),
    'ssl_dh_params_file', (SELECT setting FROM pg_settings WHERE name = 'ssl_dh_params_file'),
    'ssl_passphrase_command_set', (
        SELECT setting IS NOT NULL
        FROM pg_settings
        WHERE name = 'ssl_passphrase_command'
    ),
    'server_cert_path',   (SELECT setting FROM pg_settings WHERE name = 'ssl_cert_file'),
    'ca_cert_path',       (SELECT setting FROM pg_settings WHERE name = 'ssl_ca_file'),
    'crl_path',           (SELECT setting FROM pg_settings WHERE name = 'ssl_crl_file')
)
