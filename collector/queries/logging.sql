-- §8. Logging — logging-related settings from pg_settings
-- Collects only logging configuration, never log file content (S0).
-- Requires: pg_read_all_settings (S4)
SELECT jsonb_build_object(
    'logging_collector',          (SELECT setting::bool FROM pg_settings WHERE name = 'logging_collector'),
    'log_destination',            (SELECT setting FROM pg_settings WHERE name = 'log_destination'),
    'log_directory',              (SELECT setting FROM pg_settings WHERE name = 'log_directory'),
    'log_filename',               (SELECT setting FROM pg_settings WHERE name = 'log_filename'),
    'log_file_mode',              (SELECT setting FROM pg_settings WHERE name = 'log_file_mode'),
    'log_rotation_age',           (SELECT setting FROM pg_settings WHERE name = 'log_rotation_age'),
    'log_rotation_size',          (SELECT setting FROM pg_settings WHERE name = 'log_rotation_size'),
    'log_truncate_on_rotation',   (SELECT setting::bool FROM pg_settings WHERE name = 'log_truncate_on_rotation'),
    'log_connections',            (SELECT setting::bool FROM pg_settings WHERE name = 'log_connections'),
    'log_disconnections',         (SELECT setting::bool FROM pg_settings WHERE name = 'log_disconnections'),
    'log_statement',              (SELECT setting FROM pg_settings WHERE name = 'log_statement'),
    'log_min_messages',           (SELECT setting FROM pg_settings WHERE name = 'log_min_messages'),
    'log_min_error_statement',    (SELECT setting FROM pg_settings WHERE name = 'log_min_error_statement'),
    'log_min_duration_statement', (SELECT setting FROM pg_settings WHERE name = 'log_min_duration_statement'),
    'log_line_prefix',            (SELECT setting FROM pg_settings WHERE name = 'log_line_prefix'),
    'log_hostname',               (SELECT setting::bool FROM pg_settings WHERE name = 'log_hostname'),
    'log_checkpoints',            (SELECT setting::bool FROM pg_settings WHERE name = 'log_checkpoints'),
    'log_lock_waits',             (SELECT setting::bool FROM pg_settings WHERE name = 'log_lock_waits'),
    'log_error_verbosity',        (SELECT setting FROM pg_settings WHERE name = 'log_error_verbosity'),
    'syslog_facility',            (SELECT setting FROM pg_settings WHERE name = 'syslog_facility'),
    'syslog_ident',               (SELECT setting FROM pg_settings WHERE name = 'syslog_ident'),
    'log_directory_mode',         NULL::text,   -- host probe only
    'log_directory_owner',        NULL::text,   -- host probe only
    'pgaudit_installed',          NULL::bool,   -- determined separately
    'pgaudit_settings',           '{}'::jsonb   -- determined separately
)
