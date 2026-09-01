-- §3. Configuration — pg_settings
-- Collects all settings from pg_settings.
-- Credential denylist settings are masked at query time (S2).
-- Requires: pg_read_all_settings (S4)
SELECT jsonb_agg(
    jsonb_build_object(
        'name',              name,
        'setting',           CASE
            -- Credential denylist: mask credential tokens in the value
            WHEN name IN ('archive_command', 'archive_cleanup_command',
                          'restore_command', 'recovery_end_command',
                          'ssl_passphrase_command', 'primary_conninfo')
            THEN regexp_replace(
                setting,
                '(password|passfile|password=|passfile=)=[^ ,;]+',
                '\1=<redacted>',
                'gi'
            )
            ELSE setting
        END,
        'unit',              unit,
        'category',          category,
        'context',           context,
        'vartype',           vartype,
        'source',            source,
        'sourcefile',        sourcefile,
        'sourceline',        sourceline,
        'boot_val',          boot_val,
        'reset_val',         reset_val,
        'pending_restart',   pending_restart,
        'value_sanitised',   CASE
            WHEN name IN ('archive_command', 'archive_cleanup_command',
                          'restore_command', 'recovery_end_command',
                          'ssl_passphrase_command', 'primary_conninfo')
                 AND setting IS NOT NULL
                 AND (setting ~* '(password|passfile)=')
            THEN true
            ELSE false
        END
    )
)
FROM pg_settings
WHERE name NOT IN ('extra_float_digits', 'default_tablespace',
                   'temp_tablespaces', 'temp_file_limit')
