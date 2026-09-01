-- §7. Replication — WAL, archive, and connection info
-- archive_command and primary_conninfo are masked at query time (S2).
-- Only boolean presence is emitted; full values are never collected (S0).
-- Requires: pg_read_all_settings (S4)
SELECT jsonb_build_object(
    'wal_level',                  (SELECT setting FROM pg_settings WHERE name = 'wal_level'),
    'archive_mode',               (SELECT setting FROM pg_settings WHERE name = 'archive_mode'),
    'archive_command_sanitised',  (
        SELECT CASE
            WHEN setting IS NOT NULL
                 AND setting ~* '(password|passfile)=|password=|passfile='
            THEN regexp_replace(setting, '(password|passfile)=([^ ,;]+)', '\1=<redacted>', 'gi')
            WHEN setting IS NOT NULL THEN setting
            ELSE NULL
        END
        FROM pg_settings WHERE name = 'archive_command'
    ),
    'archive_command_set',        (SELECT setting IS NOT NULL FROM pg_settings WHERE name = 'archive_command'),
    'max_wal_senders',            (SELECT setting::int FROM pg_settings WHERE name = 'max_wal_senders'),
    'max_replication_slots',      (SELECT setting::int FROM pg_settings WHERE name = 'max_replication_slots'),
    'synchronous_standby_names',  (SELECT setting FROM pg_settings WHERE name = 'synchronous_standby_names'),
    'hot_standby',                (SELECT setting::bool FROM pg_settings WHERE name = 'hot_standby'),
    'primary_conninfo_parsed', (
        SELECT jsonb_object_agg(
            CASE WHEN key = 'password' THEN NULL ELSE key END, value
        )
        FROM (
            SELECT regexp_split_to_table(
                (SELECT setting FROM pg_settings WHERE name = 'primary_conninfo'),
                ' '
            ) AS pair
        ) pairs
        CROSS JOIN LATERAL regexp_split_to_array(pair, '=') AS kv(key, value)
        WHERE key != 'password'
          AND pair != ''
    ),
    'primary_conninfo_set',       (SELECT setting IS NOT NULL FROM pg_settings WHERE name = 'primary_conninfo'),
    'restore_command_sanitised', (
        SELECT CASE
            WHEN setting IS NOT NULL
                 AND setting ~* '(password|passfile)=|password=|passfile='
            THEN regexp_replace(setting, '(password|passfile)=([^ ,;]+)', '\1=<redacted>', 'gi')
            WHEN setting IS NOT NULL THEN setting
            ELSE NULL
        END
        FROM pg_settings WHERE name = 'restore_command'
    ),
    'restore_command_set',        (SELECT setting IS NOT NULL FROM pg_settings WHERE name = 'restore_command'),
    'cluster_manager',            NULL::text   -- determined by host probe
)
