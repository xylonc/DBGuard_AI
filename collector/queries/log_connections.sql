-- CIS 5.1: log_connections enabled
-- Collects the log_connections setting row from pg_settings.
-- Requires: pg_read_all_settings

SELECT jsonb_build_object(
    'name',             s.name,
    'setting',          s.setting,
    'source',           s.source,
    'sourcefile',       s.sourcefile,
    'sourceline',       s.sourceline,
    'context',          s.context,
    'pending_restart'   s.pending_restart
)
FROM pg_settings s
WHERE s.name = 'log_connections';
