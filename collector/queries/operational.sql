-- §9. Operational baseline — aggregated connection profiles and uptime
-- Never selects query text (S0). Aggregates by application_name, role, database.
-- client_addr_class is a derived bucket: loopback | private | public | unix_socket
-- Requires: pg_monitor (S4)
SELECT jsonb_build_object(
    'connection_profiles', (
        SELECT jsonb_agg(
            jsonb_build_object(
                'application_name', appname,
                'role',             rolname,
                'database',         datname,
                'client_addr_class', CASE
                    WHEN client_addr IS NULL THEN 'unix_socket'
                    WHEN client_addr = '127.0.0.1' OR client_addr = '::1' THEN 'loopback'
                    WHEN client_addr ~ '^10\.' OR client_addr ~ '^172\.(1[6-9]|2[0-9]|3[01])\.' OR client_addr ~ '^192\.168\.' THEN 'private'
                    WHEN client_addr !~ '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' THEN 'public'
                    ELSE 'unknown'
                END,
                'ssl_in_use',        has_ssl,
                'connection_count',  cnt
            )
        )
        FROM (
            SELECT
                COALESCE(application_name, 'none') AS appname,
                COALESCE(rolname, 'none') AS rolname,
                COALESCE(datname, 'none') AS datname,
                client_addr,
                has_ssl,
                COUNT(*) AS cnt
            FROM pg_stat_activity
            WHERE state IS NOT NULL  -- exclude backend startup
            GROUP BY appname, rolname, datname, client_addr, has_ssl
        ) profiles
        ORDER BY profiles.appname
    ),
    'max_connections', (SELECT setting::int FROM pg_settings WHERE name = 'max_connections'),
    'peak_connections_observed', (
        SELECT MAX(numbackends) FROM pg_stat_database
    ),
    'uptime_seconds', (
        SELECT EXTRACT(EPOCH FROM (NOW() - pg_postmaster_start_time())).::int
    )
)
