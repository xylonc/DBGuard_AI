-- §4. Authentication — pg_hba_file_rules
-- Collects HBA rules with line order preserved.
-- Credential-bearing options (ldapbindpasswd, radiussecret, radiussecrets)
-- are masked at query time (S2).
-- Requires: superuser or pg_read_all_files (pg_hba_file_rules is superuser-only in PG 10+) (S4)

-- PG 10+: pg_hba_file_rules is available
SELECT jsonb_agg(
    jsonb_build_object(
        'line_number', line_number,
        'type',        type,
        'database',    CASE
                          WHEN database @> '{all}'::name[] THEN '{all}'
                          ELSE database
                      END,
        'user_name',   CASE
                          WHEN user_name @> '{all}'::name[] THEN '{all}'
                          ELSE user_name
                      END,
        'address',     address,
        'netmask',     netmask,
        'auth_method', auth_method,
        'options',     CASE
                          WHEN auth_method = 'ldap'
                          THEN jsonb_agg(
                              jsonb_build_object(
                                  'key', key,
                                  'value', CASE
                                      WHEN key = 'ldapbindpasswd'
                                      THEN '<redacted>'
                                      ELSE key
                                  END
                              )
                          ) OVER (PARTITION BY line_number)
                          WHEN auth_method = 'radius'
                          THEN jsonb_agg(
                              jsonb_build_object(
                                  'key', key,
                                  'value', CASE
                                      WHEN key IN ('radiussecret', 'radiussecrets')
                                      THEN '<redacted>'
                                      ELSE key
                                  END
                              )
                          ) OVER (PARTITION BY line_number)
                          ELSE '[]'::jsonb
                      END,
        'error',       error
    )
)
FROM pg_hba_file_rules
