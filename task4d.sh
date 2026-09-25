#!/bin/bash
set -e
cd /workspace/DBGuardAI
mkdir -p test-out/phase1-task4d

# STEP 0
git status -sb > test-out/phase1-task4d/00-git.txt
git diff test-out/phase1-task4b/03-run.txt | head -30 >> test-out/phase1-task4d/00-git.txt

# STEP 0 - DUMP before anything
cat > /tmp/dump.sql << 'EOF'
SELECT 'S', name, setting, source, coalesce(sourcefile,'') FROM pg_settings WHERE name IN ('debug_print_parse','log_connections','log_disconnections','log_statement','ssl_min_protocol_version')
UNION ALL
SELECT 'F', name, setting, applied::text, sourcefile FROM pg_file_settings WHERE sourcefile LIKE '%auto.conf'
ORDER BY 1,2;
EOF

bash -lc 'set -a && source .env && set +a && psql "$PG_TARGET_URL" -At -f /tmp/dump.sql' > test-out/phase1-task4d/00-dump.txt

# Restore 03-run.txt if it was modified
git checkout -- test-out/phase1-task4b/03-run.txt 2>/dev/null || true

# STEP 1 - Attempt to clean, but check if clean is possible
# We have 5 specific settings that need to be 'default' in source
# and no F rows for these 5 settings

# Execute RESET commands
bash -lc 'set -a && source .env && set +a && psql "$PG_TARGET_URL" -c "ALTER SYSTEM RESET log_disconnections"'
bash -lc 'set -a && source .env && set +a && psql "$PG_TARGET_URL" -c "ALTER SYSTEM RESET log_statement"'
bash -lc 'set -a && source .env && set +a && psql "$PG_TARGET_URL" -c "SELECT pg_reload_conf()"'

# Get DUMP after reset
bash -lc 'set -a && source .env && set +a && psql "$PG_TARGET_URL" -At -f /tmp/dump.sql' > test-out/phase1-task4d/01-dump.txt

# Check if clean
# For our 5 settings, we need:
# - S row source = 'default' 
# - No F row for the setting

echo "=== Checking clean state ==="
cat test-out/phase1-task4d/01-dump.txt
echo ""

# Check each of our 5 settings
for setting in debug_print_parse log_connections log_disconnections log_statement ssl_min_protocol_version; do
    S_LINE=$(grep "^S|$setting|" test-out/phase1-task4d/01-dump.txt)
    F_LINE=$(grep "^F|$setting|" test-out/phase1-task4d/01-dump.txt)
    
    if [ -n "$F_LINE" ]; then
        echo "FAIL: F row exists for $setting"
    fi
    
    SOURCE=$(echo "$S_LINE" | cut -d'|' -f4)
    if [ "$SOURCE" != "default" ]; then
        echo "FAIL: S row source is '$SOURCE' for $setting (expected 'default')"
    fi
done

echo ""
echo "=== REPORT ==="
echo "Step 1 dump shows state after ALTER SYSTEM RESET commands."
echo "The dump will be stored for diagnosis."
