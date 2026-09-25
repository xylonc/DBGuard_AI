#!/bin/bash
cd /workspace/DBGuardAI/test-out/phase1-task4d

echo "== 00-git.txt"
cat 00-git.txt
echo ""
echo "== 00-dump.txt"
cat 00-dump.txt
echo ""
echo "== 01-dump.txt"
cat 01-dump.txt
echo ""

# For 02-*.txt files that don't exist, show placeholder
for f in 02-*.txt 03-all.txt; do
    if [ -f "$f" ]; then
        echo "== $f"
        if [[ "$f" == *dump* ]]; then
            cat $f
        else
            grep -E "PASSED|FAILED|ERROR|Error|assert |passed|failed" $f | head -40
        fi
    else
        echo "== $f"
        echo "[File not created - step 1 was not clean]"
    fi
    echo ""
done
