"""Fresh-session database verification and visual capture in owned sandboxes."""

from datetime import datetime, timezone
import os
import json
from .planning import CHECKS
from .bundle_assets.visual_evidence import capture


def verify_runtime(runtime, control, name, value, phase):
    queries = []
    for key, check in CHECKS.items():
        output = runtime.sql(check["query"] + ";")
        passed = output.strip() in ("1", "t", "true")
        queries.append({"id": key, **check, "output": output, "passed": passed})
    output = runtime.sql("SHOW " + name + ";")
    queries.append(
        {
            "id": "setting",
            "title": "Effective setting in a fresh connection",
            "query": "SHOW " + name + ";",
            "output": output,
            "passed": output == value,
        }
    )
    identity = runtime.sql(
        "SELECT json_build_object('database',current_database(),'server_version',current_setting('server_version'),'postmaster_started',pg_postmaster_start_time());"
    )
    evidence = {
        "scope": "DISPOSABLE SANDBOX · " + phase,
        "run_id": runtime.run_id,
        "target_id": runtime.name,
        "database_identity": json.loads(identity),
        "control_id": control,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "queries": queries,
    }
    result = {"passed": all(q["passed"] for q in queries), "query_evidence": evidence}
    if os.environ.get("DBGUARD_SCREENSHOTS") == "true":
        try:
            result["screenshot"] = capture(evidence)
        except Exception:
            result["screenshot"] = {
                "status": "UNAVAILABLE",
                "reason": "Browser capture failed; query evidence retained. Re-run verification after fixing browser setup.",
            }
    else:
        result["screenshot"] = {"status": "DISABLED"}
    return result
