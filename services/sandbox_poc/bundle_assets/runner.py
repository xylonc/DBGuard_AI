"""DBA-invoked runner for one reviewed PG17 configuration fix; never invoked by UI."""

import argparse
from datetime import datetime, timezone
import uuid
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sys
import time


def fingerprint(conn, names):
    with conn.cursor() as cur:
        cur.execute(
            """SELECT name,setting,source,sourcefile,context,pending_restart
                       FROM pg_settings WHERE name = ANY(%s)""",
            (names,),
        )
        settings = {
            r[0]: dict(
                zip(
                    ("setting", "source", "sourcefile", "context", "pending_restart"),
                    r[1:],
                )
            )
            for r in cur.fetchall()
        }
        cur.execute(
            """SELECT name,setting,sourcefile,applied,error FROM pg_file_settings
                       WHERE name = ANY(%s) ORDER BY name,sourcefile,setting""",
            (names,),
        )
        files = [
            dict(zip(("name", "setting", "sourcefile", "applied", "error"), r))
            for r in cur.fetchall()
        ]
    return {"settings": settings, "file_settings": files}


def execute(config, action, dsn, allow_demo=False):
    import psycopg2

    if config["demo_fixture_approval"] and not allow_demo:
        raise RuntimeError(
            "Demo fixture approval: use --allow-demo only with a disposable database"
        )
    with closing(psycopg2.connect(dsn, connect_timeout=10)) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout='15s'")
            cur.execute(
                "SELECT current_setting('server_version_num')::int / 10000, current_database()"
            )
            major, database = cur.fetchone()
            if major != 17 or database != config["database"]:
                raise RuntimeError(
                    "PostgreSQL version or database differs from the reviewed handoff"
                )
            cur.execute("SELECT pg_try_advisory_lock(741093, 320)")
            if cur.fetchone()[0] is not True:
                raise RuntimeError("Another DBGuard fix is running on this database")
        current = fingerprint(conn, config["names"])
        if config.get("system_identifier"):
            with conn.cursor() as cur:
                cur.execute("SELECT system_identifier::text FROM pg_control_system()")
                if cur.fetchone()[0] != str(config["system_identifier"]):
                    raise RuntimeError(
                        "Target cluster identity differs from the reviewed snapshot; no SQL executed"
                    )
        if action == "status":
            return {
                "matches_prior": current == config["prior"],
                "matches_applied": current == config["applied"],
            }
        if action in ("verify", "verify-rollback"):
            wanted = config["applied"] if action == "verify" else config["prior"]
            if current != wanted:
                raise RuntimeError(
                    "Verification failed: scoped values or configuration sources differ"
                )
            return {"action": action, "verified": True, "fix_id": config["fix_id"]}
        expected = config["prior"] if action == "apply" else config["applied"]
        wanted = config["applied"] if action == "apply" else config["prior"]
        if current != expected:
            raise RuntimeError(
                "Configuration drift detected; no SQL executed. Recollect and reassess."
            )
        # Each statement has its own autocommit command; ALTER SYSTEM cannot be in a transaction.
        with conn.cursor() as cur:
            for statement in config[action + "_statements"]:
                cur.execute(statement)
        if config.get("requires") == "restart":
            return {
                "action": action,
                "verified": False,
                "status": "RESTART_REQUIRED",
                "next": "DBA must restart PostgreSQL, then run verify or verify-rollback",
                "fix_id": config["fix_id"],
            }
        deadline = time.monotonic() + 10
        while True:
            # New sessions are required for superuser-backend settings such as log_connections.
            with closing(psycopg2.connect(dsn, connect_timeout=10)) as check:
                with check.cursor() as cur:
                    cur.execute("SET statement_timeout='10s'")
                    cur.execute("SELECT 1")
                    usable = cur.fetchone()[0] == 1
                observed = fingerprint(check, config["names"])
            if observed == wanted and usable:
                return {"action": action, "verified": True, "fix_id": config["fix_id"]}
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "SQL executed but expected state was not verified. Inspect the database before any retry."
                )
            time.sleep(0.25)


def verification_queries(config, dsn, action):
    import psycopg2

    queries = []
    checks = [
        ("Fresh connection", "SELECT 1 AS database_responds"),
        (
            "Read catalogue",
            "SELECT count(*) >= 0 AS catalogue_readable FROM pg_catalog.pg_class",
        ),
    ]
    with closing(psycopg2.connect(dsn, connect_timeout=10)) as conn:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout='10s'")
            cur.execute(
                "SELECT current_database(),inet_server_addr()::text,inet_server_port(),current_setting('server_version'),pg_postmaster_start_time()::text"
            )
            identity = dict(
                zip(
                    (
                        "database",
                        "server_address",
                        "server_port",
                        "server_version",
                        "postmaster_started",
                    ),
                    cur.fetchone(),
                )
            )
            from psycopg2 import sql

            setting_query = sql.SQL("SHOW {}").format(sql.Identifier(config["setting"]))
            cur.execute(setting_query)
            value = cur.fetchone()[0]
            wanted_setting = config[
                "prior" if action in ("rollback", "verify-rollback") else "applied"
            ]["settings"][config["setting"]]["setting"]
            queries.append(
                {
                    "title": "Effective setting in a fresh connection",
                    "query": setting_query.as_string(conn),
                    "output": value,
                    "passed": value == wanted_setting,
                }
            )
            for title, query in checks:
                cur.execute(query)
                rows = cur.fetchall()
                queries.append(
                    {
                        "title": title,
                        "query": query,
                        "output": rows,
                        "passed": bool(rows and rows[0][0] in (1, True)),
                    }
                )
            cur.execute("SELECT 1")
            ok = cur.fetchone()[0] == 1
        conn.rollback()
        queries.append(
            {
                "title": "Transaction rollback",
                "query": "BEGIN; SELECT 1; ROLLBACK;",
                "output": "SELECT 1 returned 1; transaction rolled back",
                "passed": ok,
            }
        )
        observed = fingerprint(conn, config["names"])
        wanted = (
            config["prior"]
            if action in ("rollback", "verify-rollback")
            else config["applied"]
        )
        queries.append(
            {
                "title": "Scoped settings and exact configuration source",
                "query": "SELECT name,setting,source,sourcefile,context,pending_restart FROM pg_settings WHERE name = ANY(%s); SELECT name,setting,sourcefile,applied,error FROM pg_file_settings WHERE name = ANY(%s) ORDER BY name,sourcefile,setting;",
                "parameters": config["names"],
                "output": observed,
                "passed": observed == wanted,
            }
        )
    return {
        "scope": "DBA TARGET · " + action.upper(),
        "run_id": config.get("run_id"),
        "control_id": config.get("control_id"),
        "target_id": config.get("target_id"),
        "database_identity": identity,
        "spec_set_hash": config.get("spec_set_hash"),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "queries": queries,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=["status", "apply", "rollback", "verify", "verify-rollback"]
    )
    parser.add_argument("fix_id")
    parser.add_argument("--ack-prerequisites", action="store_true")
    parser.add_argument("--screenshots", action="store_true")
    parser.add_argument("--evidence-dir", default="target-evidence")
    parser.add_argument("--allow-demo", action="store_true")
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    manifest = json.loads((base / "manifest.json").read_text())
    for name, expected in manifest["files"].items():
        if name not in {
            "fix.json",
            "evidence.json",
            "report.html",
            "harden.sh",
            "runner.py",
            "risk-review.json",
            "verify.sh",
            "visual_evidence.py",
            "sandbox-after.png",
            "sandbox-queries.json",
        }:
            raise RuntimeError("Unexpected bundle member")
        if hashlib.sha256((base / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"Bundle content changed: {name}")
    config = json.loads((base / "fix.json").read_text())
    if args.fix_id != config["fix_id"]:
        raise RuntimeError("Unknown fix ID in this bundle")
    if args.action == "apply" and not args.ack_prerequisites:
        raise RuntimeError(
            "Review risk-review.json and check prerequisites, then use --ack-prerequisites"
        )
    dsn = os.environ.get("DBGUARD_DSN")
    if not dsn:
        raise RuntimeError(
            "Set DBGUARD_DSN explicitly for the reviewed target; credentials are never bundled"
        )
    event = {
        "run_id": config.get("run_id"),
        "fix_id": args.fix_id,
        "action": args.action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    folder = Path(args.evidence_dir) / (
        "verification-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        + "-"
        + uuid.uuid4().hex[:8]
    )
    folder.mkdir(parents=True, mode=0o700)
    try:
        result = execute(config, args.action, dsn, args.allow_demo)
        event["result"] = result
        if result.get("verified"):
            evidence = verification_queries(config, dsn, args.action)
            (folder / "queries.json").write_text(json.dumps(evidence, indent=2))
            event["functional_checks_passed"] = all(
                q["passed"] for q in evidence["queries"]
            )
            if not event["functional_checks_passed"]:
                raise RuntimeError("Functional checks failed; stop before the next fix")
            if args.screenshots:
                from visual_evidence import capture, render_html
                import base64

                visual = capture(evidence)
                (folder / "database-results.png").write_bytes(
                    base64.b64decode(visual["png_base64"])
                )
                (folder / "database-results.html").write_text(render_html(evidence))
                event["screenshot_sha256"] = visual["sha256"]
        event["status"] = "COMPLETED"
        print(json.dumps({**result, "evidence_directory": str(folder)}))
    except Exception:
        event["status"] = "FAILED"
        event["next"] = (
            "Stop. Inspect target state; use status before any retry or rollback."
        )
        raise
    finally:
        (folder / "event.json").write_text(json.dumps(event, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Avoid echoing connection strings or server diagnostics that can include secrets.
        if isinstance(exc, RuntimeError):
            print(str(exc), file=sys.stderr)
        else:
            print(
                "Database operation failed. Inspect PostgreSQL and connection configuration before retrying.",
                file=sys.stderr,
            )
        sys.exit(1)
