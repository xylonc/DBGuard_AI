"""DBA-invoked runner for one reviewed PG17 configuration or object fix; never invoked by UI."""

import argparse
from datetime import datetime, timezone
import uuid
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
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


ROLE_QUERY = """SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin,
       rolreplication, rolbypassrls, rolconnlimit,
       CASE WHEN rolvaliduntil IS NULL THEN NULL
            WHEN NOT isfinite(rolvaliduntil) THEN rolvaliduntil::text
            ELSE to_char(rolvaliduntil AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US') END
  FROM pg_catalog.pg_roles WHERE rolname = %s"""
TABLE_QUERY = """SELECT c.relkind::text, pg_catalog.pg_get_userbyid(c.relowner), c.relacl::text[],
       c.relrowsecurity, c.relforcerowsecurity
  FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = %s AND c.relname = %s"""
FUNCTION_QUERY = """SELECT p.prokind::text, pg_catalog.pg_get_userbyid(p.proowner), p.prosecdef,
       coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))::text[],
       (SELECT substring(c from position('=' in c) + 1) FROM unnest(p.proconfig) c
         WHERE split_part(c, '=', 1) = 'search_path' LIMIT 1),
       coalesce((SELECT array_agg(split_part(c, '=', 1) ORDER BY ord)
                   FROM unnest(p.proconfig) WITH ORDINALITY AS u(c, ord)), '{}')
  FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = %s AND p.proname = %s
   AND pg_catalog.pg_get_function_identity_arguments(p.oid) = %s"""
# Roles a fix must never change on the target, re-checked here because the snapshot
# may be stale or not the DBA's own: the bootstrap superuser, built-in pg_* roles and
# the account this runner is connected as (removing its powers or login would lock the
# DBA out mid-fix and break the rollback).
ROLE_SAFETY_QUERY = """SELECT oid = 10, pg_catalog.left(rolname, 3) = 'pg_',
       rolname IN (session_user, current_user)
  FROM pg_catalog.pg_roles WHERE rolname = %s"""
ROLE_FIELDS = ("rolsuper", "rolinherit", "rolcreaterole", "rolcreatedb", "rolcanlogin",
               "rolreplication", "rolbypassrls", "rolconnlimit", "rolvaliduntil")


def object_fingerprint(cur, config):
    """The one target object, read-only with bound parameters, in the bundle's shape.

    Mirrors review_bundle.object_fingerprint (built from the collected evidence).
    ACLs are sets (sorted); a missing or ambiguous object is refused.
    """
    target, kind = config["target"], config["prior"]["kind"]
    if kind == "role":
        cur.execute(ROLE_QUERY, (target["role"],))
        rows = cur.fetchall()
        if len(rows) != 1:
            raise RuntimeError("Target role not found; no SQL executed")
        return {"kind": "role", "rolname": target["role"], **dict(zip(ROLE_FIELDS, rows[0]))}
    if kind == "table":
        cur.execute(TABLE_QUERY, (target["schema"], target["table"]))
        rows = cur.fetchall()
        if len(rows) != 1:
            raise RuntimeError("Target table not found; no SQL executed")
        relkind, owner, acl, rls, forced = rows[0]
        return {"kind": "table", "schema": target["schema"], "name": target["table"], "relkind": relkind,
                "owner": owner, "acl": None if acl is None else sorted(acl), "rls": rls, "rls_forced": forced}
    if kind == "function":
        cur.execute(FUNCTION_QUERY, (target["schema"], target["name"], target["identity_args"]))
        rows = cur.fetchall()
        if len(rows) != 1:
            raise RuntimeError("Target function not found; no SQL executed")
        prokind, owner, secdef, acl, search_path, config_names = rows[0]
        return {"kind": "function", "schema": target["schema"], "name": target["name"],
                "identity_args": target["identity_args"], "prokind": prokind, "owner": owner,
                "prosecdef": secdef, "acl": sorted(acl), "search_path": search_path,
                "config_names": list(config_names)}
    raise RuntimeError("Unsupported object kind in this bundle")


# W2B gate 1, ruling 3: before a fix ADDS a library to shared_preload_libraries, prove the
# library loads on this target. A missing preloaded library stops PostgreSQL starting, and a
# control file is not proof that the shared object exists. Each LOAD statement is a fixed
# literal chosen by key from this reviewed allowlist; a library name from fix.json or any
# collected data is never interpolated into SQL. The accepted error is pgaudit's own refusal
# to initialise outside shared_preload_libraries, which it raises only after the server found
# and loaded its shared object. Anything else ("could not access file", permission) refuses.
PRELOAD_LOAD_TESTS = {
    "pgaudit": ("LOAD 'pgaudit'", "pgaudit must be loaded via shared_preload_libraries"),
    "passwordcheck": ("LOAD 'passwordcheck'", None),
}
PRELOAD_REFUSAL = ("Library {} cannot be loaded on the target: install the package first; "
                   "no SQL executed")


# The one accepted shape of a statement that changes shared_preload_libraries: the reviewed
# set_config_list rendering, one quoted literal per item, each a plain library name or one
# of the exact CIS forms (W2B rulings round 3). Any other shape is refused.
_PRELOAD_ITEM = r"(?:[a-z_][a-z0-9_]{0,62}|\$libdir/pgaudit|pgaudit\.so|\$libdir/pgaudit\.so|\$libdir/passwordcheck)"
PRELOAD_STATEMENT = re.compile(r"""ALTER SYSTEM SET "shared_preload_libraries" = ('""" + _PRELOAD_ITEM
                               + r"""'(?:, '""" + _PRELOAD_ITEM + r"""')*);?""")


# Every statement a setting bundle may run, as fix_unit_render renders it: ALTER SYSTEM SET
# of one lower-case setting to one literal, ALTER SYSTEM RESET, pg_reload_conf(), or the
# preload list (PRELOAD_STATEMENT). Anything else is refused before any SQL (W2B review N1).
SETTING_STATEMENTS = (
    re.compile(r"""ALTER SYSTEM SET "[a-z_][a-z0-9_.]*" = '(?:[^'\n\r]|'')*';?"""),
    re.compile(r"""ALTER SYSTEM RESET "[a-z_][a-z0-9_.]*";?"""),
    re.compile(r"SELECT pg_reload_conf\(\);?"),
)


def check_setting_statements(config):
    """Refuse a setting bundle whose apply or rollback statements are not the reviewed shapes.

    shared_preload_libraries (matched case-insensitively, as PostgreSQL matches setting
    names) is accepted only in the list shape, never as a single-literal SET."""
    for key in ("apply_statements", "rollback_statements"):
        for statement in config.get(key) or []:
            text = statement.strip()
            if "shared_preload_libraries" in text.lower():
                if (PRELOAD_STATEMENT.fullmatch(text) is None
                        and not re.fullmatch(r"""ALTER SYSTEM RESET "shared_preload_libraries";?""", text)):
                    raise RuntimeError("Unsupported shared_preload_libraries statement; no SQL executed")
            elif not any(shape.fullmatch(text) for shape in SETTING_STATEMENTS):
                raise RuntimeError("Unsupported statement in this bundle; no SQL executed")


def _current_preload(value):
    """Items of the target's current list (quotes removed), for "already loaded" only."""
    return {item.strip().strip('"') for item in value.split(",") if item.strip()}


def preload_additions(conn, config):
    """Libraries an apply would ADD to shared_preload_libraries on this target.

    Read from the bundle's own apply statements and the target's current list, not only
    from fix.json's preload_added, so an edited fix.json cannot skip the guard. A statement
    that changes shared_preload_libraries in any other form is refused, and so is a repeated
    item. The current list only decides what is already loaded (the drift check has already
    compared it with the reviewed prior state).
    """
    check_setting_statements({"apply_statements": config.get("apply_statements") or []})
    wanted = []
    for statement in config.get("apply_statements") or []:
        if "shared_preload_libraries" not in statement.lower():
            continue
        match = PRELOAD_STATEMENT.fullmatch(statement.strip())
        if match is None:
            raise RuntimeError("Unsupported shared_preload_libraries statement; no SQL executed")
        items = [item.strip()[1:-1] for item in match.group(1).split(",")]
        if len(set(items)) != len(items):
            raise RuntimeError("Unsupported shared_preload_libraries statement; no SQL executed")
        wanted += items
    if not wanted and not config.get("preload_added"):
        return []
    with conn.cursor() as cur:
        cur.execute("SELECT pg_catalog.current_setting('shared_preload_libraries')")
        current = _current_preload(cur.fetchone()[0])
    return sorted({lib for lib in wanted + list(config.get("preload_added") or []) if lib not in current})


def preload_guard(dsn, libraries, connect=None):
    """Refuse unless every library being added loads in a throwaway session (rolled back, closed)."""
    import psycopg2

    connect = connect or psycopg2.connect
    for library in libraries:
        test = PRELOAD_LOAD_TESTS.get(library)
        if test is None:
            raise RuntimeError("A library outside the reviewed preload allowlist; no SQL executed")
        statement, accepted_error = test
        loaded = False
        with closing(connect(dsn, connect_timeout=10)) as conn:
            conn.autocommit = False
            try:
                with conn.cursor() as cur:
                    cur.execute("SET LOCAL statement_timeout='10s'")
                    try:
                        cur.execute(statement)
                        loaded = True
                    except psycopg2.Error as exc:
                        diag = getattr(exc, "diag", None)
                        message = getattr(diag, "message_primary", None)
                        loaded = accepted_error is not None and message == accepted_error
            finally:
                conn.rollback()
        if not loaded:
            raise RuntimeError(PRELOAD_REFUSAL.format(library))


def _guard(cur, config):
    """Same PG major, database, DBGuard advisory lock and cluster identity."""
    cur.execute("SET statement_timeout='15s'")
    # Built-ins only: a same-named function in a user schema must never run here.
    cur.execute("SET search_path = pg_catalog, pg_temp")
    cur.execute("SELECT current_setting('server_version_num')::int / 10000, current_database()")
    major, database = cur.fetchone()
    if major != 17 or database != config["database"]:
        raise RuntimeError("PostgreSQL version or database differs from the reviewed handoff")
    cur.execute("SELECT pg_try_advisory_lock(741093, 320)")
    if cur.fetchone()[0] is not True:
        raise RuntimeError("Another DBGuard fix is running on this database")
    if config.get("system_identifier"):
        cur.execute("SELECT system_identifier::text FROM pg_control_system()")
        if cur.fetchone()[0] != str(config["system_identifier"]):
            raise RuntimeError("Target cluster identity differs from the reviewed snapshot; no SQL executed")


def object_safety(cur, config):
    """Refuse a role fix on a protected role before any SQL runs."""
    if config["prior"]["kind"] != "role":
        return
    cur.execute(ROLE_SAFETY_QUERY, (config["target"]["role"],))
    rows = cur.fetchall()
    if len(rows) != 1:
        raise RuntimeError("Target role not found; no SQL executed")
    bootstrap, builtin, connected = rows[0]
    if bootstrap or builtin:
        raise RuntimeError("The bootstrap superuser and built-in pg_ roles are never changed; no SQL executed")
    if connected:
        raise RuntimeError("This fix targets the account the runner is connected as; "
                           "connect as a different administrator. No SQL executed")


def execute_object(config, action, dsn, allow_demo=False):
    """Apply or roll back one object fix inside ONE transaction.

    Catalog rows cannot be locked with SELECT ... FOR UPDATE, so the object's state is
    checked before the statements and re-checked after them inside the same
    transaction; anything but the exact tested state is rolled back, never committed.
    """
    import psycopg2

    if config["demo_fixture_approval"] and not allow_demo:
        raise RuntimeError("Demo fixture approval: use --allow-demo only with a disposable database")
    with closing(psycopg2.connect(dsn, connect_timeout=10)) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            _guard(cur, config)
            current = object_fingerprint(cur, config)
            if action in ("apply", "rollback"):
                object_safety(cur, config)
        if action == "status":
            return {"matches_prior": current == config["prior"], "matches_applied": current == config["applied"]}
        if action in ("verify", "verify-rollback"):
            if current != (config["applied"] if action == "verify" else config["prior"]):
                raise RuntimeError("Verification failed: the object differs from the tested state")
            return {"action": action, "verified": True, "fix_id": config["fix_id"]}
        expected = config["prior"] if action == "apply" else config["applied"]
        wanted = config["applied"] if action == "apply" else config["prior"]
        if current != expected:
            raise RuntimeError("Object drift detected; no SQL executed. Recollect and reassess.")
        conn.autocommit = False
        try:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL statement_timeout='15s'")
                cur.execute("SET LOCAL lock_timeout='5s'")
                object_safety(cur, config)
                if object_fingerprint(cur, config) != expected:
                    raise RuntimeError("Object drift detected inside the transaction; rolled back")
                for statement in config[action + "_statements"]:
                    cur.execute(statement)
                if object_fingerprint(cur, config) != wanted:
                    raise RuntimeError("The statements did not produce the tested state; rolled back, nothing changed")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.autocommit = True
    with closing(psycopg2.connect(dsn, connect_timeout=10)) as check:
        with check.cursor() as cur:
            cur.execute("SET statement_timeout='10s'")
            cur.execute("SET search_path = pg_catalog, pg_temp")
            observed = object_fingerprint(cur, config)
    if observed != wanted:
        raise RuntimeError("Committed, but a fresh connection does not show the tested state. Inspect the database.")
    return {"action": action, "verified": True, "fix_id": config["fix_id"]}


def execute(config, action, dsn, allow_demo=False):
    import psycopg2

    if config.get("kind") == "object":
        return execute_object(config, action, dsn, allow_demo)
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
        if action in ("apply", "rollback"):
            check_setting_statements(config)
        if action == "apply":
            added = preload_additions(conn, config)
            if added:
                preload_guard(dsn, added)
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
                    cur.execute("SET search_path = pg_catalog, pg_temp")
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


def object_verification_queries(config, dsn, action):
    import psycopg2

    wanted = config["prior" if action in ("rollback", "verify-rollback") else "applied"]
    queries = []
    with closing(psycopg2.connect(dsn, connect_timeout=10)) as conn:
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout='10s'")
            cur.execute("SET search_path = pg_catalog, pg_temp")
            cur.execute("SELECT current_database(),current_setting('server_version'),pg_postmaster_start_time()::text")
            identity = dict(zip(("database", "server_version", "postmaster_started"), cur.fetchone()))
            for title, query in (("Fresh connection", "SELECT 1 AS database_responds"),
                                 ("Read catalogue", "SELECT count(*) >= 0 AS catalogue_readable FROM pg_catalog.pg_class")):
                cur.execute(query)
                rows = cur.fetchall()
                queries.append({"title": title, "query": query, "output": rows,
                                "passed": bool(rows and rows[0][0] in (1, True))})
            observed = object_fingerprint(cur, config)
        conn.rollback()
        queries.append({"title": "Target object in a fresh connection", "query": "read-only catalog query (runner.object_fingerprint)",
                        "parameters": config["target"], "output": observed, "passed": observed == wanted})
    return {"scope": "DBA TARGET · " + action.upper(), "run_id": config.get("run_id"),
            "control_id": config.get("control_id"), "target_id": config.get("target_id"),
            "database_identity": identity, "spec_set_hash": config.get("spec_set_hash"),
            "captured_at": datetime.now(timezone.utc).isoformat(), "queries": queries}


def verification_queries(config, dsn, action):
    import psycopg2

    if config.get("kind") == "object":
        return object_verification_queries(config, dsn, action)

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
            cur.execute("SET search_path = pg_catalog, pg_temp")
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

            wanted_state = config["prior" if action in ("rollback", "verify-rollback") else "applied"]
            if config.get("kind") == "catalog_setting":
                # Several settings; one may be undefined (pgaudit.log without pgaudit loaded),
                # so current_setting(name, true) gives NULL instead of an error.
                for name in config["settings"]:
                    cur.execute("SELECT pg_catalog.current_setting(%s, true)", (name,))
                    value = cur.fetchone()[0]
                    wanted_setting = wanted_state["settings"].get(name, {}).get("setting")
                    queries.append({"title": "Effective setting in a fresh connection",
                                    "query": "SELECT pg_catalog.current_setting(%s, true)",
                                    "parameters": [name], "output": value,
                                    "passed": value == wanted_setting})
            else:
                setting_query = sql.SQL("SHOW {}").format(sql.Identifier(config["setting"]))
                cur.execute(setting_query)
                value = cur.fetchone()[0]
                wanted_setting = wanted_state["settings"][config["setting"]]["setting"]
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
            # Sandbox stage screenshots (Task 2); never produced or replaced by verify.
            "screenshots/before.png",
            "screenshots/after.png",
            "screenshots/rollback.png",
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
