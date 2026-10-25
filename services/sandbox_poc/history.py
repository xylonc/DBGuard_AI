"""Local durable run/evidence history. Operator statements never imply verification."""

from contextlib import contextmanager, closing
import json
import os
from pathlib import Path
import sqlite3
from datetime import datetime, timezone
from .shared import ContractError


def _connect():
    root = Path(os.environ.get("DBGUARD_HISTORY_DIR", ".demo/history"))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlite3.connect(root / "history.sqlite", timeout=15)
    (root / "history.sqlite").chmod(0o600)
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE IF NOT EXISTS runs (run_id TEXT PRIMARY KEY, created_at TEXT, result TEXT, handoff TEXT, bundle BLOB)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, run_id TEXT, timestamp TEXT, kind TEXT, data TEXT)"
    )
    return conn


@contextmanager
def db():
    with closing(_connect()) as conn:
        with conn:
            yield conn


def record(handoff, result, bundle=None):
    with db() as c:
        c.execute(
            "INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?)",
            (
                result["run_id"],
                datetime.now(timezone.utc).isoformat(),
                json.dumps(result),
                handoff.model_dump_json(),
                bundle,
            ),
        )


def get(run_id):
    with db() as c:
        row = c.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if not row:
            raise ContractError("Recorded run not found")
        result = {k: json.loads(row[k]) for k in ("result", "handoff")}
        result["events"] = [
            {**dict(e), "data": json.loads(e["data"])}
            for e in c.execute(
                "SELECT * FROM events WHERE run_id=? ORDER BY id", (run_id,)
            )
        ]
        return result


def list_runs():
    with db() as c:
        return [
            {
                "run_id": r["run_id"],
                "created_at": r["created_at"],
                "status": json.loads(r["result"])["status"],
            }
            for r in c.execute(
                "SELECT run_id,created_at,result FROM runs ORDER BY created_at DESC LIMIT 100"
            )
        ]


def bundle(run_id):
    with db() as c:
        row = c.execute("SELECT bundle FROM runs WHERE run_id=?", (run_id,)).fetchone()
        return row[0] if row else None


def event(run_id, kind, data):
    get(run_id)
    with db() as c:
        c.execute(
            "INSERT INTO events(run_id,timestamp,kind,data) VALUES (?,?,?,?)",
            (run_id, datetime.now(timezone.utc).isoformat(), kind, json.dumps(data)),
        )


def compare(run_id, fresh, engine):
    record = get(run_id)
    old = record["handoff"]["snapshot"]
    result = record["result"]
    oldenv, newenv = old["envelope"], fresh["envelope"]
    for key in ("target_id", "database"):
        if oldenv.get(key) != newenv.get(key):
            raise ContractError("Target identity differs: " + key)
    oldid = old["baseline"].get("identity", {})
    newid = fresh["baseline"].get("identity", {})
    if not oldid.get("system_identifier") or oldid["system_identifier"] != newid.get(
        "system_identifier"
    ):
        raise ContractError("Matching PostgreSQL cluster identity evidence is required")
    if oldid.get("server_version_num") != newid.get("server_version_num"):
        raise ContractError("PostgreSQL version changed")
    if engine.spec_set_hash != result["spec_set_hash"]:
        raise ContractError("Spec set changed; assessment is not comparable")
    parse = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
    try:
        if parse(newenv["collected_at"]) <= parse(oldenv["collected_at"]):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise ContractError(
            "A strictly newer collection timestamp is required"
        ) from None
    before = engine.assess(old)
    after = engine.assess(fresh)
    controls = [
        f["spec_id"]
        for f in result.get("fix_units", [result.get("fix_unit", {})])
        if f.get("spec_id")
    ]
    regressions = [
        k
        for k, v in before["findings"].items()
        if v["status"] == "PASS"
        and after["findings"].get(k, {}).get("status") != "PASS"
    ]
    gaps = [k for k, v in after["findings"].items() if v["status"] == "GAPPED"]
    verified = (
        bool(controls)
        and all(
            after["findings"].get(sid, {}).get("status") == "PASS" for sid in controls
        )
        and not regressions
        and not gaps
        and not fresh["baseline"].get("gaps")
    )
    verdict = {
        "status": (
            "TARGET_REASSESSMENT_CONFIRMED"
            if verified
            else "TARGET_VERIFICATION_FAILED"
        ),
        "regressions": regressions,
        "gaps": gaps,
        "assessment": after,
        "collected_at": newenv["collected_at"],
        "scope": "Snapshot evidence supplied by the operator; not authenticated remote collection or application health proof.",
    }
    event(run_id, verdict["status"], verdict)
    return verdict
