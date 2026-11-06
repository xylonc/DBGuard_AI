"""Local durable run/evidence history. Operator statements never imply verification."""

from contextlib import contextmanager, closing
import json
import os
from pathlib import Path
import sqlite3
from datetime import datetime, timezone
from .shared import ContractError, blocking_gaps, is_regression


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
    used = engine.policy.sha256 if engine.policy is not None else None
    if used != record["handoff"].get("policy_profile_sha256"):
        raise ContractError("Policy profile differs from the recorded run; assessment is not comparable")
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
    units = result.get("fix_units", [result.get("fix_unit", {})])
    # Object fixes (fix-unit v2) are confirmed with their object predicate: catalog
    # specs are not in the sandbox findings, and one object fix need not make the
    # whole catalog check PASS. Setting fixes keep the spec PASS rule.
    objects = [f for f in units if f.get("schema_version") == "fix-unit-v2"]
    controls = [
        f["spec_id"]
        for f in units
        if f.get("spec_id") and f.get("schema_version") not in ("fix-unit-v2", "catalog-setting-fix-v1")
    ]
    # W2B: a catalog-linked setting fix is confirmed by its catalog check in the full report.
    catalog_controls = [f["spec_id"] for f in units
                        if f.get("spec_id") and f.get("schema_version") == "catalog-setting-fix-v1"]
    upstream = {r.get("spec_id"): r.get("result") for r in (after.get("upstream_report") or {}).get("results", [])}
    object_checks = _object_checks(result, objects, old, fresh, engine) if objects else []
    regressions = [
        k
        for k, v in before["findings"].items()
        if is_regression(v["status"], after["findings"].get(k, {}).get("status"))
    ]
    gaps = engine.gapped_settings(after["findings"])
    verified = (
        bool(controls or object_checks or catalog_controls)
        and all(
            after["findings"].get(sid, {}).get("status") == "PASS" for sid in controls
        )
        and all(upstream.get(sid) == "PASS" for sid in catalog_controls)
        and all(check["verified"] for check in object_checks)
        and not regressions
        and not gaps
        and not blocking_gaps(fresh)
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
    if objects:
        verdict["object_checks"] = object_checks
    event(run_id, verdict["status"], verdict)
    return verdict


def _applied_snapshot(result):
    """The sandbox collection with every fix of the recorded run applied, or None."""
    if result.get("kind") == "object":
        attempts = result.get("attempts") or []
        if result.get("status") == "VERIFIED" and attempts and attempts[-1].get("status") == "VERIFIED":
            return attempts[-1].get("after")
        return None
    combined = result.get("combined_test") or {}
    steps = combined.get("steps") or []
    if result.get("status") == "VERIFIED" and combined.get("status") == "VERIFIED" and steps:
        return steps[-1].get("after")
    return None


def _object_checks(result, units, old, fresh, engine):
    """Per object fix: predicate on the fresh target plus prior/applied signatures."""
    from . import object_fixes
    applied = _applied_snapshot(result)
    checks = []
    for unit in units:
        # Re-derived from the recorded source evidence, never taken from storage alone.
        proposal = object_fixes.resolve(engine, old, engine.policy_pin, unit.get("fix_id"))
        recorded = {"fix_type": unit.get("fix_type"), "target": unit.get("target"),
                    "params": unit.get("params"), "prior": unit.get("prior_state"),
                    "spec_id": unit.get("spec_id")}
        if any(proposal[k] != v for k, v in recorded.items()):
            raise ContractError("Recorded object fix differs from the evidence-derived proposal")
        checks.append(object_fixes.target_verification(proposal, old, applied, fresh))
    return checks
