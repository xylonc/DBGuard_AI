"""Live: a hostile target cannot shadow the collector's built-ins or unmask secrets.

One disposable, run-labelled PG17 container (`--network none`, tmpfs only,
removed afterwards) is set up the way a hostile or merely odd target could be:

  * shadowing: `evil.current_setting(text)` returns 'PWNED' and the collecting
    role's search_path is `evil, pg_catalog`;
  * masking: the database has standard_conforming_strings = off, and
    archive_command / primary_conninfo hold planted credentials.

The real wrapper (collector/dbguard-collect.sh with the committed check
manifest) then runs inside that container, exactly as collector_runner does.
The collector must succeed, report real values, leak neither secret, and keep
the evidence of the tampering (reset_val, role_settings).
"""
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

import jsonschema
import pytest

from services.sandbox_poc.runtime import LABEL, DisposablePostgres, docker

pytestmark = pytest.mark.skipif(os.environ.get("DBGUARD_POC_LIVE") != "1",
                                reason="Requires disposable Docker databases")

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_DIR = ROOT / "collector"
MANIFEST = ROOT / "tests" / "fixtures" / "phase1" / "checks-cis-pg17-v1.1.0.json"
SCHEMA = json.loads((ROOT / "catalog" / "specs" / "contracts" / "snapshot-v0.3.0.json").read_text())
FOLDER = "/var/run/postgresql/dbguard-collector"

SHADOW_MARK = "PWNED"
ARCHIVE_SECRET = "s3cr3tXYZ"
CONNINFO_SECRET = "hunter2XYZ"
ARCHIVE_COMMAND = f"cp %p rclone://user:{ARCHIVE_SECRET}@bucket/%f"
PRIMARY_CONNINFO = f"password={CONNINFO_SECRET} host=x user=rep"
HOSTILE_SEARCH_PATH = "evil, pg_catalog"


def plant_shadow(db: DisposablePostgres) -> None:
    db.sql("CREATE SCHEMA evil;\n"
           "CREATE FUNCTION evil.current_setting(text) RETURNS text\n"
           f"  LANGUAGE sql AS $$ SELECT '{SHADOW_MARK}'::text $$;\n"
           f"ALTER ROLE dbguard_poc SET search_path = {HOSTILE_SEARCH_PATH};\n")
    # Precondition: a fresh session really resolves the shadow. Without this
    # the test could pass because the attack silently did not take.
    assert db.sql("SELECT current_setting('server_version_num');") == SHADOW_MARK
    assert db.sql("SHOW search_path;") == HOSTILE_SEARCH_PATH


def plant_masking(db: DisposablePostgres) -> None:
    # One ALTER SYSTEM per psql run: each is its own implicit transaction.
    db.sql(f"ALTER SYSTEM SET archive_command = '{ARCHIVE_COMMAND}';")
    db.sql(f"ALTER SYSTEM SET primary_conninfo = '{PRIMARY_CONNINFO}';")
    db.sql("ALTER DATABASE dbguard_sandbox SET standard_conforming_strings = off;")
    assert db.sql("SELECT pg_reload_conf();") == "t"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if db.sql("SELECT reset_val FROM pg_settings WHERE name = 'primary_conninfo';") == PRIMARY_CONNINFO:
            break
        time.sleep(0.1)
    else:
        pytest.fail("primary_conninfo did not take effect after reload")
    # Preconditions: the secrets are really on the server, in the views the
    # collector reads, and new sessions really run with backslash escapes.
    assert db.sql("SHOW standard_conforming_strings;") == "off"
    files = db.sql("SELECT string_agg(setting, ' ') FROM pg_file_settings"
                   " WHERE name IN ('archive_command', 'primary_conninfo');")
    assert ARCHIVE_SECRET in files and CONNINFO_SECRET in files


def run_collector(db: DisposablePostgres, collector_dir: Path) -> tuple[subprocess.CompletedProcess, str | None]:
    """Run the real wrapper inside the owned container, as collector_runner does,
    but keep the exit code and stderr instead of raising."""
    db._assert_owned()
    docker("exec", db.name, "mkdir", "-p", FOLDER)
    for name in ("dbguard-collect.sh", "collect.sql"):
        docker("exec", "-i", db.name, "sh", "-c", f"cat > {FOLDER}/{name}",
               stdin=(collector_dir / name).read_text())
    docker("exec", "-i", db.name, "sh", "-c", f"cat > {FOLDER}/checks.json", stdin=MANIFEST.read_text())
    db._assert_owned()
    proc = subprocess.run(
        ["docker", "exec", "-e", "PGUSER=dbguard_poc", "-e", "PGDATABASE=dbguard_sandbox",
         "-e", "TMPDIR=/var/run/postgresql", db.name, "bash", f"{FOLDER}/dbguard-collect.sh",
         "-t", db.name, "-m", f"{FOLDER}/checks.json", "-o", f"{FOLDER}/snapshot.json"],
        capture_output=True, text=True, timeout=120)
    raw = None
    if proc.returncode == 0:
        raw = docker("exec", db.name, "cat", f"{FOLDER}/snapshot.json")
    return proc, raw


def hardening_failures(db: DisposablePostgres, proc, raw: str | None, collector_dir: Path) -> list[str]:
    """Everything wrong with one collection under attack. [] means hardened."""
    failures = []
    for label, text in (("stdout", proc.stdout), ("stderr", proc.stderr), ("bundle", raw or "")):
        for secret in (ARCHIVE_SECRET, CONNINFO_SECRET):
            if secret in text:
                failures.append(f"{secret} leaked {text.count(secret)}x in {label}")
    if proc.returncode != 0:
        failures.append(f"collector exit {proc.returncode}: {proc.stderr.strip()[-300:]}")
        return failures
    if SHADOW_MARK in raw:
        failures.append(f"{SHADOW_MARK} appears {raw.count(SHADOW_MARK)}x in the bundle")
    snapshot = json.loads(raw)
    jsonschema.validate(snapshot, SCHEMA)
    env = snapshot["envelope"]
    if env["collector_sha256"] != hashlib.sha256((collector_dir / "collect.sql").read_bytes()).hexdigest():
        failures.append("collector_sha256 does not match the collect.sql that ran")
    if env["manifest"]["sha256"] != hashlib.sha256(MANIFEST.read_bytes()).hexdigest():
        failures.append("manifest sha256 does not match the committed manifest")
    if int(snapshot["baseline"]["identity"]["server_version_num"]) // 10000 != 17:
        failures.append("identity does not report PostgreSQL 17")

    # Manifest checks: each answer equals what SHOW (no function lookup) gives
    # in a fresh session on the same target.
    manifest = json.loads(MANIFEST.read_text())
    if set(snapshot["checks"]) != {c["spec_id"] for c in manifest["checks"]}:
        failures.append("checks do not answer exactly the manifest")
    for c in manifest["checks"]:
        got = snapshot["checks"].get(c["spec_id"], {})
        real = db.sql(f"SHOW {c['setting_name']};")
        if got.get("status") != "ok" or got.get("result") != real:
            failures.append(f"{c['spec_id']}: got {got!r}, real {real!r}")

    settings = {r["name"]: r for r in snapshot["baseline"]["settings"]}
    files = {r["name"]: r for r in snapshot["baseline"]["file_settings"]
             if r["name"] in ("archive_command", "primary_conninfo")}

    # Redaction really ran (structure kept, secret replaced), rather than the
    # values simply being absent from the bundle.
    if files.get("archive_command", {}).get("setting") != "cp %p rclone://user:***REDACTED***@bucket/%f":
        failures.append(f"archive_command file setting: {files.get('archive_command')!r}")
    if files.get("primary_conninfo", {}).get("setting") != "password=***REDACTED*** host=x user=rep":
        failures.append(f"primary_conninfo file setting: {files.get('primary_conninfo')!r}")
    pc = settings.get("primary_conninfo", {})
    if not pc.get("sanitised") or pc.get("reset_val") != "password=***REDACTED*** host=x user=rep":
        failures.append(f"primary_conninfo settings row: {pc!r}")
    parsed = snapshot["baseline"]["replication"].get("primary_conninfo_parsed")
    if parsed != {"host": "x", "user": "rep"}:
        failures.append(f"parsed primary_conninfo: {parsed!r}")

    # The collector's own pins show as 'session'; reset_val keeps the target's
    # configured values, so the tampering stays visible to the reviewer.
    expected_rows = {
        "search_path": {"setting": "pg_catalog, pg_temp", "source": "session", "reset_val": HOSTILE_SEARCH_PATH},
        "standard_conforming_strings": {"setting": "on", "source": "session", "reset_val": "off"},
    }
    for name, want in expected_rows.items():
        row = settings.get(name, {})
        got = {k: row.get(k) for k in want}
        if got != want:
            failures.append(f"{name} row: got {got!r}, want {want!r}")
    role_settings = {(r["role"], r["database"]): r["settings"] for r in snapshot["baseline"]["role_settings"]}
    if role_settings.get(("dbguard_poc", "ALL")) != [f"search_path={HOSTILE_SEARCH_PATH}"]:
        failures.append(f"role search_path not preserved: {role_settings!r}")
    if role_settings.get(("ALL", "dbguard_sandbox")) != ["standard_conforming_strings=off"]:
        failures.append(f"database standard_conforming_strings not preserved: {role_settings!r}")
    return failures


def collect_under_attack(collector_dir: Path) -> tuple[list[str], dict]:
    """Plant both attacks in one fresh container, collect, judge, and clean up."""
    db = DisposablePostgres()
    cleanup = None
    try:
        db.start()
        networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", db.name))
        assert set(networks) == {"none"}, networks
        mounts = json.loads(docker("inspect", "--format", "{{json .Mounts}}", db.name))
        assert not [m for m in mounts if m.get("Type") == "bind"], mounts
        plant_shadow(db)
        plant_masking(db)
        proc, raw = run_collector(db, collector_dir)
        failures = hardening_failures(db, proc, raw, collector_dir)
    finally:
        cleanup = db.close()
    return failures, cleanup | {"run_id": db.run_id, "name": db.name}


def test_hostile_target_cannot_shadow_builtins_or_unmask_secrets():
    failures, cleanup = collect_under_attack(COLLECTOR_DIR)
    assert failures == []
    assert cleanup["verified"]
    assert not docker("ps", "-aq", "--filter", f"label={LABEL}={cleanup['run_id']}")
    assert not docker("ps", "-aq", "--filter", f"name=^/{cleanup['name']}$")
