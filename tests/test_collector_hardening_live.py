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

Secret-bearing settings never ship as text: every row, file_settings entry,
role_settings entry and manifest answer for them reads exactly
"***REDACTED*** (set, N characters)". That covers the seven named settings
and every custom or extension (dotted) setting except an exact list of
reviewed pgaudit, set_user, pg_stat_statements and plpgsql settings. Row-level
security policy expressions ship as the same marker. primary_conninfo is also
parsed to allowlisted keys only, and a URI that cannot be read safely
(including a query parameter with whitespace or a second '=') is unparsed.
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
REDACTED = "***REDACTED***"


def marker(value: str) -> str:
    """What every row of a secret-bearing setting must read: set, and its length."""
    return f"{REDACTED} (set, {len(value)} characters)"


# The marker format pinned by literal, independent of marker().
assert marker("cp %p /x/%f") == "***REDACTED*** (set, 11 characters)"

# libpq connection keys parse_conninfo may return (pinned in the unit tests).
ALLOWED_CONNINFO_KEYS = {
    "host", "hostaddr", "port", "user", "dbname", "application_name",
    "sslmode", "sslrootcert", "sslcert", "sslkey", "sslcrl", "sslcrldir", "sslsni",
    "gssencmode", "channel_binding", "target_session_attrs", "load_balance_hosts",
    "connect_timeout", "keepalives", "keepalives_idle", "keepalives_interval",
    "keepalives_count", "tcp_user_timeout", "krbsrvname", "service", "requiressl",
    "replication",
    "ssl_min_protocol_version", "ssl_max_protocol_version", "require_auth", "sslcertmode",
    "sslnegotiation", "sslcompression", "gssdelegation", "fallback_application_name",
}


def all_strings(obj):
    """Every string (keys included) in a decoded snapshot."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from all_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from all_strings(v)


def raw_text_failures(snapshot: dict, raw_values, fragments=()) -> list[str]:
    """No decoded string in the snapshot contains a planted raw value, or a
    non-secret fragment of it (the text is never shipped, not just masked)."""
    failures = []
    for s in all_strings(snapshot):
        for needle in (*raw_values, *fragments):
            if needle in s:
                failures.append(f"raw text {needle!r} shipped in {s[:120]!r}")
    return failures


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


def run_collector(db: DisposablePostgres, collector_dir: Path,
                  manifest_text: str | None = None) -> tuple[subprocess.CompletedProcess, str | None]:
    """Run the real wrapper inside the owned container, as collector_runner does,
    but keep the exit code and stderr instead of raising. `manifest_text`
    defaults to the committed manifest."""
    db._assert_owned()
    docker("exec", db.name, "mkdir", "-p", FOLDER)
    for name in ("dbguard-collect.sh", "collect.sql"):
        docker("exec", "-i", db.name, "sh", "-c", f"cat > {FOLDER}/{name}",
               stdin=(collector_dir / name).read_text())
    docker("exec", "-i", db.name, "sh", "-c", f"cat > {FOLDER}/checks.json",
           stdin=MANIFEST.read_text() if manifest_text is None else manifest_text)
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
        # db.sql trims output, which would drop a real trailing space (the PG17
        # default log_line_prefix is '%m [%p] '), so read the exact bytes as hex
        # through schema-qualified built-ins the hostile search_path cannot shadow.
        real = bytes.fromhex(db.sql(
            "SELECT pg_catalog.encode(pg_catalog.convert_to("
            f"pg_catalog.current_setting('{c['setting_name']}'), 'UTF8'), 'hex');")).decode()
        if got.get("status") != "ok" or got.get("result") != real:
            failures.append(f"{c['spec_id']}: got {got!r}, real {real!r}")

    settings = {r["name"]: r for r in snapshot["baseline"]["settings"]}
    files = {r["name"]: r for r in snapshot["baseline"]["file_settings"]
             if r["name"] in ("archive_command", "primary_conninfo")}

    # Redaction really ran (the exact set-and-length marker), rather than the
    # values simply being absent from the bundle.
    if files.get("archive_command", {}).get("setting") != marker(ARCHIVE_COMMAND):
        failures.append(f"archive_command file setting: {files.get('archive_command')!r}")
    if files.get("primary_conninfo", {}).get("setting") != marker(PRIMARY_CONNINFO):
        failures.append(f"primary_conninfo file setting: {files.get('primary_conninfo')!r}")
    pc = settings.get("primary_conninfo", {})
    if not pc.get("sanitised") or pc.get("reset_val") != marker(PRIMARY_CONNINFO) \
            or pc.get("setting") != marker(PRIMARY_CONNINFO):
        failures.append(f"primary_conninfo settings row: {pc!r}")
    # archive_mode is off here: setting shows PostgreSQL's "(disabled)" (kept
    # readable), while reset_val holds the planted command (redacted).
    ac = settings.get("archive_command", {})
    if not ac.get("sanitised") or ac.get("setting") != "(disabled)" \
            or ac.get("reset_val") != marker(ARCHIVE_COMMAND):
        failures.append(f"archive_command settings row: {ac!r}")
    failures += raw_text_failures(snapshot, (ARCHIVE_COMMAND, PRIMARY_CONNINFO))
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


# ---------------------------------------------------------------------------
# primary_conninfo in every form libpq accepts: URI with a password in the
# userinfo, keyword form with a quoted value holding spaces and '=', and
# sslpassword in both forms. On main, the URI password ended up inside a KEY
# of primary_conninfo_parsed and sslpassword was returned as a value.
#
# Every settings / file_settings row of primary_conninfo must read exactly
# marker(conninfo): the raw text is never shipped. (Until the "never ship raw
# text" design these rows held mask_secrets' output, pinned exactly; the exact
# marker replaces each of those pins.) The parsed dict is pinned exactly and
# may hold allowlisted keys only.
# ---------------------------------------------------------------------------

CONNINFO_CASES = [
    pytest.param(
        "postgresql://rep:SECRETURI1@db.example:5432/postgres?sslmode=require&application_name=standby1",
        "SECRETURI1",
        # URI hostspec is kept whole as "host" (the port is not split out).
        {"user": "rep", "host": "db.example:5432", "dbname": "postgres",
         "sslmode": "require", "application_name": "standby1"},
        id="uri-userinfo-password"),
    pytest.param(
        "host=x user=rep password='ab cd=SECRETQ2' application_name=s1",
        "SECRETQ2",
        {"host": "x", "user": "rep", "application_name": "s1"},
        id="keyword-quoted-password-with-space-and-equals"),
    pytest.param(
        "host=x user=rep sslpassword=SECRETSSL3 sslmode=verify-full",
        "SECRETSSL3",
        {"host": "x", "user": "rep", "sslmode": "verify-full"},
        id="keyword-sslpassword"),
    pytest.param(
        "postgres://rep@db.example/postgres?sslpassword=SECRETSSL4&sslmode=require",
        "SECRETSSL4",
        {"user": "rep", "host": "db.example", "dbname": "postgres", "sslmode": "require"},
        id="uri-query-sslpassword"),
    # A URI password with an empty user name. On main the mask required a
    # non-empty user ([^:/@\s]+), so the password reached settings and
    # file_settings unmasked.
    pytest.param(
        "postgresql://:SECRETNOUSER5@db.example/postgres",
        "SECRETNOUSER5",
        {"host": "db.example", "dbname": "postgres"},
        id="uri-empty-user-password"),
    # libpq allows \' inside a quoted value. On main the mask's quoted
    # alternative stopped at the escaped quote, leaving "s SECRETESC9'" behind.
    pytest.param(
        r"host=x user=rep password='it\'s SECRETESC9' application_name=s1",
        "SECRETESC9",
        {"host": "x", "user": "rep", "application_name": "s1"},
        id="keyword-quoted-password-with-escaped-quote"),
    # Like libpq, the URI userinfo ends only at '@' or '/', so '?' and '#' are
    # part of the password. Only the user name may come out of the userinfo.
    pytest.param(
        "postgresql://rep:Sec?SECRETQM7@db/postgres",
        "SECRETQM7",
        {"host": "db", "user": "rep", "dbname": "postgres"},
        id="uri-password-with-question-mark"),
    pytest.param(
        "postgresql://rep:Sec#SECRETHASH8@db/postgres",
        "SECRETHASH8",
        {"host": "db", "user": "rep", "dbname": "postgres"},
        id="uri-password-with-hash"),
    # libpq honours backslash escapes in unquoted values: "abc\ SECRET" is one
    # value. A plain \S+ stops at the backslash-space and leaves SECRET behind.
    pytest.param(
        r"host=x user=rep password=abc\ SECRETUNQ10 application_name=s1",
        "SECRETUNQ10",
        {"host": "x", "user": "rep", "application_name": "s1"},
        id="keyword-unquoted-password-with-escaped-space"),
    # A quote in the middle of an unquoted value is literal in libpq; the value
    # must not be split at the quote or at the '=' after it.
    pytest.param(
        "host=x user=rep password=ab'cd=SECRETAPOS11 application_name=s1",
        "SECRETAPOS11",
        {"host": "x", "user": "rep", "application_name": "s1"},
        id="keyword-unquoted-password-with-inner-quote-and-equals"),
    # libpq percent-decodes URI query keywords: pass%77ord is "password".
    # The key is dropped from the parsed output.
    pytest.param(
        "postgresql://rep@db/postgres?pass%77ord=SECRETPCT12",
        "SECRETPCT12",
        {"host": "db", "user": "rep", "dbname": "postgres"},
        id="uri-query-percent-encoded-password-key"),
    # A '/' inside the password ends libpq's userinfo scan early, so the '@'
    # lands in the path. The parser must report it as unparsed, never guess.
    pytest.param(
        "postgresql://rep:pa/SECRETSLASH13@db/x",
        "SECRETSLASH13",
        {"unparsed": True},
        id="uri-password-with-slash-is-unparsed"),
    # options is not allowlisted: dropped from the parsed output entirely.
    # (Before the allowlist it was returned as "-c app.password=***REDACTED***".)
    pytest.param(
        "host=x user=rep options='-c app.password=SECRETOPT14'",
        "SECRETOPT14",
        {"host": "x", "user": "rep"},
        id="keyword-options-value-carrying-a-password-is-dropped"),
    # An allowlisted key carrying a password: kept, its value masked. This is
    # what still exercises mask_secrets on PostgreSQL's own regex engine.
    pytest.param(
        "host=x user=rep application_name='a password=SECRETAPP19'",
        "SECRETAPP19",
        {"host": "x", "user": "rep", "application_name": f"a password={REDACTED}"},
        id="keyword-application-name-value-carrying-a-password"),
    # db-security-reviewer F2: whitespace inside a URI password. The old mask
    # stopped at the space and shipped "SECRETWS16 horse@primary/postgres".
    pytest.param(
        "postgresql://rep:correct SECRETWS16 horse@primary/postgres",
        "SECRETWS16",
        {"host": "primary", "user": "rep", "dbname": "postgres"},
        id="uri-password-with-whitespace"),
    # A query password containing a space: the old mask kept "SECRETWS17".
    # (Was {"host": "h", "dbname": "db"}: the allowlist dropped the key.
    # Since N1 a query with whitespace makes the whole URI unparsed.)
    pytest.param(
        "postgresql://h/db?password=my SECRETWS17",
        "SECRETWS17",
        {"unparsed": True},
        id="uri-query-password-with-space"),
    # db-security-reviewer F3: a URI followed by a keyword password. The old
    # parser returned it inside "dbname"; now the string is unparsed.
    pytest.param(
        "postgresql://rep@primary/postgres password=SECRETMIX18",
        "SECRETMIX18",
        {"unparsed": True},
        id="uri-mixed-with-keyword-password-is-unparsed"),
    # db-security-reviewer N1: an allowlisted query value carrying fragments.
    # Before, sslmode came back as "require password=***REDACTED*** SECRETQ33".
    pytest.param(
        "postgresql://rep@primary/postgres?sslmode=require password=correct SECRETQ33",
        "SECRETQ33",
        {"unparsed": True},
        id="uri-query-allowlisted-value-with-whitespace-is-unparsed"),
    pytest.param(
        "postgresql://rep@primary/postgres?application_name=standby1=SECRETEQ38",
        "SECRETEQ38",
        {"unparsed": True},
        id="uri-query-allowlisted-value-with-second-equals-is-unparsed"),
    # Every key added to the allowlist after the third review, kept exactly.
    pytest.param(
        "host=primary user=rep password=SECRETNEW42 ssl_min_protocol_version=TLSv1.2 "
        "ssl_max_protocol_version=TLSv1.3 require_auth=scram-sha-256 sslcertmode=allow "
        "sslnegotiation=postgres sslcompression=0 gssdelegation=0 fallback_application_name=fb1",
        "SECRETNEW42",
        {"host": "primary", "user": "rep", "ssl_min_protocol_version": "TLSv1.2",
         "ssl_max_protocol_version": "TLSv1.3", "require_auth": "scram-sha-256", "sslcertmode": "allow",
         "sslnegotiation": "postgres", "sslcompression": "0", "gssdelegation": "0",
         "fallback_application_name": "fb1"},
        id="keyword-allowlist-additions-are-returned"),
]


def plant_setting(db: DisposablePostgres, name: str, value: str, secret: str) -> None:
    """ALTER SYSTEM one sighup setting (fixed test names only) and wait for it."""
    assert name in ("primary_conninfo", "archive_command"), name
    # Literal under standard_conforming_strings = on (the psql default here):
    # only ' is doubled; a backslash in the value stays a backslash.
    literal = value.replace("'", "''")
    db.sql(f"ALTER SYSTEM SET {name} = '{literal}';")
    assert db.sql("SELECT pg_reload_conf();") == "t"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if db.sql(f"SELECT reset_val FROM pg_settings WHERE name = '{name}';") == value:
            break
        time.sleep(0.1)
    else:
        pytest.fail(f"{name} did not take effect after reload")
    # Preconditions: the planted secret really is on the server, in both views
    # the collector reads, so a clean bundle means it was redacted, not missing.
    assert db.sql(f"SHOW {name};") == value
    files = db.sql(f"SELECT setting FROM pg_file_settings WHERE name = '{name}';")
    assert secret in files


def plant_conninfo(db: DisposablePostgres, conninfo: str, secret: str) -> None:
    plant_setting(db, "primary_conninfo", conninfo, secret)


def parsed_key_problems(parsed) -> list[str]:
    """Keys of a parsed conninfo that can only come from a broken parser, or
    that are outside the allowlist."""
    if not isinstance(parsed, dict):
        return [f"parsed conninfo is not an object: {parsed!r}"]
    problems = [f"suspicious key {k!r}" for k in parsed
                if any(bad in k.lower() for bad in ("://", "@", "password", "passfile"))]
    problems += [f"key outside the allowlist {k!r}" for k in parsed
                 if k not in ALLOWED_CONNINFO_KEYS | {"unparsed"}]
    return problems


def leak_and_envelope_failures(proc, raw: str | None, collector_dir: Path,
                               secret: str) -> tuple[list[str], dict | None]:
    """Secret anywhere in the output (case-insensitive), a failed run, or an
    envelope that does not match. Returns the snapshot when the run succeeded."""
    failures = []
    for label, text in (("stdout", proc.stdout), ("stderr", proc.stderr), ("bundle", raw or "")):
        hits = text.lower().count(secret.lower())
        if hits:
            failures.append(f"{secret} leaked {hits}x in {label} (case-insensitive)")
    if proc.returncode != 0:
        failures.append(f"collector exit {proc.returncode}: {proc.stderr.strip()[-300:]}")
        return failures, None
    snapshot = json.loads(raw)
    jsonschema.validate(snapshot, SCHEMA)
    if snapshot["envelope"]["collector_sha256"] != hashlib.sha256((collector_dir / "collect.sql").read_bytes()).hexdigest():
        failures.append("collector_sha256 does not match the collect.sql that ran")
    return failures, snapshot


def redacted_row_failures(snapshot: dict, name: str, value: str) -> list[str]:
    """settings.setting, settings.reset_val and file_settings.setting of `name`
    are marked sanitised and read exactly marker(value)."""
    failures = []
    rows = {"settings": next((r for r in snapshot["baseline"]["settings"]
                              if r["name"] == name), {}),
            "file_settings": next((r for r in snapshot["baseline"]["file_settings"]
                                   if r["name"] == name), {})}
    values = {"settings.setting": rows["settings"].get("setting"),
              "settings.reset_val": rows["settings"].get("reset_val"),
              "file_settings.setting": rows["file_settings"].get("setting")}
    if rows["settings"].get("sanitised") is not True:
        failures.append(f"{name} settings row not marked sanitised: {rows['settings']!r}")
    for where, got in values.items():
        if got != marker(value):
            failures.append(f"{where}: got {got!r}, want {marker(value)!r}")
    return failures


def conninfo_failures(proc, raw: str | None, collector_dir: Path, conninfo: str, secret: str,
                      parsed_want: dict) -> list[str]:
    """Everything wrong with one collection of a planted primary_conninfo."""
    failures, snapshot = leak_and_envelope_failures(proc, raw, collector_dir, secret)
    if snapshot is None:
        return failures

    parsed = snapshot["baseline"]["replication"].get("primary_conninfo_parsed")
    failures += parsed_key_problems(parsed)
    if parsed != parsed_want:
        failures.append(f"parsed primary_conninfo: got {parsed!r}, want {parsed_want!r}")

    failures += redacted_row_failures(snapshot, "primary_conninfo", conninfo)
    failures += raw_text_failures(snapshot, (conninfo,))
    return failures


def collect_with_conninfo(collector_dir: Path, conninfo: str, secret: str,
                          parsed_want: dict) -> tuple[list[str], dict]:
    db = DisposablePostgres()
    try:
        db.start()
        networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", db.name))
        assert set(networks) == {"none"}, networks
        plant_conninfo(db, conninfo, secret)
        proc, raw = run_collector(db, collector_dir)
        failures = conninfo_failures(proc, raw, collector_dir, conninfo, secret, parsed_want)
    finally:
        cleanup = db.close()
    return failures, cleanup | {"run_id": db.run_id, "name": db.name}


@pytest.mark.parametrize("conninfo, secret, parsed_want", CONNINFO_CASES)
def test_primary_conninfo_never_leaks_and_parses_exactly(conninfo, secret, parsed_want):
    assert secret in conninfo  # the case really plants the secret it searches for
    failures, cleanup = collect_with_conninfo(COLLECTOR_DIR, conninfo, secret, parsed_want)
    assert failures == []
    assert cleanup["verified"]
    assert not docker("ps", "-aq", "--filter", f"label={LABEL}={cleanup['run_id']}")
    assert not docker("ps", "-aq", "--filter", f"name=^/{cleanup['name']}$")


# ---------------------------------------------------------------------------
# archive_command is never shipped as text either: not even its non-secret
# structure. (Until the "never ship raw text" design the rows held
# mask_secrets' output, pinned exactly; the exact marker replaces each pin.)
# ---------------------------------------------------------------------------

ARCHIVE_CASES = [
    pytest.param(
        "cp %p rclone://:SECRETARCH6@bucket/%f",
        "SECRETARCH6",
        ("rclone://",),
        id="archive-uri-empty-user-password"),
    # On main and 03a618c the URI rule stopped at '/', so the secret was kept.
    pytest.param(
        "cp %p rclone://u:a/SECRETARCHSL@bucket/%f",
        "SECRETARCHSL",
        ("rclone://",),
        id="archive-uri-password-with-slash"),
    # db-security-reviewer: a cloud key in the environment of the command. No
    # mask rule knows this format; the old collector shipped it verbatim.
    pytest.param(
        "AWS_SECRET_ACCESS_KEY=SECRETAWS20 aws s3 cp %p s3://b/%f",
        "SECRETAWS20",
        ("AWS_SECRET_ACCESS_KEY", "aws s3 cp", "s3://b/"),
        id="archive-aws-secret-key-in-environment"),
]


def plant_archive_command(db: DisposablePostgres, command: str, secret: str) -> None:
    # With archive_mode = off, pg_settings.setting (and SHOW) report
    # archive_command as "(disabled)", so the settings.setting row would not
    # exercise the redaction at all. Turn archiving on first (postmaster
    # setting: a controlled restart of the owned container).
    db.sql("ALTER SYSTEM SET archive_mode = on;")
    # Test setup, not a fix: activate() only restarts for the reviewed restart
    # allowlist, so restart this owned container explicitly and confirm it.
    db.restart()
    assert db.sql("SHOW archive_mode;") == "on"
    plant_setting(db, "archive_command", command, secret)
    assert db.sql("SELECT setting FROM pg_settings WHERE name = 'archive_command';") == command


def collect_with_archive_command(collector_dir: Path, command: str, secret: str,
                                 fragments: tuple[str, ...]) -> tuple[list[str], dict]:
    db = DisposablePostgres()
    try:
        db.start()
        networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", db.name))
        assert set(networks) == {"none"}, networks
        plant_archive_command(db, command, secret)
        proc, raw = run_collector(db, collector_dir)
        failures, snapshot = leak_and_envelope_failures(proc, raw, collector_dir, secret)
        if snapshot is not None:
            failures += redacted_row_failures(snapshot, "archive_command", command)
            failures += raw_text_failures(snapshot, (command,), fragments)
    finally:
        cleanup = db.close()
    return failures, cleanup | {"run_id": db.run_id, "name": db.name}


@pytest.mark.parametrize("command, secret, fragments", ARCHIVE_CASES)
def test_archive_command_never_leaks_and_is_redacted_exactly(command, secret, fragments):
    assert secret in command  # the case really plants the secret it searches for
    assert all(f in command for f in fragments)
    failures, cleanup = collect_with_archive_command(COLLECTOR_DIR, command, secret, fragments)
    assert failures == []
    assert cleanup["verified"]
    assert not docker("ps", "-aq", "--filter", f"label={LABEL}={cleanup['run_id']}")
    assert not docker("ps", "-aq", "--filter", f"name=^/{cleanup['name']}$")


# ---------------------------------------------------------------------------
# A manifest check reads a setting by name through current_setting(), which
# ignores case. sanitise_setting must ignore case too: on main and 03a618c,
# setting_name 'PRIMARY_CONNINFO' missed the (lower-case) list and the raw
# conninfo, password included, came back as the check result.
# ---------------------------------------------------------------------------

CASE_SECRET = "SECRETUPMF21"
CASE_CONNINFO = f"host=x user=rep password={CASE_SECRET}"
CASE_NAMES = ("PRIMARY_CONNINFO", "Primary_Conninfo", "primary_conninfo")
CASE_MANIFEST = json.dumps({
    "manifest_version": 1,
    "benchmark_id": "cis-pg17-v1.1.0",
    "checks": [{"spec_id": f"test:case-{k}", "spec_hash": f"{k:064x}", "kind": "setting",
                "query": f"SHOW {name}", "setting_name": name}
               for k, name in enumerate(CASE_NAMES)],
}, indent=2)


def collect_with_case_manifest(collector_dir: Path) -> tuple[list[str], dict]:
    db = DisposablePostgres()
    try:
        db.start()
        networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", db.name))
        assert set(networks) == {"none"}, networks
        plant_conninfo(db, CASE_CONNINFO, CASE_SECRET)
        # Precondition: the server really resolves the upper-case name.
        assert db.sql("SELECT current_setting('PRIMARY_CONNINFO');") == CASE_CONNINFO
        proc, raw = run_collector(db, collector_dir, CASE_MANIFEST)
        failures, snapshot = leak_and_envelope_failures(proc, raw, collector_dir, CASE_SECRET)
        if snapshot is not None:
            if snapshot["envelope"]["manifest"]["sha256"] != hashlib.sha256(CASE_MANIFEST.encode()).hexdigest():
                failures.append("manifest sha256 does not match the manifest that ran")
            want = {f"test:case-{k}": {"spec_hash": f"{k:064x}", "query": f"SHOW {name}",
                                       "status": "ok", "result": marker(CASE_CONNINFO)}
                    for k, name in enumerate(CASE_NAMES)}
            if snapshot["checks"] != want:
                failures.append(f"checks: got {snapshot['checks']!r}, want {want!r}")
            failures += raw_text_failures(snapshot, (CASE_CONNINFO,))
    finally:
        cleanup = db.close()
    return failures, cleanup | {"run_id": db.run_id, "name": db.name}


def test_manifest_setting_name_in_any_case_is_redacted():
    assert CASE_SECRET in CASE_CONNINFO
    failures, cleanup = collect_with_case_manifest(COLLECTOR_DIR)
    assert failures == []
    assert cleanup["verified"]
    assert not docker("ps", "-aq", "--filter", f"label={LABEL}={cleanup['run_id']}")
    assert not docker("ps", "-aq", "--filter", f"name=^/{cleanup['name']}$")


# ---------------------------------------------------------------------------
# pg_subscription.subconninfo goes through the same parse_conninfo. A
# subscription created WITH (connect = false) never contacts the publisher, so
# it works in a --network none container; the conninfo is still validated by
# libpq and stored verbatim in pg_subscription.
# ---------------------------------------------------------------------------

SUB_SECRET = "SECRETSUB15"
SUB_CONNINFO = f"postgresql://rep:Sub?{SUB_SECRET}@db.example/postgres?application_name=sub1"
SUB_WANT = [{"subname": "s1", "owner": "dbguard_poc", "enabled": False,
             "conninfo_parsed": {"user": "rep", "host": "db.example", "dbname": "postgres",
                                 "application_name": "sub1"}}]


def plant_subscription(db: DisposablePostgres) -> None:
    literal = SUB_CONNINFO.replace("'", "''")
    db.sql(f"CREATE SUBSCRIPTION s1 CONNECTION '{literal}' PUBLICATION p1 WITH (connect = false);")
    # Preconditions: the secret really is in the catalog the collector reads,
    # and the subscription is inert (connect = false leaves it disabled).
    assert db.sql("SELECT subconninfo FROM pg_subscription WHERE subname = 's1';") == SUB_CONNINFO
    assert db.sql("SELECT subenabled FROM pg_subscription WHERE subname = 's1';") == "f"


def collect_with_subscription(collector_dir: Path) -> tuple[list[str], dict]:
    db = DisposablePostgres()
    try:
        db.start()
        networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", db.name))
        assert set(networks) == {"none"}, networks
        plant_subscription(db)
        proc, raw = run_collector(db, collector_dir)
        failures, snapshot = leak_and_envelope_failures(proc, raw, collector_dir, SUB_SECRET)
        if snapshot is not None:
            subs = snapshot["baseline"]["replication"].get("subscriptions")
            if isinstance(subs, list):
                for sub in subs:
                    failures += parsed_key_problems(sub.get("conninfo_parsed"))
            if subs != SUB_WANT:
                failures.append(f"subscriptions: got {subs!r}, want {SUB_WANT!r}")
    finally:
        cleanup = db.close()
    return failures, cleanup | {"run_id": db.run_id, "name": db.name}


def test_subscription_conninfo_with_question_mark_in_password_never_leaks():
    assert SUB_SECRET in SUB_CONNINFO  # the case really plants the secret it searches for
    failures, cleanup = collect_with_subscription(COLLECTOR_DIR)
    assert failures == []
    assert cleanup["verified"]
    assert not docker("ps", "-aq", "--filter", f"label={LABEL}={cleanup['run_id']}")
    assert not docker("ps", "-aq", "--filter", f"name=^/{cleanup['name']}$")


# ---------------------------------------------------------------------------
# db-security-reviewer B1 and N2: custom and extension (dotted) settings, and
# row-level security policy expressions. One container holds the main
# session's live smoke plus the edges:
#
#   * ALTER ROLE authenticator SET pgrst.jwt_secret (PostgREST's JWT key),
#     next to a hostile search_path that must stay visible as evidence, two
#     reviewed-prefix settings that must stay readable, and a prefix that only
#     extends a reviewed one (pgaudit_x);
#   * ALTER DATABASE postgres SET "app.jwt_secret" and "APP.Token";
#   * ALTER SYSTEM SET app.jwt_key (file_settings, and a manifest check
#     reading it by name in two cases);
#   * ALTER SYSTEM SET pgaudit.log and plpgsql.variable_conflict: reviewed
#     names, readable in file_settings, settings and checks;
#   * pg_trgm loaded through session_preload_libraries, so a dotted setting
#     outside the reviewed names really appears in pg_settings: its row is
#     redacted and flagged sanitised;
#   * a policy USING (api_key = 'SECRET') WITH CHECK (api_key <> 'SECRET'),
#     and a SELECT policy with no WITH CHECK.
# (A two-dot name such as app.settings.key is rejected by PG17.)
# On main and 03a618c, role_settings and rls_policies shipped every one of
# these values raw, and so did the checks.
# ---------------------------------------------------------------------------

CUSTOM_SECRETS = ("SECRETJWT30", "SECRETAPPDB31", "SECRETCONF32", "SECRETRLS34", "SECRETUPC35",
                  "SECRETPFX36", "SECRETWC37")
TRGM_THRESHOLD = "0.437"
POLICY_QUAL = "(api_key = 'SECRETRLS34'::text)"
POLICY_WITH_CHECK = "(api_key <> 'SECRETWC37'::text)"
CUSTOM_NAMES = ("app.jwt_key", "APP.JWT_KEY", "pgaudit.log", "plpgsql.variable_conflict",
                "pg_trgm.similarity_threshold")
CUSTOM_MANIFEST = json.dumps({
    "manifest_version": 1,
    "benchmark_id": "cis-pg17-v1.1.0",
    "checks": [{"spec_id": f"test:custom-{k}", "spec_hash": f"{k + 100:064x}", "kind": "setting",
                "query": f"SHOW {name}", "setting_name": name}
               for k, name in enumerate(CUSTOM_NAMES)],
}, indent=2)
# What each check must answer, by setting name.
CUSTOM_CHECK_RESULTS = {
    "app.jwt_key": "***REDACTED*** (set, 12 characters)",
    "APP.JWT_KEY": "***REDACTED*** (set, 12 characters)",
    "pgaudit.log": "ddl",
    "plpgsql.variable_conflict": "use_column",
    "pg_trgm.similarity_threshold": marker(TRGM_THRESHOLD),
}
ROLE_SETTINGS_WANT = {
    ("authenticator", "ALL"): [
        "search_path=evil, public",
        "pgrst.jwt_secret=***REDACTED*** (set, 11 characters)",
        "pgaudit.log=read",
        "plpgsql.variable_conflict=use_column",
        "pgaudit_x.key=***REDACTED*** (set, 11 characters)",
    ],
    ("ALL", "postgres"): [
        "app.jwt_secret=***REDACTED*** (set, 13 characters)",
        "APP.Token=***REDACTED*** (set, 11 characters)",
    ],
}
# file_settings rows of dotted names (and the preload setting), name -> setting.
FILE_SETTINGS_WANT = {
    "session_preload_libraries": "pg_trgm",
    "pg_trgm.similarity_threshold": marker(TRGM_THRESHOLD),
    "app.jwt_key": "***REDACTED*** (set, 12 characters)",
    "pgaudit.log": "ddl",
    "plpgsql.variable_conflict": "use_column",
}
# settings rows of dotted names. Placeholders (app.jwt_key, pgaudit.log
# without the extension) are not in pg_settings; pg_trgm and plpgsql are
# loaded in the collector's session, so theirs are.
SETTINGS_WANT = {
    # boot_val too (N4): pg_trgm's compiled-in 0.3 is redacted like the value.
    "pg_trgm.similarity_threshold": {"setting": marker(TRGM_THRESHOLD), "reset_val": marker(TRGM_THRESHOLD),
                                     "boot_val": marker("0.3"), "sanitised": True, "source": "configuration file"},
    "plpgsql.variable_conflict": {"setting": "use_column", "reset_val": "use_column", "boot_val": "error",
                                  "sanitised": False, "source": "configuration file"},
}
RLS_WANT = [
    {"schema": "public", "table": "t", "policy": "p", "permissive": "PERMISSIVE", "roles": ["public"],
     "cmd": "ALL", "qual": "***REDACTED*** (set, 31 characters)",
     "with_check": "***REDACTED*** (set, 31 characters)"},
    {"schema": "public", "table": "t", "policy": "p2", "permissive": "PERMISSIVE", "roles": ["public"],
     "cmd": "SELECT", "qual": "***REDACTED*** (set, 4 characters)", "with_check": None},
]
# The exact reviewed extension settings that stay readable (pinned in the
# unit tests too).
REVIEWED_SETTINGS = {
    "pgaudit.log", "pgaudit.log_catalog", "pgaudit.log_client", "pgaudit.log_level", "pgaudit.log_parameter",
    "pgaudit.log_parameter_max_size", "pgaudit.log_relation", "pgaudit.log_rows", "pgaudit.log_statement",
    "pgaudit.log_statement_once", "pgaudit.role",
    "set_user.block_alter_system", "set_user.block_copy_program", "set_user.block_log_statement",
    "set_user.exit_on_error", "set_user.nosuperuser_target_allowlist", "set_user.superuser_allowlist",
    "set_user.superuser_audit_tag",
    "pg_stat_statements.max", "pg_stat_statements.track", "pg_stat_statements.track_utility",
    "pg_stat_statements.track_planning", "pg_stat_statements.save",
    "plpgsql.variable_conflict", "plpgsql.print_strict_params", "plpgsql.check_asserts",
    "plpgsql.extra_warnings", "plpgsql.extra_errors",
}
NEW_REDACTIONS = {"custom and extension settings": "S0", "pg_policies.qual and with_check": "S0"}

# Literal pins, independent of marker().
assert marker("SECRETJWT30") == "***REDACTED*** (set, 11 characters)"
assert marker(POLICY_QUAL) == "***REDACTED*** (set, 31 characters)" == marker(POLICY_WITH_CHECK)


def plant_custom_settings_and_policies(db: DisposablePostgres) -> None:
    # One statement per psql run (ALTER SYSTEM cannot run in a transaction block).
    for stmt in (
        "CREATE ROLE authenticator NOLOGIN;",
        "ALTER ROLE authenticator SET search_path = evil, public;",
        "ALTER ROLE authenticator SET pgrst.jwt_secret = 'SECRETJWT30';",
        "ALTER ROLE authenticator SET pgaudit.log = 'read';",
        "ALTER ROLE authenticator SET plpgsql.variable_conflict = 'use_column';",
        "ALTER ROLE authenticator SET pgaudit_x.key = 'SECRETPFX36';",
        "ALTER DATABASE postgres SET \"app.jwt_secret\" TO 'SECRETAPPDB31';",
        "ALTER DATABASE postgres SET \"APP.Token\" TO 'SECRETUPC35';",
        "ALTER SYSTEM SET session_preload_libraries = 'pg_trgm';",
        f"ALTER SYSTEM SET pg_trgm.similarity_threshold = {TRGM_THRESHOLD};",
        "ALTER SYSTEM SET app.jwt_key = 'SECRETCONF32';",
        "ALTER SYSTEM SET pgaudit.log = 'ddl';",
        "ALTER SYSTEM SET plpgsql.variable_conflict = 'use_column';",
        "CREATE TABLE t (api_key text);",
        "ALTER TABLE t ENABLE ROW LEVEL SECURITY;",
        "CREATE POLICY p ON t USING (api_key = 'SECRETRLS34') WITH CHECK (api_key <> 'SECRETWC37');",
        "CREATE POLICY p2 ON t FOR SELECT USING (true);",
    ):
        db.sql(stmt)
    assert db.sql("SELECT pg_reload_conf();") == "t"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if db.sql("SELECT current_setting('app.jwt_key', true);") == "SECRETCONF32":
            break
        time.sleep(0.1)
    else:
        pytest.fail("app.jwt_key did not take effect after reload")
    # Preconditions: every secret really is where the collector reads, so a
    # clean bundle means it was redacted, not missing.
    setconfig = db.sql("SELECT string_agg(array_to_string(setconfig, '|'), '|') FROM pg_db_role_setting;")
    for secret in ("SECRETJWT30", "SECRETPFX36", "SECRETAPPDB31", "SECRETUPC35"):
        assert secret in setconfig, secret
    assert "search_path=evil, public" in setconfig
    assert db.sql("SELECT setting FROM pg_file_settings WHERE name = 'app.jwt_key';") == "SECRETCONF32"
    assert db.sql("SELECT current_setting('APP.JWT_KEY');") == "SECRETCONF32"
    assert db.sql("SELECT setting || '|' || source FROM pg_settings"
                  " WHERE name = 'pg_trgm.similarity_threshold';") == f"{TRGM_THRESHOLD}|configuration file"
    assert db.sql("SELECT qual || '|' || with_check FROM pg_policies WHERE policyname = 'p';") \
        == f"{POLICY_QUAL}|{POLICY_WITH_CHECK}"
    assert db.sql("SELECT qual || '|' || coalesce(with_check, 'NULL') FROM pg_policies"
                  " WHERE policyname = 'p2';") == "true|NULL"


def custom_failures(proc, raw: str | None, collector_dir: Path) -> list[str]:
    failures, snapshot = [], None
    for secret in CUSTOM_SECRETS:
        got, snap = leak_and_envelope_failures(proc, raw, collector_dir, secret)
        failures += [f for f in got if f not in failures]
        snapshot = snapshot or snap
    if snapshot is None:
        return failures
    base = snapshot["baseline"]
    if snapshot["envelope"]["manifest"]["sha256"] != hashlib.sha256(CUSTOM_MANIFEST.encode()).hexdigest():
        failures.append("manifest sha256 does not match the manifest that ran")

    role_settings = {(r["role"], r["database"]): r["settings"] for r in base["role_settings"]}
    if role_settings != ROLE_SETTINGS_WANT:
        failures.append(f"role_settings: got {role_settings!r}, want {ROLE_SETTINGS_WANT!r}")

    files = {r["name"]: r["setting"] for r in base["file_settings"]
             if "." in r["name"] or r["name"] == "session_preload_libraries"}
    if files != FILE_SETTINGS_WANT:
        failures.append(f"file_settings: got {files!r}, want {FILE_SETTINGS_WANT!r}")

    settings = {r["name"]: {k: r.get(k) for k in ("setting", "reset_val", "boot_val", "sanitised", "source")}
                for r in base["settings"] if "." in r["name"]}
    if settings != SETTINGS_WANT:
        failures.append(f"settings: got {settings!r}, want {SETTINGS_WANT!r}")
    # The flag follows the predicate on every row, not only the dotted ones.
    # (Was a prefix rule over five prefixes; now the exact reviewed names.)
    for r in base["settings"]:
        name = r["name"].lower()
        secret = name in {"archive_command", "restore_command", "archive_cleanup_command",
                          "recovery_end_command", "primary_conninfo", "ssl_passphrase_command",
                          "krb_server_keyfile"} or ("." in name and name not in REVIEWED_SETTINGS)
        if r.get("sanitised") is not secret:
            failures.append(f"sanitised flag of {r['name']}: {r.get('sanitised')!r}, want {secret!r}")

    want_checks = {f"test:custom-{k}": {"spec_hash": f"{k + 100:064x}", "query": f"SHOW {name}",
                                        "status": "ok", "result": CUSTOM_CHECK_RESULTS[name]}
                   for k, name in enumerate(CUSTOM_NAMES)}
    if snapshot["checks"] != want_checks:
        failures.append(f"checks: got {snapshot['checks']!r}, want {want_checks!r}")

    if base["rls_policies"] != RLS_WANT:
        failures.append(f"rls_policies: got {base['rls_policies']!r}, want {RLS_WANT!r}")

    redactions = {r["field"]: r["class"] for r in base["redactions"]}
    for field, cls in NEW_REDACTIONS.items():
        if redactions.get(field) != cls:
            failures.append(f"redactions[{field!r}]: got {redactions.get(field)!r}, want {cls!r}")

    failures += raw_text_failures(snapshot, (POLICY_QUAL, POLICY_WITH_CHECK, "api_key"))
    return failures


def collect_with_custom_settings(collector_dir: Path) -> tuple[list[str], dict]:
    db = DisposablePostgres()
    try:
        db.start()
        networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", db.name))
        assert set(networks) == {"none"}, networks
        plant_custom_settings_and_policies(db)
        proc, raw = run_collector(db, collector_dir, CUSTOM_MANIFEST)
        failures = custom_failures(proc, raw, collector_dir)
    finally:
        cleanup = db.close()
    return failures, cleanup | {"run_id": db.run_id, "name": db.name}


def test_custom_settings_and_policy_expressions_never_leak():
    failures, cleanup = collect_with_custom_settings(COLLECTOR_DIR)
    assert failures == []
    assert cleanup["verified"]
    assert not docker("ps", "-aq", "--filter", f"label={LABEL}={cleanup['run_id']}")
    assert not docker("ps", "-aq", "--filter", f"name=^/{cleanup['name']}$")


# ---------------------------------------------------------------------------
# Exact reviewed names, not prefixes. The previous delta exempted every name
# under five prefixes, so ALTER ROLE ... SET pgaudit.jwt_secret = '...'
# shipped raw in role_settings (test-writer's live probe). Here, on a target
# without pgaudit loaded (so pgaudit.* names are free placeholders):
#   * role settings pgaudit.jwt_secret and plpgsql.jwt_key are redacted,
#     next to pgaudit.log and plpgsql.variable_conflict, which stay visible;
#   * ALTER SYSTEM SET pgaudit.api_key is redacted in file_settings and in a
#     manifest check reading it; auto_explain (no longer exempt) is redacted;
#     pgaudit.log and plpgsql.variable_conflict stay visible in both.
# ---------------------------------------------------------------------------

EXACT_SECRETS = ("SECRETRESID40", "SECRETPLK48", "SECRETPGA50")
EXACT_NAMES = ("pgaudit.api_key", "pgaudit.log", "plpgsql.variable_conflict")
EXACT_MANIFEST = json.dumps({
    "manifest_version": 1,
    "benchmark_id": "cis-pg17-v1.1.0",
    "checks": [{"spec_id": f"test:exact-{k}", "spec_hash": f"{k + 200:064x}", "kind": "setting",
                "query": f"SHOW {name}", "setting_name": name}
               for k, name in enumerate(EXACT_NAMES)],
}, indent=2)
EXACT_CHECK_RESULTS = {
    "pgaudit.api_key": "***REDACTED*** (set, 11 characters)",
    "pgaudit.log": "ddl",
    "plpgsql.variable_conflict": "use_column",
}
EXACT_ROLE_SETTINGS_WANT = {
    ("authenticator", "ALL"): [
        "pgaudit.log=read",
        "pgaudit.jwt_secret=***REDACTED*** (set, 13 characters)",
        "plpgsql.variable_conflict=use_column",
        "plpgsql.jwt_key=***REDACTED*** (set, 11 characters)",
    ],
}
EXACT_FILE_SETTINGS_WANT = {
    "pgaudit.api_key": "***REDACTED*** (set, 11 characters)",
    "auto_explain.log_min_duration": "***REDACTED*** (set, 3 characters)",
    "pgaudit.log": "ddl",
    "plpgsql.variable_conflict": "use_column",
}


def plant_unreviewed_names(db: DisposablePostgres) -> None:
    for stmt in (
        "CREATE ROLE authenticator NOLOGIN;",
        "ALTER ROLE authenticator SET pgaudit.log = 'read';",
        "ALTER ROLE authenticator SET pgaudit.jwt_secret = 'SECRETRESID40';",
        "ALTER ROLE authenticator SET plpgsql.variable_conflict = 'use_column';",
        "ALTER ROLE authenticator SET plpgsql.jwt_key = 'SECRETPLK48';",
        "ALTER SYSTEM SET pgaudit.api_key = 'SECRETPGA50';",
        "ALTER SYSTEM SET auto_explain.log_min_duration = '250';",
        "ALTER SYSTEM SET pgaudit.log = 'ddl';",
        "ALTER SYSTEM SET plpgsql.variable_conflict = 'use_column';",
    ):
        db.sql(stmt)
    assert db.sql("SELECT pg_reload_conf();") == "t"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if db.sql("SELECT current_setting('pgaudit.api_key', true);") == "SECRETPGA50":
            break
        time.sleep(0.1)
    else:
        pytest.fail("pgaudit.api_key did not take effect after reload")
    # Preconditions: pgaudit is not loaded (its names are free placeholders),
    # and every secret is where the collector reads.
    assert db.sql("SHOW shared_preload_libraries;") == ""
    assert db.sql("SELECT array_to_string(setconfig, '|') FROM pg_db_role_setting;") == (
        "pgaudit.log=read|pgaudit.jwt_secret=SECRETRESID40|plpgsql.variable_conflict=use_column|"
        "plpgsql.jwt_key=SECRETPLK48")
    assert db.sql("SELECT setting FROM pg_file_settings WHERE name = 'pgaudit.api_key';") == "SECRETPGA50"


def exact_failures(proc, raw: str | None, collector_dir: Path) -> list[str]:
    failures, snapshot = [], None
    for secret in EXACT_SECRETS:
        got, snap = leak_and_envelope_failures(proc, raw, collector_dir, secret)
        failures += [f for f in got if f not in failures]
        snapshot = snapshot or snap
    if snapshot is None:
        return failures
    base = snapshot["baseline"]
    role_settings = {(r["role"], r["database"]): r["settings"] for r in base["role_settings"]}
    if role_settings != EXACT_ROLE_SETTINGS_WANT:
        failures.append(f"role_settings: got {role_settings!r}, want {EXACT_ROLE_SETTINGS_WANT!r}")
    files = {r["name"]: r["setting"] for r in base["file_settings"] if "." in r["name"]}
    if files != EXACT_FILE_SETTINGS_WANT:
        failures.append(f"file_settings: got {files!r}, want {EXACT_FILE_SETTINGS_WANT!r}")
    want_checks = {f"test:exact-{k}": {"spec_hash": f"{k + 200:064x}", "query": f"SHOW {name}",
                                       "status": "ok", "result": EXACT_CHECK_RESULTS[name]}
                   for k, name in enumerate(EXACT_NAMES)}
    if snapshot["checks"] != want_checks:
        failures.append(f"checks: got {snapshot['checks']!r}, want {want_checks!r}")
    # plpgsql is loaded in the collector's session: its reviewed setting is a
    # real pg_settings row, visible and not flagged.
    pv = next((r for r in base["settings"] if r["name"] == "plpgsql.variable_conflict"), {})
    if {k: pv.get(k) for k in ("setting", "sanitised")} != {"setting": "use_column", "sanitised": False}:
        failures.append(f"plpgsql.variable_conflict settings row: {pv!r}")
    return failures


def collect_with_unreviewed_names(collector_dir: Path) -> tuple[list[str], dict]:
    db = DisposablePostgres()
    try:
        db.start()
        networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", db.name))
        assert set(networks) == {"none"}, networks
        plant_unreviewed_names(db)
        proc, raw = run_collector(db, collector_dir, EXACT_MANIFEST)
        failures = exact_failures(proc, raw, collector_dir)
    finally:
        cleanup = db.close()
    return failures, cleanup | {"run_id": db.run_id, "name": db.name}


def test_unreviewed_names_under_reviewed_prefixes_are_redacted():
    failures, cleanup = collect_with_unreviewed_names(COLLECTOR_DIR)
    assert failures == []
    assert cleanup["verified"]
    assert not docker("ps", "-aq", "--filter", f"label={LABEL}={cleanup['run_id']}")
    assert not docker("ps", "-aq", "--filter", f"name=^/{cleanup['name']}$")


# ---------------------------------------------------------------------------
# db-security-reviewer B2, N1 and N4 in one container.
#
#   * B2: two lines appended to postgresql.conf WITHOUT a reload: an unknown
#     plain name (jwt_secret) and a typo of a secret setting
#     (restore_comand). pg_file_settings reads the file on every query, so
#     both reach file_settings; on the previous version they shipped raw.
#     Their error / applied columns must be exactly what the server reports.
#   * N1: look-alike names, written through a UTF-8 SQL script:
#     "set_user.blocK_copy_program" (U+212A KELVIN SIGN) and
#     "pgaudİt.log" (U+0130). The database collation's lower() folds
#     them onto reviewed names, so on the previous version the
#     file_settings rows and the manifest checks reading them shipped raw.
#     (In role_settings the names come from a catalog column in the C
#     collation, which never folded them: those entries are redacted on both
#     versions and are kept here as a control.)
#   * N4: krb_server_keyfile's boot_val (a path) is the marker, while
#     log_statement's boot_val and value stay readable.
#   * pgaudit.log and log_statement stay visible everywhere.
# ---------------------------------------------------------------------------

KELVIN_NAME = "set_user.blocK_copy_program"
DOTTED_I_NAME = "pgaudİt.log"
B2_LINES = ("\njwt_secret = 'SECRETUNK60'\n"
            "restore_comand = 'aws s3 cp --sse-c-key SECRETTYPO61 s3://b/%f %p'\n")
B2_SECRETS = ("SECRETUNK60", "SECRETTYPO61", "SECRETKEL62", "SECRETDOT63", "SECRETKEL66", "SECRETDOT67")
B2_NAMES = (DOTTED_I_NAME, KELVIN_NAME, "pgaudit.log", "log_statement")
B2_MANIFEST = json.dumps({
    "manifest_version": 1,
    "benchmark_id": "cis-pg17-v1.1.0",
    "checks": [{"spec_id": f"test:b2-{k}", "spec_hash": f"{k + 300:064x}", "kind": "setting",
                "query": f"SHOW {name}", "setting_name": name}
               for k, name in enumerate(B2_NAMES)],
}, indent=2, ensure_ascii=False)
B2_CHECK_RESULTS = {
    DOTTED_I_NAME: "***REDACTED*** (set, 11 characters)",
    KELVIN_NAME: "***REDACTED*** (set, 11 characters)",
    "pgaudit.log": "ddl",
    "log_statement": "ddl",
}
B2_FILE_SETTINGS = {
    "jwt_secret": "***REDACTED*** (set, 11 characters)",
    "restore_comand": marker("aws s3 cp --sse-c-key SECRETTYPO61 s3://b/%f %p"),
    DOTTED_I_NAME: "***REDACTED*** (set, 11 characters)",
    KELVIN_NAME: "***REDACTED*** (set, 11 characters)",
    "pgaudit.log": "ddl",
    "log_statement": "ddl",
}
B2_ROLE_SETTINGS = {("r", "ALL"): [f"{KELVIN_NAME}=***REDACTED*** (set, 11 characters)",
                                   f"{DOTTED_I_NAME}=***REDACTED*** (set, 11 characters)"]}


def plant_b2_n1(db: DisposablePostgres) -> dict:
    """Plant everything; return what the server itself reports for the
    file_settings rows (sourceline, applied, error) and krb_server_keyfile's
    boot_val."""
    for stmt in (
        f"ALTER SYSTEM SET \"{DOTTED_I_NAME}\" = 'SECRETDOT63';",
        f"ALTER SYSTEM SET \"{KELVIN_NAME}\" = 'SECRETKEL62';",
        "ALTER SYSTEM SET pgaudit.log = 'ddl';",
        "ALTER SYSTEM SET log_statement = 'ddl';",
        "CREATE ROLE r NOLOGIN;",
        f"ALTER ROLE r SET \"{KELVIN_NAME}\" = 'SECRETKEL66';",
        f"ALTER ROLE r SET \"{DOTTED_I_NAME}\" = 'SECRETDOT67';",
    ):
        db.sql(stmt)
    assert db.sql("SELECT pg_reload_conf();") == "t"
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if db.sql(f"SELECT current_setting('{DOTTED_I_NAME}', true);") == "SECRETDOT63":
            break
        time.sleep(0.1)
    else:
        pytest.fail("look-alike settings did not take effect after reload")
    # B2: appended after the reload, and never reloaded.
    db.write_config("postgresql.conf", B2_LINES)
    # Preconditions. The look-alikes are stored as written (not ASCII), and
    # the database collation's lower() folds them onto reviewed names: the
    # attack is real on the routes whose names carry that collation.
    assert db.sql(f"SELECT octet_length('{KELVIN_NAME}') - length('{KELVIN_NAME}');") == "2"
    assert db.sql(f"SELECT lower(name) FROM pg_file_settings WHERE name = '{KELVIN_NAME}';") \
        == "set_user.block_copy_program"
    assert db.sql(f"SELECT lower(name) FROM pg_file_settings WHERE name = '{DOTTED_I_NAME}';") == "pgaudit.log"
    assert db.sql(f"SELECT current_setting('{KELVIN_NAME}');") == "SECRETKEL62"
    assert db.sql("SELECT setting FROM pg_file_settings WHERE name = 'jwt_secret';") == "SECRETUNK60"
    assert "SECRETTYPO61" in db.sql("SELECT setting FROM pg_file_settings WHERE name = 'restore_comand';")
    assert db.sql("SELECT count(*) FROM pg_settings WHERE name IN ('jwt_secret', 'restore_comand');") == "0"
    server_rows = {}
    for line in db.sql("SELECT name || '|' || sourceline || '|' || applied || '|' || coalesce(error, '<null>')"
                       " FROM pg_file_settings;").splitlines():
        name, sourceline, applied, error = line.split("|", 3)
        server_rows[name] = {"sourceline": int(sourceline), "applied": applied == "true",
                             "error": None if error == "<null>" else error}
    krb_boot = db.sql("SELECT boot_val FROM pg_settings WHERE name = 'krb_server_keyfile';")
    assert krb_boot  # a non-empty compiled-in path
    return {"file_rows": server_rows, "krb_boot": krb_boot}


def b2_failures(proc, raw: str | None, collector_dir: Path, server: dict) -> list[str]:
    failures, snapshot = [], None
    for secret in B2_SECRETS:
        got, snap = leak_and_envelope_failures(proc, raw, collector_dir, secret)
        failures += [f for f in got if f not in failures]
        snapshot = snapshot or snap
    if snapshot is None:
        return failures
    base = snapshot["baseline"]
    rows = {r["name"]: r for r in base["file_settings"] if r["name"] in B2_FILE_SETTINGS}
    got = {n: r["setting"] for n, r in rows.items()}
    if got != B2_FILE_SETTINGS:
        failures.append(f"file_settings: got {got!r}, want {B2_FILE_SETTINGS!r}")
    # error / applied / sourceline are exactly what the server reports.
    for name, r in rows.items():
        want = server["file_rows"].get(name)
        have = {k: r.get(k) for k in ("sourceline", "applied", "error")}
        if have != want:
            failures.append(f"file_settings {name!r} metadata: got {have!r}, server {want!r}")
    for name in ("jwt_secret", "restore_comand"):
        if (rows.get(name) or {}).get("error") != "unrecognized configuration parameter":
            failures.append(f"{name}: error not kept: {rows.get(name)!r}")
    want_checks = {f"test:b2-{k}": {"spec_hash": f"{k + 300:064x}", "query": f"SHOW {name}",
                                    "status": "ok", "result": B2_CHECK_RESULTS[name]}
                   for k, name in enumerate(B2_NAMES)}
    if snapshot["checks"] != want_checks:
        failures.append(f"checks: got {snapshot['checks']!r}, want {want_checks!r}")
    role_settings = {(r["role"], r["database"]): r["settings"] for r in base["role_settings"]}
    if role_settings != B2_ROLE_SETTINGS:
        failures.append(f"role_settings: got {role_settings!r}, want {B2_ROLE_SETTINGS!r}")
    settings = {r["name"]: r for r in base["settings"]}
    krb = {k: settings.get("krb_server_keyfile", {}).get(k) for k in ("boot_val", "setting", "reset_val", "sanitised")}
    want_krb = {"boot_val": marker(server["krb_boot"]), "setting": marker(server["krb_boot"]),
                "reset_val": marker(server["krb_boot"]), "sanitised": True}
    if krb != want_krb:
        failures.append(f"krb_server_keyfile row: got {krb!r}, want {want_krb!r}")
    ls = {k: settings.get("log_statement", {}).get(k) for k in ("boot_val", "setting", "reset_val", "sanitised")}
    if ls != {"boot_val": "none", "setting": "ddl", "reset_val": "ddl", "sanitised": False}:
        failures.append(f"log_statement row: {ls!r}")
    failures += raw_text_failures(snapshot, (server["krb_boot"],))
    return failures


def collect_with_b2_n1(collector_dir: Path) -> tuple[list[str], dict]:
    db = DisposablePostgres()
    try:
        db.start()
        networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", db.name))
        assert set(networks) == {"none"}, networks
        server = plant_b2_n1(db)
        proc, raw = run_collector(db, collector_dir, B2_MANIFEST)
        failures = b2_failures(proc, raw, collector_dir, server)
    finally:
        cleanup = db.close()
    return failures, cleanup | {"run_id": db.run_id, "name": db.name}


def test_unknown_names_lookalikes_and_boot_val_never_leak():
    failures, cleanup = collect_with_b2_n1(COLLECTOR_DIR)
    assert failures == []
    assert cleanup["verified"]
    assert not docker("ps", "-aq", "--filter", f"label={LABEL}={cleanup['run_id']}")
    assert not docker("ps", "-aq", "--filter", f"name=^/{cleanup['name']}$")
