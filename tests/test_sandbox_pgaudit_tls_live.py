"""Live W2B gate 1 sandbox capabilities (DBGUARD_POC_LIVE=1, Docker, the pinned pgaudit image).

    python3 scripts/build_sandbox_image.py
    DBGUARD_POC_LIVE=1 .venv-demo/bin/python -m pytest tests/test_sandbox_pgaudit_tls_live.py

Each test owns one run-labelled sandbox with --network none and verifies its removal.
"""
import json
import os
import subprocess
import time

import pytest

from services.sandbox_poc import runtime as runtime_module
from services.sandbox_poc.runtime import (
    STOCK_IMAGE, LABEL, PINNED_IMAGES_DIR, TLS_KEY, DisposablePostgres, SandboxStartError,
    container_stderr, docker)

pytestmark = pytest.mark.skipif(os.environ.get("DBGUARD_POC_LIVE") != "1",
                                reason="Set DBGUARD_POC_LIVE=1 with Docker running")

PGAUDIT_IMAGE = json.loads((PINNED_IMAGES_DIR / "pg17-pgaudit.json").read_text())["tag"]
CIS_CIPHERS = ("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
               "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
WEAK_TLS12 = "ECDHE-RSA-AES256-SHA384"  # CBC suite, allowed by the default HIGH:MEDIUM list


@pytest.fixture
def pgaudit_image():
    try:
        docker("image", "inspect", "--format", "{{.Id}}", PGAUDIT_IMAGE)
    except RuntimeError:
        pytest.skip(f"{PGAUDIT_IMAGE} is not built: python3 scripts/build_sandbox_image.py")
    return PGAUDIT_IMAGE


def _run_owned(run_id):
    return docker("ps", "-aq", "--filter", f"label={LABEL}={run_id}")


def _closed(db):
    cleanup = db.close()
    assert cleanup["verified"] is True
    assert _run_owned(db.run_id) == ""


def test_pgaudit_image_preload_restart_and_exact_rollback(pgaudit_image):
    db = DisposablePostgres(pgaudit_image)
    try:
        db.start()
        # Pinned: started by the recorded image ID; nothing preloaded by default.
        record = json.loads((PINNED_IMAGES_DIR / "pg17-pgaudit.json").read_text())
        assert db.image_id in record["image_ids"].values()
        assert db.sql("SHOW shared_preload_libraries;") == ""
        with pytest.raises(RuntimeError, match="unrecognized configuration parameter"):
            db.sql("SHOW pgaudit.log;")
        assert db.sql("SELECT default_version FROM pg_catalog.pg_available_extensions "
                      "WHERE name = 'pgaudit';") == record["pgaudit_extension_version"]
        names = ["shared_preload_libraries"]
        before = db.setting_sources(names)

        db.sql("ALTER SYSTEM SET shared_preload_libraries = 'pgaudit';\n"
               "ALTER SYSTEM SET pgaudit.log = 'ddl,role,write';\n")
        db.activate({"shared_preload_libraries": "pgaudit", "pgaudit.log": "ddl,role,write"})
        assert db.sql("SHOW shared_preload_libraries;") == "pgaudit"
        assert db.sql("SHOW pgaudit.log;") == "ddl,role,write"
        assert db.pending_restart() == set()
        assert db.health()
        # pgaudit is really loaded: a DDL statement produces an audit record.
        db.sql("CREATE TABLE dbguard_audit_probe (id int);")
        deadline = time.monotonic() + 5
        while "AUDIT: SESSION" not in container_stderr(db.name) and time.monotonic() < deadline:
            time.sleep(0.2)
        log = container_stderr(db.name)
        assert "AUDIT: SESSION" in log and "DDL,CREATE TABLE" in log

        # Exact rollback: another controlled restart back to the empty preload list.
        db.sql("ALTER SYSTEM RESET pgaudit.log;\nALTER SYSTEM RESET shared_preload_libraries;\n")
        db.activate({"shared_preload_libraries": ""})
        assert db.setting_sources(names) == before
        assert db.pending_restart() == set()
        with pytest.raises(RuntimeError, match="unrecognized configuration parameter"):
            db.sql("SHOW pgaudit.log;")
    finally:
        _closed(db)


@pytest.mark.parametrize("image", ["pgaudit", "stock"])
def test_missing_preload_library_is_a_clean_start_failure(pgaudit_image, image):
    db = DisposablePostgres(pgaudit_image if image == "pgaudit" else STOCK_IMAGE)
    try:
        db.start()
        db.sql("ALTER SYSTEM SET shared_preload_libraries = 'dbguard_missing_lib';")
        started = time.monotonic()
        with pytest.raises(SandboxStartError) as error:
            db.activate({"shared_preload_libraries": "dbguard_missing_lib"})
        assert time.monotonic() - started < 20
        assert str(error.value) == ("PostgreSQL failed to start after restart: shared_preload_libraries "
                                    "names 'dbguard_missing_lib', which is not installed in the sandbox image")
        with pytest.raises(RuntimeError):
            db.health()
    finally:
        _closed(db)


def test_sandbox_tls_rehearsal_negotiates_only_cis_ciphers_and_key_never_leaves(pgaudit_image, monkeypatch, caplog):
    seen = []  # every docker output and error the runtime handled

    def recording_docker(*args, **kwargs):
        try:
            out = docker(*args, **kwargs)
        except RuntimeError as exc:
            seen.append(str(exc))
            raise
        seen.append(out)
        return out
    monkeypatch.setattr(runtime_module, "docker", recording_docker)

    db = DisposablePostgres(pgaudit_image)
    results, errors, key_lines = [], [], []
    try:
        db.start()
        db.enable_tls()
        assert db.sql("SHOW ssl;") == "on"
        host = json.loads(docker("inspect", "--format",
                                 "{{json .HostConfig.NetworkMode}} {{json .Mounts}}", db.name)
                          .replace(" ", ",", 1).join("[]"))
        assert host == ["none", []]  # loopback only; no host mounts for key material to reach

        # Before the fix: the default cipher list still accepts a non-CIS TLS 1.2 suite.
        default_ciphers = db.sql("SHOW ssl_ciphers;")
        assert db.tls_accepts_cipher(WEAK_TLS12) is True
        results.append(db.tls_probe("TLSv1.2"))

        db.sql(f"ALTER SYSTEM SET ssl_ciphers = '{CIS_CIPHERS}';")
        db.activate({"ssl_ciphers": CIS_CIPHERS})
        probe = db.tls_probe("TLSv1.2")
        results.append(probe)
        assert probe["protocol"] == "TLSv1.2" and probe["cipher"] in CIS_CIPHERS.split(":")
        assert db.tls_accepts_cipher(WEAK_TLS12) is False
        assert db.tls_accepts_cipher("ECDHE-RSA-AES128-GCM-SHA256") is True
        results.append(db.tls_probe("TLSv1.3"))  # TLS 1.3 is unaffected by ssl_ciphers
        try:
            db.tls_probe("TLSv1.1")
        except Exception as exc:  # refused by the allowlist
            errors.append("".join(str(a) for a in exc.args))

        # Rollback restores the default list exactly; the weak suite is accepted again.
        db.sql("ALTER SYSTEM RESET ssl_ciphers;")
        db.activate({"ssl_ciphers": default_ciphers})
        assert db.tls_accepts_cipher(WEAK_TLS12) is True

        # Test-only read of the key, inside the test process, to prove it never leaked.
        mode = subprocess.run(["docker", "exec", db.name, "stat", "-c", "%a %U", TLS_KEY],
                              capture_output=True, text=True, check=True).stdout.split()
        assert mode == ["600", "postgres"]
        pem = subprocess.run(["docker", "exec", db.name, "cat", TLS_KEY],
                             capture_output=True, text=True, check=True).stdout
        key_lines = [line for line in pem.splitlines() if len(line) >= 40 and "-----" not in line]
        assert len(key_lines) > 10 and "PRIVATE KEY" in pem
        del pem
        haystack = "\n".join(seen + errors + [json.dumps(results), container_stderr(db.name), caplog.text])
        leaked = sum(line in haystack for line in key_lines)
        assert leaked == 0, f"key material found in {leaked} places"
        assert "PRIVATE KEY" not in haystack
    finally:
        key_lines.clear()
        _closed(db)
