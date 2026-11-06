"""W2B gate 1 sandbox runtime: pinned pgaudit image, preload restarts, sandbox-only TLS.

Unit tests with a fake docker; the live counterparts are in
tests/test_sandbox_pgaudit_tls_live.py (DBGUARD_POC_LIVE=1).
"""
import hashlib
import json
import re
import traceback

import pytest

from services.sandbox_poc import runtime as runtime_module
from services.sandbox_poc.runtime import (
    DATA, DEFAULT_IMAGE, PINNED_IMAGES_DIR, RESTART_SETTINGS, TLS_CERT, TLS_CONFIG, TLS_GENERATE,
    TLS_KEY, DisposablePostgres, SandboxStartError, sandbox_image)
from services.sandbox_poc.service import SandboxService
from services.sandbox_poc.shared import ROOT, ContractError
from scripts.build_sandbox_image import pinned_inputs, tag_for

RECORD = PINNED_IMAGES_DIR / "pg17-pgaudit.json"
DOCKERFILE = ROOT / "services/sandbox_poc/images/pg17-pgaudit/Dockerfile"
# Stand-in for key material: must never surface from any runtime path.
FAKE_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdbguardFAKEKEY\n"
KEY_MARKER = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDdbguardFAKEKEY"


class FakeDocker:
    """Records docker argv; per-command responses via a handler."""

    def __init__(self, handler=None):
        self.calls = []
        self.handler = handler or (lambda args, stdin: "")

    def __call__(self, *args, stdin=None, timeout=60):
        self.calls.append((args, stdin))
        return self.handler(args, stdin)


def owned_target(monkeypatch, fake, image="unused"):
    target = DisposablePostgres(image=image)
    target.started = True
    monkeypatch.setattr(runtime_module, "docker", fake)
    monkeypatch.setattr(target, "_assert_owned", lambda: None)
    monkeypatch.setattr(runtime_module.time, "sleep", lambda seconds: None)
    return target


# ---------------------------------------------------------------------------
# Image selection and pinning (B3, ruling 5)
# ---------------------------------------------------------------------------

def test_default_image_is_the_pinned_pgaudit_image(monkeypatch):
    # W2B Gate 2 ruling 4: switched after every live suite passed on it.
    monkeypatch.delenv("DBGUARD_POSTGRES_IMAGE", raising=False)
    record = json.loads((PINNED_IMAGES_DIR / "pg17-pgaudit.json").read_text())
    assert DEFAULT_IMAGE == record["tag"] == "dbguard/sandbox-pg17:pgaudit-17.1-2.pgdg12-1"
    assert DisposablePostgres().image == DEFAULT_IMAGE


def test_image_selectable_by_env_and_explicit_wins(monkeypatch):
    monkeypatch.setenv("DBGUARD_POSTGRES_IMAGE", "dbguard/sandbox-pg17:pgaudit-x")
    assert DisposablePostgres().image == "dbguard/sandbox-pg17:pgaudit-x"
    assert sandbox_image("postgres:17-bookworm") == "postgres:17-bookworm"
    # The service and API paths no longer hard-code the stock image over the env var.
    assert SandboxService("unused").runtime_factory().image == "dbguard/sandbox-pg17:pgaudit-x"


def _pin_dir(tmp_path, monkeypatch, ids):
    (tmp_path / "img.json").write_text(json.dumps({"tag": "dbguard/sandbox-pg17:t", "image_ids": ids}))
    monkeypatch.setattr(runtime_module, "PINNED_IMAGES_DIR", tmp_path)


class ReachedRun(Exception):
    pass


def _start_handler(inspect_out):
    def handler(args, stdin):
        if args[:2] == ("image", "inspect"):
            return inspect_out
        if args[0] == "run":
            raise ReachedRun(args)
        raise AssertionError(f"unexpected docker call {args}")
    return handler


@pytest.mark.parametrize("inspect_out", ["sha256:" + "b" * 64 + " linux/arm64",
                                         "sha256:" + "a" * 64 + " linux/amd64"])
def test_pinned_tag_with_other_image_id_or_platform_refused_before_run(tmp_path, monkeypatch, inspect_out):
    _pin_dir(tmp_path, monkeypatch, {"linux/arm64": "sha256:" + "a" * 64})
    fake = FakeDocker(_start_handler(inspect_out))
    monkeypatch.setattr(runtime_module, "docker", fake)
    target = DisposablePostgres(image="dbguard/sandbox-pg17:t")
    with pytest.raises(ContractError, match="pinned image ID"):
        target.start()
    assert [a[0] for a, _ in fake.calls] == ["image"]
    assert target.started is False and target.image_id is None


def test_pinned_tag_with_recorded_id_starts_by_id(tmp_path, monkeypatch):
    pinned = "sha256:" + "a" * 64
    _pin_dir(tmp_path, monkeypatch, {"linux/arm64": pinned})
    fake = FakeDocker(_start_handler(pinned + " linux/arm64"))
    monkeypatch.setattr(runtime_module, "docker", fake)
    target = DisposablePostgres(image="dbguard/sandbox-pg17:t")
    with pytest.raises(ReachedRun) as reached:
        target.start()
    run_args = reached.value.args[0]
    assert pinned in run_args and "dbguard/sandbox-pg17:t" not in run_args
    assert run_args[run_args.index("--network") + 1] == "none"
    assert "-v" not in run_args and "--mount" not in run_args and "-p" not in run_args


def test_unrecorded_image_is_not_pin_checked(tmp_path, monkeypatch):
    _pin_dir(tmp_path, monkeypatch, {"linux/arm64": "sha256:" + "a" * 64})
    fake = FakeDocker(_start_handler("sha256:" + "c" * 64 + " linux/arm64"))
    monkeypatch.setattr(runtime_module, "docker", fake)
    with pytest.raises(ReachedRun):
        DisposablePostgres(image="postgres:17-bookworm").start()


def test_repo_pin_record_matches_dockerfile_and_build_script():
    record = json.loads(RECORD.read_text())
    text = DOCKERFILE.read_text()
    base, version = pinned_inputs(text)
    assert record["dockerfile"] == str(DOCKERFILE.relative_to(ROOT))
    assert record["dockerfile_sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert record["base_image"] == base
    assert re.fullmatch(r"postgres:17-bookworm@sha256:[0-9a-f]{64}", base)
    assert record["pgaudit_package"] == "postgresql-17-pgaudit"
    assert record["pgaudit_package_version"] == version
    assert record["tag"] == tag_for(version)
    assert record["preloaded_by_default"] == []
    assert record["image_ids"] and all(re.fullmatch(r"sha256:[0-9a-f]{64}", v)
                                       for v in record["image_ids"].values())


def test_dockerfile_preloads_nothing_and_opens_nothing():
    code = [line for line in DOCKERFILE.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    body = "\n".join(code)
    assert sum(line.startswith("FROM ") for line in code) == 1
    assert "preload" not in body and "postgresql.conf" not in body
    for keyword in ("EXPOSE", "VOLUME", "ENTRYPOINT", "CMD", "USER", "ENV", "COPY", "ADD"):
        assert not any(line.startswith(keyword + " ") for line in code), keyword


def test_pin_record_is_not_a_twin_catalog_entry():
    # catalog/images/catalog.py loads *.yaml in catalog/images/ as APPROVED twin images;
    # the sandbox pin must never be picked up there.
    assert RECORD.suffix == ".json" and RECORD.parent != ROOT / "catalog/images"


# ---------------------------------------------------------------------------
# Restart for preload changes (B1, ruling 3)
# ---------------------------------------------------------------------------

def test_shared_preload_libraries_is_a_reviewed_restart_setting(monkeypatch):
    assert "shared_preload_libraries" in RESTART_SETTINGS
    target = DisposablePostgres(image="unused")
    calls = []

    def sql(script):
        if "pg_reload_conf" in script:
            return "t"
        if "pending_restart" in script:
            return "shared_preload_libraries"
        raise AssertionError(script)
    monkeypatch.setattr(target, "sql", sql)
    monkeypatch.setattr(target, "restart", lambda: calls.append("restart"))
    monkeypatch.setattr(target, "_effective", lambda name, value: True)
    monkeypatch.setattr(runtime_module.time, "sleep", lambda seconds: None)
    target.activate({"shared_preload_libraries": "pgaudit"})
    assert calls == ["restart"]


OLD_LOG = [
    "2026-11-05 10:00:00.000 UTC [1] LOG:  database system is ready to accept connections",
    # An earlier failure already in the log must not be attributed to this restart.
    '2026-11-05 09:59:00.000 UTC [1] FATAL:  could not access file "stale_lib": No such file or directory',
]


def _restarting_target(monkeypatch, new_lines, comes_back_after=None):
    logs = {"n": 0}

    def stderr(name):
        logs["n"] += 1
        return "\n".join(OLD_LOG + (new_lines if logs["n"] > 1 else [])) + "\n"
    monkeypatch.setattr(runtime_module, "container_stderr", stderr)
    target = owned_target(monkeypatch, FakeDocker())
    polls = {"n": 0}

    def sql(script):
        polls["n"] += 1
        if comes_back_after is not None and polls["n"] > comes_back_after:
            return "1"
        raise RuntimeError("Docker exec failed: psql: error: connection refused")
    monkeypatch.setattr(target, "sql", sql)
    return target


def test_restart_with_missing_preload_library_fails_fast_with_clear_error(monkeypatch):
    target = _restarting_target(monkeypatch, [
        '2026-11-05 10:01:00.000 UTC [77] FATAL:  could not access file "dbguard_missing_lib": '
        "No such file or directory",
        "2026-11-05 10:01:00.000 UTC [77] LOG:  database system is shut down"])
    with pytest.raises(SandboxStartError) as error:
        target.restart()
    message = str(error.value)
    assert "dbguard_missing_lib" in message and "shared_preload_libraries" in message
    assert "stale_lib" not in message and "No such file" not in message and "UTC" not in message
    assert isinstance(error.value, RuntimeError)


def test_restart_reports_other_fatal_startup_errors_without_log_text(monkeypatch):
    target = _restarting_target(monkeypatch, [
        "2026-11-05 10:01:00.000 UTC [77] FATAL:  could not set the cipher list 'ssl-value-from-config'",
        # A quoted name outside the safe character set is never echoed.
        '2026-11-05 10:01:00.000 UTC [78] FATAL:  could not access file "a b\'c": No such file'])
    with pytest.raises(SandboxStartError, match="fatal startup error") as error:
        target.restart()
    assert "ssl-value-from-config" not in str(error.value) and "a b" not in str(error.value)


def test_restart_ignores_expected_connection_fatals(monkeypatch):
    target = _restarting_target(monkeypatch, [
        "2026-11-05 10:01:00.000 UTC [80] FATAL:  the database system is shutting down",
        "2026-11-05 10:01:00.000 UTC [81] FATAL:  the database system is starting up"],
        comes_back_after=3)
    target.restart()


def test_restart_ignores_failures_logged_before_the_restart(monkeypatch):
    target = _restarting_target(monkeypatch, [], comes_back_after=2)
    target.restart()


def test_restart_timeout_is_a_start_error(monkeypatch):
    target = _restarting_target(monkeypatch, [])
    clock = iter([0.0] + [100.0] * 10)
    monkeypatch.setattr(runtime_module.time, "monotonic", lambda: next(clock))
    with pytest.raises(SandboxStartError, match="did not return"):
        target.restart()


# ---------------------------------------------------------------------------
# Sandbox-only TLS (B2, ruling 4)
# ---------------------------------------------------------------------------

def test_tls_material_stays_in_the_container_tmpfs():
    assert TLS_KEY.startswith(DATA + "/") and TLS_CERT.startswith(DATA + "/")
    assert TLS_GENERATE.startswith("umask 077 && ")
    assert TLS_GENERATE.endswith(">/dev/null 2>&1")
    # The key path is only ever an output of openssl; nothing reads it back.
    assert TLS_GENERATE.count(TLS_KEY) == 1 and "-keyout " + TLS_KEY in TLS_GENERATE
    for reader in ("cat ", "base64", "echo", "tee", "cp ", "$", "`"):
        assert reader not in TLS_GENERATE
    assert TLS_CONFIG.count("\n") == 5 and "ssl = 'on'" in TLS_CONFIG


def test_enable_tls_runs_only_constant_commands(monkeypatch):
    fake = FakeDocker()
    target = owned_target(monkeypatch, fake)
    activated = []
    monkeypatch.setattr(target, "activate", activated.append)
    target.enable_tls()
    assert fake.calls == [
        (("exec", target.name, "sh", "-c", TLS_GENERATE), None),
        (("exec", "-i", target.name, "sh", "-c", "cat >> /var/lib/postgresql/data/postgresql.conf"), TLS_CONFIG),
    ]
    assert activated == [{"ssl": "on", "ssl_cert_file": TLS_CERT, "ssl_key_file": TLS_KEY}]


def _leaks(exc, caplog):
    rendered = "".join(traceback.format_exception(exc)) + repr(exc) + str(exc) + caplog.text
    return KEY_MARKER in rendered or "PRIVATE KEY" in rendered


def test_tls_generation_failure_never_carries_key_material(monkeypatch, caplog):
    def handler(args, stdin):
        raise RuntimeError("Docker exec failed: " + FAKE_KEY)
    target = owned_target(monkeypatch, FakeDocker(handler))
    with pytest.raises(RuntimeError, match="certificate generation failed") as error:
        target.enable_tls()
    assert error.value.__cause__ is None and error.value.__suppress_context__
    assert not _leaks(error.value, caplog)


def test_tls_probe_failure_never_carries_key_material(monkeypatch, caplog):
    def handler(args, stdin):
        raise RuntimeError("Docker exec failed: " + FAKE_KEY)
    target = owned_target(monkeypatch, FakeDocker(handler))
    with pytest.raises(RuntimeError, match="connection over loopback failed") as error:
        target.tls_probe()
    assert not _leaks(error.value, caplog)


def test_tls_probe_returns_only_protocol_and_cipher(monkeypatch):
    fake = FakeDocker(lambda args, stdin: "TLSv1.2,ECDHE-RSA-AES256-GCM-SHA384")
    target = owned_target(monkeypatch, fake)
    result = target.tls_probe("TLSv1.2")
    assert result == {"protocol": "TLSv1.2", "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
                      "scope": "DISPOSABLE SANDBOX loopback", "run_id": target.run_id}
    (args, stdin), = fake.calls
    conninfo = args[args.index("-d") + 1]
    assert conninfo == ("host=127.0.0.1 dbname=dbguard_sandbox user=dbguard_poc sslmode=require "
                        "ssl_min_protocol_version=TLSv1.2 ssl_max_protocol_version=TLSv1.2")
    assert stdin.startswith("SELECT version || ',' || cipher FROM pg_catalog.pg_stat_ssl")


@pytest.mark.parametrize("protocol", ["TLSv1", "TLSv1.1", "TLSv1.2 sslmode=disable", "", "tlsv1.2"])
def test_tls_probe_refuses_other_protocols(monkeypatch, protocol):
    fake = FakeDocker()
    target = owned_target(monkeypatch, fake)
    with pytest.raises(ContractError):
        target.tls_probe(protocol)
    assert fake.calls == []


@pytest.mark.parametrize("output", ["", "TLSv1.3,TLS_AES_256_GCM_SHA384", "TLSv1.2,", "TLSv1.2,a b",
                                    "TLSv1.2,ECDHE;rm"])
def test_tls_probe_rejects_unencrypted_or_odd_results(monkeypatch, output):
    target = owned_target(monkeypatch, FakeDocker(lambda args, stdin: output))
    with pytest.raises(RuntimeError, match="encrypted session"):
        target.tls_probe("TLSv1.2")


@pytest.mark.parametrize("cipher", ["ALL:!aNULL", "x;rm -rf /", "", "ecdhe-rsa-aes128-gcm-sha256",
                                    "A" * 70, "-cipher", "AES128 SHA", "DEFAULT@SECLEVEL=0"])
def test_tls_cipher_check_refuses_anything_but_one_cipher_name(monkeypatch, cipher):
    fake = FakeDocker()
    target = owned_target(monkeypatch, fake)
    with pytest.raises(ContractError):
        target.tls_accepts_cipher(cipher)
    assert fake.calls == []


def test_tls_cipher_check_is_one_argv_item_and_returns_only_a_bool(monkeypatch):
    def handler(args, stdin):
        if "ECDHE-RSA-AES256-SHA384" in args:
            raise RuntimeError("Docker exec failed: handshake failure " + FAKE_KEY)
        return "CONNECTION ESTABLISHED"
    fake = FakeDocker(handler)
    target = owned_target(monkeypatch, fake)
    assert target.tls_accepts_cipher("ECDHE-RSA-AES128-GCM-SHA256") is True
    assert target.tls_accepts_cipher("ECDHE-RSA-AES256-SHA384") is False
    args, stdin = fake.calls[0]
    assert args == ("exec", "-i", target.name, "openssl", "s_client", "-connect", "127.0.0.1:5432",
                    "-starttls", "postgres", "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-brief")
    assert stdin == ""


@pytest.mark.parametrize("method,args", [("enable_tls", ()), ("tls_probe", ()),
                                         ("tls_accepts_cipher", ("ECDHE-RSA-AES128-GCM-SHA256",))])
def test_tls_methods_require_an_owned_container(monkeypatch, method, args):
    fake = FakeDocker()
    monkeypatch.setattr(runtime_module, "docker", fake)
    target = DisposablePostgres(image="unused")
    with pytest.raises(RuntimeError, match="not owned"):
        getattr(target, method)(*args)
    assert fake.calls == []
