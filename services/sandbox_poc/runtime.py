"""Docker access restricted to freshly created, run-labelled containers.

No target DSN, existing container ID, host port, network or persistent volume
is accepted. DATABASE_URL is never used by this execution layer.
"""
from __future__ import annotations

import json
import re
import os
import secrets
import subprocess
import time
import uuid

from .shared import ROOT, ContractError

DATA = "/var/lib/postgresql/data"
LABEL = "dbguard.sandbox-poc.run"
# The stock image has no pgaudit; tests that need a server without it name it explicitly.
STOCK_IMAGE = "postgres:17-bookworm"
# Pin records for locally built sandbox images (scripts/build_sandbox_image.py). A tag
# listed in a record only starts if its local image ID equals the one pinned there.
PINNED_IMAGES_DIR = ROOT / "catalog/images/sandbox"
# Default sandbox image (W2B Gate 2 ruling 4): the pinned PG17 image with pgaudit,
# switched after every live suite passed on it. Nothing is preloaded by default.
DEFAULT_IMAGE = json.loads((PINNED_IMAGES_DIR / "pg17-pgaudit.json").read_text())["tag"]

# Reviewed postmaster-context settings the sandbox may reconstruct, change and restart
# for (see provenance.py, which re-exports this set). activate() restarts only when
# every pending_restart setting is in this set. shared_preload_libraries: W2B gate 1,
# ruling 3 (preload fixes for CIS 3.2 and 5.6); restart() detects a failed start.
RESTART_SETTINGS = frozenset({"logging_collector", "listen_addresses", "shared_preload_libraries"})

# Sandbox-only TLS for the CIS 6.10 rehearsal (W2B gate 1, ruling 4). The throwaway key
# and certificate live in the data directory tmpfs of this run-owned container and are
# destroyed with it. Every command and config line below is a constant: no caller value
# reaches the shell, and the key is never read back, logged or returned.
TLS_DIR = DATA + "/dbguard_tls"
TLS_CERT = TLS_DIR + "/server.crt"
TLS_KEY = TLS_DIR + "/server.key"
TLS_GENERATE = ("umask 077 && mkdir -p " + TLS_DIR + " && openssl req -x509 -newkey rsa:2048 -noenc "
                "-subj /CN=localhost -days 1 -keyout " + TLS_KEY + " -out " + TLS_CERT + " >/dev/null 2>&1")
TLS_CONFIG = ("\n# DBGuard sandbox-only TLS (throwaway self-signed certificate, never leaves this container)\n"
              f"ssl_cert_file = '{TLS_CERT}'\nssl_key_file = '{TLS_KEY}'\nssl = 'on'\n")
TLS_PROTOCOLS = frozenset({"TLSv1.2", "TLSv1.3"})
CIPHER_NAME = re.compile(r"[A-Z0-9][A-Z0-9_-]{2,63}")

# Startup failures recognised in the server log after a controlled restart. Connection
# FATALs raised while the server is starting or stopping are expected and ignored.
EXPECTED_FATALS = ("the database system is starting up", "the database system is shutting down",
                   "the database system is not yet accepting connections",
                   "terminating connection due to administrator command")
PRELOAD_FAILURE = re.compile(r'FATAL:\s+could not (?:access file|load library) "([A-Za-z0-9_$./-]{1,128})"')


# Task 2 terminal screenshots: the only files written for evidence, one per fixed stage.
# Constant argv (tee to a fixed path, its echo discarded); no shell, no caller value.
EVIDENCE_SQL_PREFIX = "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;\n"
EVIDENCE_SQL_COMMANDS = {
    "before": ("tee", "/var/run/postgresql/dbguard-before.sql"),
    "after": ("tee", "/var/run/postgresql/dbguard-after.sql"),
    "rollback": ("tee", "/var/run/postgresql/dbguard-rollback.sql"),
}


class SandboxStartError(RuntimeError):
    """PostgreSQL did not come back after a controlled restart of the sandbox."""


def sandbox_image(image: str | None = None) -> str:
    """Explicit image, else DBGUARD_POSTGRES_IMAGE, else the pinned pgaudit image (Gate 2 ruling 4)."""
    return image or os.environ.get("DBGUARD_POSTGRES_IMAGE") or DEFAULT_IMAGE


def pinned_image_ids(image: str) -> dict[str, str] | None:
    """Platform -> pinned image ID when image is a recorded sandbox tag, else None."""
    for path in sorted(PINNED_IMAGES_DIR.glob("*.json")):
        record = json.loads(path.read_text())
        if record.get("tag") == image:
            return dict(record.get("image_ids") or {})
    return None


def container_stderr(name: str) -> str:
    """PostgreSQL's server log (container stderr) of a run-owned container; never returned to callers."""
    result = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("Docker logs failed")
    return result.stderr


def docker(*args: str, stdin: str | None = None, timeout: int = 60) -> str:
    if args and args[0] == "run" and os.environ.get("DBGUARD_DEMO_OWNER"):
        args = ("run", "--label", "dbguard.demo.owner=" + os.environ["DBGUARD_DEMO_OWNER"], *args[1:])
    result = subprocess.run(["docker", *args], input=stdin, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


class DisposablePostgres:
    def __init__(self, image: str | None = None):
        self.run_id = uuid.uuid4().hex
        self.name = f"dbguard-poc-{self.run_id}"
        self.image = sandbox_image(image)
        self.image_id = None
        self.started = False

    def start(self) -> None:
        image_id, platform = docker("image", "inspect", "--format", "{{.Id}} {{.Os}}/{{.Architecture}}",
                                    self.image).split()
        pinned = pinned_image_ids(self.image)
        if pinned is not None and pinned.get(platform) != image_id:
            raise ContractError(f"Sandbox image {self.image} does not match its pinned image ID for "
                                f"{platform}; rebuild and re-record it with scripts/build_sandbox_image.py")
        self.image_id = image_id
        # Register ownership before creation so cleanup covers partial failures.
        self.started = True
        docker("run", "-d", "--name", self.name, "--label", f"{LABEL}={self.run_id}",
               "--network", "none", "--read-only", "--user", "postgres",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
               "--memory", "1g", "--cpus", "1", "--pids-limit", "128",
               "--tmpfs", f"{DATA}:rw,uid=999,gid=999,mode=0700,size=512m",
               "--tmpfs", "/var/run/postgresql:rw,uid=999,gid=999,mode=0775",
               "-e", "POSTGRES_USER=dbguard_poc", "-e", "POSTGRES_DB=dbguard_sandbox",
               "-e", f"POSTGRES_PASSWORD={secrets.token_hex(24)}", self.image_id, "sh", "-c",
               'trap "exit 0" TERM INT; while :; do docker-entrypoint.sh postgres & child=$!; wait "$child"; sleep 0.2; done')
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                if self.sql("SELECT 1;") == "1":
                    # initdb's temporary server has no TCP listener. Require the
                    # final server before applying/reloading configuration.
                    if self.sql("SHOW listen_addresses;") != "":
                        break
            except RuntimeError:
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError("PostgreSQL did not become ready within 45 seconds")
        if int(self.sql("SHOW server_version_num;")) // 10000 != 17:
            raise ContractError("Sandbox image must run PostgreSQL 17")

    def _assert_owned(self) -> None:
        if not self.started:
            raise RuntimeError("Container is not owned by this active session")
        labels = json.loads(docker("inspect", "--format", "{{json .Config.Labels}}", self.name))
        if labels.get(LABEL) != self.run_id:
            raise RuntimeError("Container ownership mismatch; refusing access")

    def sql(self, script: str) -> str:
        self._assert_owned()
        # -f / stdin executes statements separately: ALTER SYSTEM cannot run in
        # the implicit transaction created by a multi-statement psql -c string.
        return docker("exec", "-i", self.name, "psql", "-X", "-qAt",
                      "-U", "dbguard_poc", "-d", "dbguard_sandbox",
                      "-v", "ON_ERROR_STOP=1", "-v", f"target_id={self.name}",
                      "-f", "-", stdin=script)

    def write_config(self, filename: str, content: str) -> None:
        self._assert_owned()
        if filename not in ("postgresql.conf", "postgresql.auto.conf"):
            raise ContractError("Unsupported configuration file")
        # Constant shell command; data only travels on stdin, never interpolation.
        command = "cat >> /var/lib/postgresql/data/postgresql.conf" if filename == "postgresql.conf" else "cat > /var/lib/postgresql/data/postgresql.auto.conf"
        docker("exec", "-i", self.name, "sh", "-c", command, stdin=content)

    def write_evidence_sql(self, stage: str, content: str) -> None:
        """Write one stage's read-only evidence SQL into this owned container (Task 2 Gate 1,
        decision 4). The destination comes from a fixed dict; the command is a constant argv
        (no shell at all); the content travels only on stdin. /var/run/postgresql is the
        container's writable tmpfs, removed with it. The content must be the reviewed file:
        read-only prefix, bounded, and free of backslashes (no psql meta-commands) and
        control characters."""
        self._assert_owned()
        command = EVIDENCE_SQL_COMMANDS.get(stage) if isinstance(stage, str) else None
        if command is None:
            raise ContractError("Unsupported evidence stage")
        if (not isinstance(content, str) or not content.startswith(EVIDENCE_SQL_PREFIX)
                or len(content.encode("utf-8")) > 64 * 1024
                or re.search(r"[\\\x00-\x09\x0b-\x1f\x7f]", content)):
            raise ContractError("Evidence SQL is outside the reviewed template")
        docker("exec", "-i", self.name, *command, stdin=content)

    def activate(self, expected: dict[str, str]) -> None:
        if self.sql("SELECT pg_reload_conf();") != "t":
            raise RuntimeError("PostgreSQL rejected reload request")
        # Postmaster settings need a controlled restart of this owned container.
        time.sleep(.15)
        pending = self.pending_restart()
        if pending:
            unreviewed = sorted(pending - RESTART_SETTINGS)
            if unreviewed:
                raise ContractError("Restart refused: settings outside the reviewed restart "
                                    "allowlist are pending a restart: " + ", ".join(unreviewed))
            self.restart()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            # Every query uses a fresh backend, including backend-context GUCs.
            if all(self._effective(name, value) for name, value in expected.items()):
                return
            time.sleep(0.1)
        raise RuntimeError("Reload did not produce expected effective values")

    def pending_restart(self) -> set[str]:
        """Names of the settings whose changed value waits for a restart (read-only query)."""
        out = self.sql("SELECT coalesce(string_agg(name, ',' ORDER BY name), '') "
                       "FROM pg_catalog.pg_settings WHERE pending_restart;")
        return {name for name in out.split(",") if name}

    def restart(self) -> None:
        """Controlled restart of PostgreSQL inside this owned, run-labelled container only.

        A server that cannot start (for example shared_preload_libraries naming a library
        that is not installed) raises SandboxStartError with a fixed message; log text is
        matched here but never returned. The caller's close() still removes the container.
        """
        self._assert_owned()
        seen = len(container_stderr(self.name).splitlines())
        # Stop only PostgreSQL. PID 1 supervises its replacement, preserving tmpfs.
        docker("exec", self.name, "pg_ctl", "-D", DATA, "-m", "fast", "-w", "stop")
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                if self.sql("SELECT 1;") == "1": return
            except RuntimeError: pass
            failure = self._start_failure(container_stderr(self.name).splitlines()[seen:])
            if failure:
                raise SandboxStartError(failure)
            time.sleep(.25)
        raise SandboxStartError("PostgreSQL did not return within 45 seconds after restart")

    @staticmethod
    def _start_failure(lines: list[str]) -> str | None:
        """A fixed description of a fatal startup error in the new log lines, if any."""
        for line in lines:
            match = PRELOAD_FAILURE.search(line)
            if match:
                return (f"PostgreSQL failed to start after restart: shared_preload_libraries names "
                        f"'{match.group(1)}', which is not installed in the sandbox image")
        for line in lines:
            if "FATAL:" in line and not any(text in line for text in EXPECTED_FATALS):
                return "PostgreSQL failed to start after restart: the server reported a fatal startup error"
        return None

    def enable_tls(self) -> None:
        """Sandbox-only TLS: throwaway self-signed key and certificate in this container's tmpfs.

        Constant commands only. The key is generated, used and destroyed inside the
        container; nothing here reads it, and failures raise fixed messages.
        """
        self._assert_owned()
        try:
            docker("exec", self.name, "sh", "-c", TLS_GENERATE)
        except RuntimeError:
            raise RuntimeError("Sandbox TLS certificate generation failed") from None
        self.write_config("postgresql.conf", TLS_CONFIG)
        self.activate({"ssl": "on", "ssl_cert_file": TLS_CERT, "ssl_key_file": TLS_KEY})

    def tls_probe(self, protocol: str = "TLSv1.2") -> dict:
        """Read-only: open one TLS connection over loopback inside the container (works with
        --network none) and return the negotiated protocol and cipher as the server saw them."""
        self._assert_owned()
        if protocol not in TLS_PROTOCOLS:
            raise ContractError("Unsupported TLS protocol version")
        conninfo = ("host=127.0.0.1 dbname=dbguard_sandbox user=dbguard_poc sslmode=require "
                    f"ssl_min_protocol_version={protocol} ssl_max_protocol_version={protocol}")
        try:
            row = docker("exec", "-i", self.name, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
                         "-d", conninfo, "-f", "-",
                         stdin="SELECT version || ',' || cipher FROM pg_catalog.pg_stat_ssl "
                               "WHERE pid = pg_catalog.pg_backend_pid() AND ssl;")
        except RuntimeError:
            raise RuntimeError(f"Sandbox {protocol} connection over loopback failed") from None
        version, _, cipher = row.partition(",")
        if version != protocol or not CIPHER_NAME.fullmatch(cipher):
            raise RuntimeError("Sandbox TLS probe did not return an encrypted session")
        return {"protocol": version, "cipher": cipher, "scope": "DISPOSABLE SANDBOX loopback",
                "run_id": self.run_id}

    def tls_accepts_cipher(self, cipher: str) -> bool:
        """Read-only: whether a TLS 1.2 handshake offering only this one cipher succeeds over
        loopback inside the container. The name is validated and passed as one argv item."""
        self._assert_owned()
        if not CIPHER_NAME.fullmatch(cipher):
            raise ContractError("Unsupported cipher name")
        try:
            docker("exec", "-i", self.name, "openssl", "s_client", "-connect", "127.0.0.1:5432",
                   "-starttls", "postgres", "-tls1_2", "-cipher", cipher, "-brief", stdin="")
        except RuntimeError:
            return False
        return True

    def _effective(self, name: str, value: str) -> bool:
        """The setting's effective value equals value, in SHOW or pg_settings.setting form.

        Expected values come in two exact forms: fix values as SHOW prints them
        ('1d', '10MB') and reconstructed/rollback values from pg_settings.setting
        ('1440' min, '10240' kB). For unitless settings both forms are identical.
        Values are compared here, never interpolated into SQL, and travel hex-encoded
        so psql/docker output trimming cannot hide leading or trailing spaces (the
        default log_line_prefix is '%m [%p] ').
        """
        if not re.fullmatch(r"[a-z_][a-z0-9_.]*", name):
            raise ContractError("Unsupported setting name")
        row = self.sql("SELECT encode(convert_to(current_setting(name), 'UTF8'), 'hex') || ',' || "
                       "encode(convert_to(setting, 'UTF8'), 'hex') FROM pg_catalog.pg_settings "
                       f"WHERE name = '{name}';")
        return value.encode("utf-8").hex() in row.split(",")

    def setting_sources(self, names: list[str]) -> dict:
        """Live pg_settings source/sourcefile for the named settings (read-only query)."""
        for name in names:
            if not re.fullmatch(r"[a-z_][a-z0-9_.]*", name):
                raise ContractError("Unsupported setting name")
        listed = ", ".join(f"'{n}'" for n in names)
        out = self.sql("SELECT coalesce(json_object_agg(name, json_build_object("
                       "'source', source, 'sourcefile', sourcefile)), '{}') "
                       f"FROM pg_catalog.pg_settings WHERE name IN ({listed});")
        return json.loads(out)

    def health(self) -> bool:
        return self.sql("SELECT 1;") == "1"

    def close(self) -> dict:
        # Label selection also finds a container created before docker run timed out.
        ids = docker("ps", "-aq", "--filter", f"label={LABEL}={self.run_id}").split()
        for cid in ids:
            docker("rm", "-f", "-v", cid)
        remaining = docker("ps", "-aq", "--filter", f"label={LABEL}={self.run_id}")
        if remaining:
            raise RuntimeError("Run-owned container remains after cleanup")
        self.started = False
        return {"run_id": self.run_id, "container": self.name, "verified": True,
                "storage": "tmpfs; no persistent volumes or run-created networks"}
