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

from .shared import ContractError

DATA = "/var/lib/postgresql/data"
LABEL = "dbguard.sandbox-poc.run"

# Reviewed postmaster-context settings the sandbox may reconstruct, change and restart
# for (see provenance.py, which re-exports this set). activate() restarts only when
# every pending_restart setting is in this set.
RESTART_SETTINGS = frozenset({"logging_collector", "listen_addresses"})


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
        self.image = image or os.environ.get("DBGUARD_POSTGRES_IMAGE", "postgres:17-bookworm")
        self.image_id = None
        self.started = False

    def start(self) -> None:
        self.image_id = docker("image", "inspect", "--format", "{{.Id}}", self.image)
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
        """Controlled restart of PostgreSQL inside this owned, run-labelled container only."""
        self._assert_owned()
        # Stop only PostgreSQL. PID 1 supervises its replacement, preserving tmpfs.
        docker("exec", self.name, "pg_ctl", "-D", DATA, "-m", "fast", "-w", "stop")
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                if self.sql("SELECT 1;") == "1": return
            except RuntimeError: pass
            time.sleep(.25)
        raise RuntimeError("PostgreSQL did not return after restart")

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
