"""Docker access restricted to freshly created, run-labelled containers.

No target DSN, existing container ID, host port, network or persistent volume
is accepted. DATABASE_URL is never used by this execution layer.
"""
from __future__ import annotations

import json
import secrets
import subprocess
import time
import uuid

from .shared import ContractError

DATA = "/var/lib/postgresql/data"
LABEL = "dbguard.sandbox-poc.run"


def docker(*args: str, stdin: str | None = None, timeout: int = 60) -> str:
    result = subprocess.run(["docker", *args], input=stdin, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Docker {args[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


class DisposablePostgres:
    def __init__(self, image: str = "postgres:17-bookworm"):
        self.run_id = uuid.uuid4().hex
        self.name = f"dbguard-poc-{self.run_id}"
        self.image = image
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
               "-e", f"POSTGRES_PASSWORD={secrets.token_hex(24)}", self.image_id)
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
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            # Every SHOW uses a fresh backend, including backend-context GUCs.
            if all(self.sql(f"SHOW {name};") == value for name, value in expected.items()):
                return
            time.sleep(0.1)
        raise RuntimeError("Reload did not produce expected effective values")

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
