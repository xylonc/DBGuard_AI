#!/usr/bin/env python3
"""Build the pinned PostgreSQL 17 + pgaudit sandbox image and print its image ID.

    python3 scripts/build_sandbox_image.py            # build, tag, verify against the record
    python3 scripts/build_sandbox_image.py --record   # build, tag, write the ID into the record

The Dockerfile pins the base image by digest and pgaudit by exact package version.
Network is used only here, at build time (apt). The runtime
(services/sandbox_poc/runtime.py) refuses to start the tagged image unless its local
image ID equals the one recorded in catalog/images/sandbox/pg17-pgaudit.json for this
platform, so a rebuild that changes the ID must be re-recorded and reviewed in a PR.

The build-time check container runs with --network none and is removed afterwards.
No arguments are passed through to docker: the tag, Dockerfile and context are fixed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = ROOT / "services/sandbox_poc/images/pg17-pgaudit"
DOCKERFILE = CONTEXT / "Dockerfile"
RECORD = ROOT / "catalog/images/sandbox/pg17-pgaudit.json"
REPOSITORY = "dbguard/sandbox-pg17"


def pinned_inputs(text: str) -> tuple[str, str]:
    """(base image reference, pgaudit package version) from the Dockerfile; both must be pinned."""
    base = re.search(r"^FROM (postgres:17-bookworm@sha256:[0-9a-f]{64})\s*$", text, re.M)
    version = re.search(r"^ARG PGAUDIT_VERSION=([0-9][0-9A-Za-z.+~-]*)\s*$", text, re.M)
    if not base or not version:
        raise SystemExit("Dockerfile must pin the base by digest and PGAUDIT_VERSION exactly")
    return base.group(1), version.group(1)


def tag_for(version: str) -> str:
    # Docker tags allow [A-Za-z0-9_.-]; Debian versions may contain '+' and '~'.
    return f"{REPOSITORY}:pgaudit-{re.sub(r'[^A-Za-z0-9_.-]', '-', version)}"


def run(*args: str) -> str:
    result = subprocess.run(list(args), capture_output=True, text=True)
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(f"{args[0]} {args[1]} failed")
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--record", action="store_true",
                        help="write the built image ID for this platform into the pin record")
    args = parser.parse_args()

    text = DOCKERFILE.read_text()
    base, version = pinned_inputs(text)
    tag = tag_for(version)
    # Fixed argument list: no build args, no pass-through. Attestations are disabled so
    # the image ID is the plain image manifest digest the runtime inspects.
    run("docker", "build", "--provenance=false", "--sbom=false",
        "--tag", tag, "--file", str(DOCKERFILE), str(CONTEXT))
    image_id, platform = run("docker", "image", "inspect", "--format",
                             "{{.Id}} {{.Os}}/{{.Architecture}}", tag).split()

    # Offline self-check of the installed versions (no network, removed afterwards).
    probe = run("docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "--user", "postgres", image_id, "sh", "-c",
                "dpkg-query -W -f='${Version}\\n' postgresql-17 postgresql-17-pgaudit; "
                "sed -n \"s/^default_version = '\\(.*\\)'/\\1/p\" "
                "/usr/share/postgresql/17/extension/pgaudit.control")
    lines = probe.splitlines() + [""] * 3
    pg_version, pgaudit_version, extension_version = lines[0], lines[1], lines[2]
    if pgaudit_version != version:
        raise SystemExit(f"Installed pgaudit {pgaudit_version!r} differs from pinned {version!r}")

    record = json.loads(RECORD.read_text()) if RECORD.is_file() else {}
    recorded = (record.get("image_ids") or {}).get(platform)
    print(f"tag:       {tag}")
    print(f"platform:  {platform}")
    print(f"image_id:  {image_id}")
    print(f"base:      {base}")
    print(f"postgres:  {pg_version}")
    print(f"pgaudit:   {pgaudit_version} (extension {extension_version})")

    if args.record:
        record.update({
            "schema": 1,
            "name": "pg17-pgaudit",
            "tag": tag,
            "dockerfile": str(DOCKERFILE.relative_to(ROOT)),
            "dockerfile_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "base_image": base,
            "postgresql_package_version": pg_version,
            "pgaudit_package": "postgresql-17-pgaudit",
            "pgaudit_package_version": pgaudit_version,
            "pgaudit_extension_version": extension_version,
            "preloaded_by_default": [],
        })
        record.setdefault("image_ids", {})[platform] = image_id
        record["image_ids"] = dict(sorted(record["image_ids"].items()))
        RECORD.parent.mkdir(parents=True, exist_ok=True)
        RECORD.write_text(json.dumps(record, indent=2) + "\n")
        print(f"recorded:  {RECORD.relative_to(ROOT)}")
        return 0
    if recorded != image_id:
        print(f"MISMATCH: record pins {recorded or 'nothing'} for {platform}; the runtime will refuse "
              "this image until it is re-recorded (--record) and reviewed", file=sys.stderr)
        return 1
    print("matches:   pinned record")
    return 0


if __name__ == "__main__":
    sys.exit(main())
