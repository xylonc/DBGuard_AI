#!/usr/bin/env python3
"""Pipeline runner: manifest builder -> collector -> assessment engine.

This module runs the three components as subprocesses via their real entry points,
testing the seams between them. It does NOT call Python functions directly.
"""

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _libpq_env() -> dict:
    """Build libpq environment from PG_TARGET_URL."""
    url = os.environ.get("PG_TARGET_URL")
    if not url:
        raise RuntimeError("PG_TARGET_URL is not set")
    from urllib.parse import urlparse
    parsed = urlparse(url)
    env = os.environ.copy()
    env["PGHOST"] = str(parsed.hostname)
    env["PGPORT"] = str(parsed.port or 5432)
    env["PGUSER"] = str(parsed.username)
    env["PGPASSWORD"] = str(parsed.password or "")
    env["PGDATABASE"] = str(parsed.path.lstrip("/") or "postgres")
    return env


def run_pipeline(spec_dir: Path, workdir: Path) -> Tuple[Path, Path, dict]:
    """Run the full pipeline: manifest builder -> collector -> assessment.
    
    Args:
        spec_dir: Directory containing .yaml spec files
        workdir: Working directory for output files
        
    Returns:
        Tuple of (manifest_path, snapshot_path, report_dict)
        
    Raises:
        RuntimeError: If any subprocess fails or PG_TARGET_URL not set
    """
    # Validate workdir exists
    workdir.mkdir(parents=True, exist_ok=True)
    
    # Step 1: Build manifest
    manifest_path = workdir / "manifest.json"
    result = subprocess.run(
        ["uv", "run", "python", str(REPO_ROOT / "scripts" / "build_check_manifest.py"),
         "--specs", str(spec_dir), "--out", str(manifest_path)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT)
    )
    if result.returncode != 0:
        raise RuntimeError(f"Manifest builder failed (exit {result.returncode}):\n{result.stderr}")
    
    # Step 2: Run collector
    snapshot_path = workdir / "snapshot.json"
    result = subprocess.run(
        ["bash", str(REPO_ROOT / "collector" / "dbguard-collect.sh"),
         "-m", str(manifest_path), "-o", str(snapshot_path)],
        capture_output=True,
        text=True,
        env=_libpq_env()
    )
    if result.returncode != 0:
        raise RuntimeError(f"Collector failed (exit {result.returncode}):\n{result.stderr}")
    
    # Step 3: Run assessment
    records_path = REPO_ROOT / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json"
    result = subprocess.run(
        ["uv", "run", "python", str(REPO_ROOT / "scripts" / "assess.py"),
         "--specs", str(spec_dir), "--records", str(records_path), "--snapshot", str(snapshot_path)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT)
    )
    if result.returncode != 0:
        raise RuntimeError(f"Assessment failed (exit {result.returncode}):\n{result.stderr}")
    
    # Parse report
    report = json.loads(result.stdout)
    
    return manifest_path, snapshot_path, report


def compute_file_hash(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    return hashlib.sha256(filepath.read_bytes()).hexdigest()
