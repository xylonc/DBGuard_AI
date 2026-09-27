"""Workbook intake using Xylon's parser; unknown controls remain manual drafts."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import zipfile
import yaml
from .shared import ROOT, ContractError, SpecEngine


def local_root():
    p = Path(os.environ.get("DBGUARD_CATALOG_DIR", ".demo/benchmarks"))
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    return p


def paths(benchmark_id):
    if not __import__("re").fullmatch(r"[a-z0-9]+(?:-[a-z0-9.]+)+", benchmark_id):
        raise ContractError("Invalid benchmark ID")
    specs = ROOT / "catalog/specs" / benchmark_id
    records = ROOT / "catalog/benchmarks" / benchmark_id / "records.json"
    if specs.is_dir() and records.is_file():
        return specs, records
    directory = local_root() / benchmark_id
    if not (directory / "approval.json").is_file():
        raise ContractError("Benchmark specs are not installed or approved")
    approval = json.loads((directory / "approval.json").read_text())
    engine = SpecEngine.load(directory / "specs", directory / "records.json")
    if engine.spec_set_hash != approval["spec_set_hash"]:
        raise ContractError("Approved benchmark content changed; review a new release")
    return directory / "specs", directory / "records.json"


def import_workbook(data):
    from scripts.parse_cis_workbook import parse_workbook
    from app.services.spec_engine import RecordsIndex

    if len(data) > 20 * 1024 * 1024:
        raise ContractError("Workbook exceeds 20 MB")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if sum(i.file_size for i in z.infolist()) > 100 * 1024 * 1024:
            raise ContractError("Expanded workbook exceeds 100 MB")
    sha = hashlib.sha256(data).hexdigest()
    identity = "cis-pg17-v1.1.0-import-" + sha[:12]
    directory = local_root() / identity
    if (directory / "receipt.json").exists():
        receipt = json.loads((directory / "receipt.json").read_text())
        if (directory / "approval.json").exists():
            receipt.update(
                status="APPROVED",
                approval=json.loads((directory / "approval.json").read_text()),
            )
        return receipt
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp) / "source.xlsx"
        source.write_bytes(data)
        output = Path(temp) / "records.json"
        parse_workbook(str(source), str(output))
        records = json.loads(output.read_text())
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / "specs").mkdir(exist_ok=True)
    (directory / "records.json").write_text(json.dumps(records, indent=2))
    index = RecordsIndex.load(directory / "records.json")
    known = SpecEngine.load(
        ROOT / "catalog/specs/cis-pg17-v1.1.0",
        ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json",
    )
    extra = yaml.safe_load(
        (ROOT / "catalog/specs-examples/logging_collector.yaml").read_text()
    )
    # Example control is validated against the same benchmark evidence before reuse.
    extra_engine = SpecEngine([extra], known.records)
    known_by_hash = {
        s["ref"]["source_sha256"]: s for s in [*known.specs, *extra_engine.specs]
    }
    specs = []
    for record in records["records"]:
        existing = known_by_hash.get(record["source_sha256"])
        if existing:
            spec = copy.deepcopy(existing)
        else:
            spec = {
                "schema_version": 1,
                "authored_by": "agent",
                "tier": (
                    "manual_checklist"
                    if record["assessment_status"] == "Manual"
                    else "needs_capability"
                ),
                "reason": "No matching reviewed executable spec. DBA review or upstream capability implementation is required.",
                "ref": {
                    "benchmark": records["benchmark"],
                    "benchmark_version": records["benchmark_version"],
                    "pg_major": 17,
                    "recommendation": record["recommendation"],
                    "title": record["title"],
                    "source_sha256": record["source_sha256"],
                },
            }
        spec["spec_id"] = identity + ":" + record["recommendation"]
        specs.append(spec)
    engine = SpecEngine(specs, index)
    for i, spec in enumerate(specs):
        (directory / "specs" / f"{i:04d}.yaml").write_text(
            yaml.safe_dump(spec, sort_keys=False)
        )
    (directory / "checks.json").write_text(engine.manifest_text)
    receipt = {
        "benchmark_id": identity,
        "source_sha256": sha,
        "spec_set_hash": engine.spec_set_hash,
        "status": "DRAFT",
        "controls": len(specs),
        "automated": sum(s["tier"] == "automated" for s in specs),
        "manual_or_capability": sum(s["tier"] != "automated" for s in specs),
        "scope": "CIS PostgreSQL 17 v1.1.0 Combined Profiles format. Exact matching reviewed specs reused; other controls explicitly need review/capability.",
    }
    (directory / "receipt.json").write_text(json.dumps(receipt, indent=2))
    return receipt


def package(identity):
    if not __import__("re").fullmatch(
        r"cis-pg17-v1\.1\.0-import-[a-f0-9]{12}", identity
    ):
        raise ContractError("Invalid imported benchmark ID")
    directory = local_root() / identity
    if not (directory / "receipt.json").is_file():
        raise ContractError("Imported benchmark not found")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in [
            directory / "records.json",
            directory / "checks.json",
            directory / "receipt.json",
            *sorted((directory / "specs").glob("*.yaml")),
        ]:
            z.write(p, str(p.relative_to(directory)))
        for name in ("dbguard-collect.sh", "collect.sql"):
            z.write(ROOT / "collector" / name, name)
        z.writestr(
            "README.txt",
            "Review all specs before approval. Unknown controls remain manual or need capability.\nRun: bash dbguard-collect.sh -m checks.json -t YOUR_TARGET_ID -o snapshot.json\nConfigure standard PostgreSQL connection environment locally; never target the DBGuard registry.\nUpload snapshot.json and use the exact benchmark_id from receipt.json.\n",
        )
    return buf.getvalue()
