"""Reconstruction and exact semantic rollback for the supported file sources."""
from __future__ import annotations

from .runtime import DATA
from .shared import ContractError

FILES = (f"{DATA}/postgresql.conf", f"{DATA}/postgresql.auto.conf")
FIELDS = ("setting", "source", "sourcefile", "context", "pending_restart")


def setting_rows(snapshot: dict) -> dict:
    return {r["name"]: r for r in snapshot["baseline"].get("settings") or []}


def signature(snapshot: dict, names: list[str]) -> dict:
    settings = setting_rows(snapshot)
    files = snapshot["baseline"].get("file_settings")
    if files is None:
        raise ContractError("File-setting evidence is missing")
    return {
        "settings": {name: {key: settings[name].get(key) for key in FIELDS} for name in names},
        # ALTER SYSTEM may rewrite line numbers/comments; preserve values,
        # source paths, precedence and validity, not formatting of auto.conf.
        "file_settings": sorted(
            [{k: r.get(k) for k in ("name", "setting", "sourcefile", "applied", "error")}
             for r in files if r.get("name") in names],
            key=lambda r: (r["name"], r["sourcefile"], r["setting"])),
    }


def reconstruction_plan(snapshot: dict, specs: list[dict]) -> dict:
    names = [s["check"]["setting_name"] for s in specs if "check" in s]
    rows = setting_rows(snapshot)
    if not set(names) <= rows.keys():
        raise ContractError("Missing setting provenance for the spec set")
    files = snapshot["baseline"].get("file_settings")
    if files is None:
        raise ContractError("File-setting evidence is required")
    if snapshot["baseline"].get("gaps"):
        raise ContractError("The first milestone requires an ungapped source snapshot")
    selected = [r for r in files if r.get("name") in names]
    seen = set()
    for entry in selected:
        key = (entry.get("sourcefile"), entry["name"])
        if key in seen or key[0] not in FILES or entry.get("error"):
            raise ContractError("Unsupported, duplicate or invalid configuration entry")
        seen.add(key)
        value = entry.get("setting")
        if not isinstance(value, str) or any(c in value for c in "\n\r\x00"):
            raise ContractError("Unsupported configuration value")
    for name in names:
        row = rows[name]
        if row.get("sanitised") or row.get("pending_restart") is not False:
            raise ContractError(f"Incomplete or pending-restart state: {name}")
        if row.get("context") in ("postmaster", "internal"):
            raise ContractError(f"Restart/internal setting is unsupported in this milestone: {name}")
        if row.get("source") == "default":
            if row.get("sourcefile") is not None or any(e["name"] == name for e in selected):
                raise ContractError(f"Inconsistent default provenance: {name}")
        elif row.get("source") == "configuration file":
            if row.get("sourcefile") not in FILES or (row["sourcefile"], name) not in seen:
                raise ContractError(f"Missing/unsupported file provenance: {name}")
        else:
            raise ContractError(f"Unsupported configuration source: {name}")
    return {"names": names, "entries": selected,
            "expected": {name: rows[name]["setting"] for name in names},
            "signature": signature(snapshot, names)}


def reconstruct(runtime, plan: dict) -> None:
    for filename in FILES:
        entries = [r for r in plan["entries"] if r["sourcefile"] == filename]
        lines = ["\n# DBGuard local POC reconstruction"]
        for entry in entries:
            value = entry["setting"].replace("\\", "\\\\").replace("'", "''")
            lines.append(f"{entry['name']} = '{value}'")
        runtime.write_config(filename.rsplit("/", 1)[1], "\n".join(lines) + "\n")
    runtime.activate(plan["expected"])


def rollback_sql(snapshot: dict) -> str:
    row = setting_rows(snapshot)["log_connections"]
    if row["sourcefile"] == FILES[1]:
        # Restore the original textual file value, not just its effective alias.
        original = next(r["setting"] for r in snapshot["baseline"]["file_settings"]
                        if r["name"] == "log_connections" and r["sourcefile"] == FILES[1])
        literal = original.replace("'", "''")
        command = f"ALTER SYSTEM SET log_connections = '{literal}';"
    else:
        command = "ALTER SYSTEM RESET log_connections;"
    return command + "\nSELECT pg_reload_conf();"
