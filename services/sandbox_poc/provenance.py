"""Reconstruction and exact semantic rollback for the supported file sources."""
from __future__ import annotations

from .runtime import DATA, RESTART_SETTINGS
from .shared import ContractError, blocking_gaps

FILES = (f"{DATA}/postgresql.conf", f"{DATA}/postgresql.auto.conf")
FIELDS = ("setting", "source", "sourcefile", "context", "pending_restart")

# Reviewed postmaster-context settings the sandbox may reconstruct and change. The
# sandbox restarts only its own run-labelled container (runtime.activate) and talks
# to PostgreSQL over the local Unix socket with --network none, so changing either
# setting cannot cut the sandbox off:
# - logging_collector (3.1.3): moves server output into files;
# - listen_addresses (5.2): TCP/IP addresses only. Note a fix naming an address the
#   sandbox does not have (no network) makes the restarted server refuse to start
#   unless at least one listed address (e.g. localhost) can be bound.
# Every other postmaster or internal setting in a spec set stops reconstruction.
# RESTART_SETTINGS is defined in runtime.py (activate() enforces it) and imported above.


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
             for r in files if r.get("name") in names and not _shadowed_duplicate(r, files)],
            key=lambda r: (r["name"], r["sourcefile"], r["setting"])),
    }


def _shadowed_duplicate(row: dict, files: list[dict]) -> bool:
    """An unapplied, error-free line repeated LATER in the same file with the same value.

    initdb and the postgres image already write log_timezone and listen_addresses into
    postgresql.conf; reconstruction appends the source's line again (write_config
    appends to postgresql.conf), so the image line becomes an earlier duplicate.

    Rule: drop `row` only if another error-free line has the same name, sourcefile and
    value, and that line is later in the file: either it is the applied line (PostgreSQL
    applies only the last line for a name) or both are unapplied and it has the higher
    sourceline (both superseded, e.g. by postgresql.auto.conf after ALTER SYSTEM).

    Why this is safe: the file still contributes the same value from the kept line, so
    the effective value, reload, ALTER SYSTEM RESET (falls back to that same value) and
    removing either line all behave identically. Exactly one copy is always kept, so a
    superseded line still counts as "this file sets X under auto.conf". Not dropped:
    a superseded line with a DIFFERENT value, a line superseded only by another file,
    any line with an error, or a line whose order cannot be proven (no sourceline).
    Source snapshots never contain such pairs: reconstruction_plan rejects duplicate
    (file, name) entries, so this only removes image/initdb lines from sandboxes.
    """
    if row.get("applied") is not False or row.get("error"):
        return False
    line = row.get("sourceline")
    for other in files:
        if other is row or other.get("error") or not all(
                other.get(k) == row.get(k) for k in ("name", "sourcefile", "setting")):
            continue
        if other.get("applied") is True:
            return True
        later = other.get("sourceline")
        if (other.get("applied") is False and isinstance(line, int) and isinstance(later, int)
                and later > line):
            return True
    return False


def reconstruction_plan(snapshot: dict, specs: list[dict]) -> dict:
    names = [s["check"]["setting_name"] for s in specs if "check" in s and s["check"].get("kind") != "catalog"]
    rows = setting_rows(snapshot)
    if len(rows) != len(snapshot["baseline"].get("settings") or []):
        raise ContractError("Duplicate setting provenance")
    if not set(names) <= rows.keys():
        raise ContractError("Missing setting provenance for the spec set")
    files = snapshot["baseline"].get("file_settings")
    if files is None:
        raise ContractError("File-setting evidence is required")
    if blocking_gaps(snapshot):
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
        if row.get("context") == "internal" or (row.get("context") == "postmaster" and name not in RESTART_SETTINGS):
            raise ContractError(f"Restart/internal setting is unsupported in this milestone: {name}")
        if row.get("source") == "default":
            if row.get("sourcefile") is not None or any(e["name"] == name for e in selected):
                raise ContractError(f"Inconsistent default provenance: {name}")
        elif row.get("source") == "configuration file":
            if row.get("sourcefile") not in FILES or (row["sourcefile"], name) not in seen:
                raise ContractError(f"Missing/unsupported file provenance: {name}")
        else:
            raise ContractError(f"Unsupported configuration source: {name}")
    for name in names:
        connection = rows[name]
        if connection.get("sourcefile") == FILES[1]:
            original = next(e["setting"] for e in selected if e["name"] == name and e["sourcefile"] == FILES[1])
            if original != connection["setting"]:
                raise ContractError("Typed rollback requires a canonical auto.conf value; textual aliases need manual review")
    return {"names": names, "entries": selected,
            "expected": {name: rows[name]["setting"] for name in names},
            "signature": signature(snapshot, names)}


def restart_candidates(plan: dict) -> list[str]:
    """Reviewed restart settings whose source line reconstruction writes into a file."""
    written = {e["name"] for e in plan["entries"]}
    return sorted(n for n in set(plan["names"]) & RESTART_SETTINGS if n in written)


def restart_needed(plan: dict, live: dict) -> list[str]:
    """Restart-allowlisted settings whose live source/sourcefile still differs from the plan.

    A postmaster setting is re-sourced only at server start. When the written line holds
    the value the sandbox already runs (logging_collector='off' in postgresql.auto.conf vs
    the built-in default 'off'), reload reports no pending restart and pg_settings keeps
    source 'default'. Only names in RESTART_SETTINGS with a written file line qualify;
    anything else is left to the unchanged signature comparison, which fails closed.
    """
    wanted = plan["signature"]["settings"]
    return [n for n in restart_candidates(plan)
            if (live.get(n) or {}).get("source") != wanted[n]["source"]
            or (live.get(n) or {}).get("sourcefile") != wanted[n]["sourcefile"]]


def _live_sources(runtime, names: list[str]) -> dict:
    for name in names:  # Only reviewed restart settings are ever queried here.
        if name not in RESTART_SETTINGS:
            raise ContractError("Unsupported restart setting")
    return runtime.setting_sources(names)


def reconstruct(runtime, plan: dict) -> None:
    for filename in FILES:
        entries = [r for r in plan["entries"] if r["sourcefile"] == filename]
        lines = ["\n# DBGuard local POC reconstruction"]
        for entry in entries:
            value = entry["setting"].replace("\\", "\\\\").replace("'", "''")
            lines.append(f"{entry['name']} = '{value}'")
        runtime.write_config(filename.rsplit("/", 1)[1], "\n".join(lines) + "\n")
    runtime.activate(plan["expected"])
    candidates = restart_candidates(plan)
    if candidates and restart_needed(plan, _live_sources(runtime, candidates)):
        # One controlled restart of this run-owned sandbox re-sources the postmaster
        # setting. Provenance is still checked afterwards by the caller's signature
        # comparison; a remaining mismatch fails closed there.
        runtime.restart()
        runtime.activate(plan["expected"])
