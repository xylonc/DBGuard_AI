"""Content-addressed, file-backed store for UI-created policy profiles.

Layout (one directory per benchmark, like the snapshot store):

    <storage_dir>/<benchmark_id>/<sha256>.yaml     immutable profile bytes
    <storage_dir>/<benchmark_id>/log.jsonl         append-only draft/approval log

A profile is addressed by the SHA-256 of its exact bytes (``profile_ref``); that
is the same value the assessment report and sandbox runs pin
(``PolicyProfile.sha256``). Nothing is ever rewritten:

- ``create_draft`` writes a new object with ``approved_by: null``. It takes no
  approver argument, so a draft can never be created approved.
- ``approve(profile_ref, approver_name)`` reads a draft, sets the approver's name
  and the UTC time, writes the result as a NEW object (new hash) and logs the
  approval. The draft stays as it was. An approved profile cannot be approved or
  edited again; an edit is a new draft (``create_draft``).
- A store object is only treated as approved when the log has the matching
  approval entry, so a file dropped into the directory with ``approved_by`` set
  is refused rather than trusted.
- The repository profile ``catalog/policies/<benchmark>/reference.yaml`` is a
  read-only seed: it is listed and loadable, never written. Its approval is
  whatever the file says (only a named human edits that file).

Approval is a human action through the trusted API only. It is not exposed on
the HERMES MCP surface and takes no model input; see services/sandbox_poc/router.py.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import threading
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import yaml

from app.services.spec_engine.policy import (
    APPROVAL_AUTH,
    PolicyProfile,
    PolicyProfileError,
    approver_name_error,
    default_profile_path,
    parse_profile,
    profile_value_errors,
)
from app.services.spec_engine.records import RecordsIndex

PROFILE_REF_RE = re.compile(r"[0-9a-f]{64}")
_LOCK = threading.Lock()


class ProfileStoreError(ValueError):
    """Invalid request to the profile store (bad content, state or approver)."""


class ProfileNotFoundError(LookupError):
    pass


def validate_approver_name(name: Any) -> str:
    problem = approver_name_error(name)
    if problem is not None:
        raise ProfileStoreError(problem)
    return name.strip()


def _dump(doc: dict) -> bytes:
    return yaml.safe_dump(doc, sort_keys=True, allow_unicode=True, default_flow_style=False).encode("utf-8")


class PolicyProfileStore:
    def __init__(self, storage_dir: str | Path, records: RecordsIndex, specs: list[dict],
                 seed_path: Path | None = None):
        self.records = records
        self.specs = specs
        self.root = Path(storage_dir).resolve() / records.benchmark_id
        self.seed_path = Path(seed_path) if seed_path is not None else default_profile_path(records.benchmark_id)

    # ---- reading ----------------------------------------------------------------

    def _parse(self, data: bytes, source: str) -> PolicyProfile:
        try:
            profile = parse_profile(data, self.records, source)
        except PolicyProfileError as exc:
            raise ProfileStoreError(str(exc)) from exc
        errors = profile_value_errors(profile, self.specs, strict=True)
        if errors:
            raise ProfileStoreError(f"{source}: " + "; ".join(errors))
        return profile

    def _log(self) -> list[dict]:
        path = self.root / "log.jsonl"
        if not path.is_file():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def _seed(self) -> tuple[bytes, PolicyProfile] | None:
        if not self.seed_path.is_file():
            return None
        data = self.seed_path.read_bytes()
        return data, self._parse(data, "seed:" + self.seed_path.name)

    def _approval_entry(self, ref: str) -> dict | None:
        return next((e for e in self._log() if e.get("event") == "approved" and e.get("sha256") == ref), None)

    def get(self, profile_ref: str) -> PolicyProfile:
        """The profile with this exact hash (store object or the seed)."""
        if not isinstance(profile_ref, str) or not PROFILE_REF_RE.fullmatch(profile_ref):
            raise ProfileNotFoundError(profile_ref)
        seed = self._seed()
        if seed is not None and seed[1].sha256 == profile_ref:
            return seed[1]
        path = self.root / f"{profile_ref}.yaml"
        if not path.is_file():
            raise ProfileNotFoundError(profile_ref)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != profile_ref:
            raise ProfileStoreError("Stored profile content does not match its hash")
        profile = self._parse(data, f"store:{profile_ref}")
        if profile.approved:
            entry = self._approval_entry(profile_ref)
            if (entry is None or entry.get("approved_by") != profile.approved_by
                    or entry.get("approved_at") != profile.approved_at):
                raise ProfileStoreError("Approved profile has no matching approval record")
        return profile

    def source(self, profile: PolicyProfile) -> str:
        seed = self._seed()
        return "seed" if seed is not None and seed[1].sha256 == profile.sha256 else "store"

    def summary(self, profile: PolicyProfile, source: str) -> dict:
        return {"profile_ref": profile.sha256, "profile_id": profile.profile_id,
                "benchmark": profile.benchmark, "source": source,
                "status": "approved" if profile.approved else "draft",
                "approved_by": profile.approved_by, "approved_at": profile.approved_at,
                "approval_auth": APPROVAL_AUTH,
                "value_count": len(profile.values), "fix_count": len(profile.fixes),
                "has_connection_limits": profile.connection_limits is not None}

    def list(self) -> list[dict]:
        items = []
        seed = self._seed()
        if seed is not None:
            items.append(self.summary(seed[1], "seed"))
        if self.root.is_dir():
            for path in sorted(self.root.glob("*.yaml")):
                if PROFILE_REF_RE.fullmatch(path.stem):
                    try:
                        items.append(self.summary(self.get(path.stem), "store"))
                    except (ProfileStoreError, ProfileNotFoundError):
                        continue  # refused content is never listed as usable
        return items

    @staticmethod
    def document(profile: PolicyProfile) -> dict:
        """The profile content for display (no secrets are ever stored in a profile)."""
        doc = {"profile_id": profile.profile_id, "benchmark": profile.benchmark,
               "approved_by": profile.approved_by, "approved_at": profile.approved_at,
               "values": profile.values}
        if profile.fixes:
            doc["fixes"] = profile.fixes
        if profile.connection_limits is not None:
            doc["connection_limits"] = profile.connection_limits
        return doc

    # ---- writing ----------------------------------------------------------------

    def _write(self, data: bytes) -> str:
        ref = hashlib.sha256(data).hexdigest()
        self.root.mkdir(parents=True, exist_ok=True)
        destination = self.root / f"{ref}.yaml"
        if not destination.exists():
            with NamedTemporaryFile(mode="wb", dir=self.root, prefix=f".{ref}-", suffix=".tmp",
                                    delete=False) as temporary:
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)
            os.replace(temporary_path, destination)
        return ref

    def _append_log(self, entry: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        with open(self.root / "log.jsonl", "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def create_draft(self, *, profile_id: str, values: dict, fixes: dict | None = None,
                     connection_limits: dict | None = None, based_on: str | None = None) -> PolicyProfile:
        """Validate and store a new draft. There is no way to pass an approver here."""
        doc: dict[str, Any] = {"profile_id": profile_id, "benchmark": self.records.benchmark_id,
                               "approved_by": None, "approved_at": None, "values": values or {}}
        if fixes:
            doc["fixes"] = fixes
        if connection_limits is not None:
            doc["connection_limits"] = connection_limits
        if based_on is not None:
            self.get(based_on)  # must exist; the draft records where it came from in the log
        data = _dump(doc)
        profile = self._parse(data, "draft")
        with _LOCK:
            ref = self._write(data)
            self._append_log({"event": "draft_created", "sha256": ref, "profile_id": profile.profile_id,
                              "based_on": based_on,
                              "at": _dt.datetime.now(_dt.timezone.utc).isoformat()})
        return self.get(ref)

    def approve(self, profile_ref: str, approver_name: str) -> PolicyProfile:
        """Record a named human's approval as a new, hash-pinned approved profile."""
        name = validate_approver_name(approver_name)
        draft = self.get(profile_ref)
        if draft.approved:
            raise ProfileStoreError("Profile is already approved; edit it as a new draft")
        approved_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
        doc = self.document(draft)
        doc.update(approved_by=name, approved_at=approved_at)
        data = _dump(doc)
        self._parse(data, "approval")
        with _LOCK:
            ref = hashlib.sha256(data).hexdigest()
            # Log first: an object without its approval entry is refused, never trusted.
            self._append_log({"event": "approved", "sha256": ref, "draft_sha256": profile_ref,
                              "profile_id": draft.profile_id, "approved_by": name, "approved_at": approved_at})
            self._write(data)
        return self.get(ref)
