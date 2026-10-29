"""Resolve the policy profile a user chose for an assessment or sandbox run.

The choice is a profile hash (``profile_ref``) passed as an API parameter. It is
resolved here, server-side, from the profile store (UI drafts/approvals plus the
read-only repository seed). Default: no profile (policy_missing). HERMES/MCP
tools never pass one, and nothing here can approve a profile.
"""
from __future__ import annotations

from app.config import settings
from app.services.policy_profile_store import PolicyProfileStore, ProfileNotFoundError, ProfileStoreError

from .shared import ContractError


def profile_store(records, specs) -> PolicyProfileStore:
    return PolicyProfileStore(settings.policy_profile_storage_dir, records, specs)


def resolve_profile(records, specs, profile_ref: str | None):
    if profile_ref is None:
        return None
    try:
        return profile_store(records, specs).get(profile_ref)
    except ProfileNotFoundError as exc:
        raise ContractError("Selected policy profile was not found") from exc
    except ProfileStoreError as exc:
        raise ContractError(f"Selected policy profile is invalid: {exc}") from exc
