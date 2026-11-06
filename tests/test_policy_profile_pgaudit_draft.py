"""CIS 3.2 pgaudit_log_classes on the policy-profile draft path (Gate W2B ruling 2).

The router's PolicyProfileDraft (extra=forbid) and PolicyProfileStore.create_draft
accept ``pgaudit_log_classes`` and validate it with the engine's own rule
(catalog_checks.pgaudit_policy_classes_error): a non-empty list of unique items
from read, write, function, role, ddl, misc, misc_set. A draft keeps the value
through approval and is never approved by creating it. No Docker, network or model.
"""
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.services.spec_engine.catalog_checks import PGAUDIT_LOG_CLASSES

B = "cis-pg17-v1.1.0"
BAD_CLASSES = [
    [],                              # empty
    ["ddl", "ddl"],                  # repeated
    ["all"],                         # keyword, not a class
    ["none"],
    ["DDL"],                         # case matters in the policy value
    ["ddl", "-write"],               # subtraction syntax is pgaudit.log, not policy
    ["ddl", 1],                      # not a string
    ["ddl", None],
    [["ddl"]],
    "ddl,role,write",                # a string, not a list
    {"ddl": True},
]


@pytest.fixture
def tmp_store(tmp_path, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "policy_profile_storage_dir", str(tmp_path / "profiles"))
    return tmp_path / "profiles"


def _draft(**extra):
    from services.sandbox_poc.router import PolicyProfileDraft
    return PolicyProfileDraft(profile_id="site-a", values={}, **extra)


def test_draft_model_has_the_field_and_still_forbids_unknown_keys():
    from services.sandbox_poc.router import PolicyProfileDraft
    assert "pgaudit_log_classes" in PolicyProfileDraft.model_fields
    assert _draft().pgaudit_log_classes is None
    with pytest.raises(ValidationError):
        _draft(pgaudit_classes=["ddl"])  # a near-miss key is refused, not dropped


@pytest.mark.parametrize("value", [["ddl", "role", "write"], list(PGAUDIT_LOG_CLASSES), ["misc_set"]])
def test_draft_model_accepts_valid_class_lists(value):
    assert _draft(pgaudit_log_classes=value).pgaudit_log_classes == value


@pytest.mark.parametrize("value", BAD_CLASSES)
def test_draft_model_refuses_invalid_class_lists(value):
    with pytest.raises(ValidationError):
        _draft(pgaudit_log_classes=value)


def test_create_draft_stores_classes_unapproved_and_approval_keeps_them(tmp_store):
    from services.sandbox_poc import router
    created = router.create_policy_profile_draft(
        B, _draft(pgaudit_log_classes=["ddl", "role", "write"]))
    assert created["profile"]["pgaudit_log_classes"] == ["ddl", "role", "write"]
    assert created["profile"]["approved_by"] is None and created["profile"]["approved_at"] is None
    approved = router.approve_policy_profile(
        B, created["profile_ref"], router.PolicyProfileApproval(approver_name="Test Human"))
    assert approved["profile"]["pgaudit_log_classes"] == ["ddl", "role", "write"]
    assert approved["profile"]["approved_by"] == "Test Human"


def test_create_draft_without_classes_leaves_the_key_out(tmp_store):
    from services.sandbox_poc import router
    created = router.create_policy_profile_draft(B, _draft())
    assert "pgaudit_log_classes" not in created["profile"]


@pytest.mark.parametrize("value", BAD_CLASSES)
def test_store_create_draft_refuses_invalid_classes_directly(tmp_store, value):
    """The store re-validates (parse_profile), so a caller that skips the router model
    still cannot store a bad value."""
    from app.services.policy_profile_store import ProfileStoreError
    from services.sandbox_poc.router import _profile_store
    store = _profile_store(B)
    with pytest.raises(ProfileStoreError, match="pgaudit_log_classes"):
        store.create_draft(profile_id="site-a", values={}, pgaudit_log_classes=value)
    assert all(p.get("source") == "seed" for p in store.list())  # nothing was stored


def test_validate_route_checks_classes_like_create(tmp_store):
    from services.sandbox_poc import router
    good = router.validate_policy_profile_draft(B, _draft(pgaudit_log_classes=["ddl", "role", "write"]))
    assert good == {"valid": True, "errors": []}
    # nothing is stored by validation
    assert all(p.get("source") == "seed" for p in router._profile_store(B).list())


def test_create_route_maps_store_errors_to_422(tmp_store, monkeypatch):
    """A value that slips past the model (constructed without validation) is still a 422."""
    from services.sandbox_poc import router
    bad = router.PolicyProfileDraft.model_construct(profile_id="site-a", values={}, fixes=None,
                                                    connection_limits=None, based_on=None,
                                                    pgaudit_log_classes=["all"])
    with pytest.raises(HTTPException) as exc:
        router.create_policy_profile_draft(B, bad)
    assert exc.value.status_code == 422
    assert "pgaudit_log_classes" in str(exc.value.detail)
