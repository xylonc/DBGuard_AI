"""Policy-profile approval stays with a named human (CLAUDE.md, Gate 1 ruling A8).

- The committed reference profile keeps ``approved_by: null`` (only Melvin edits it).
- No code path sets a profile's ``approved_by`` from model/MCP input: the one writer is
  ``PolicyProfileStore.approve``, reached only from the UI approval route, which takes a
  profile hash and a human name and is not on the HERMES MCP surface.

Static checks are tripwires: a new writer or caller fails here and must be reviewed.
No Docker, network or model.
"""
import ast
import re
from pathlib import Path

import pytest
import yaml
from fastapi import HTTPException
from pydantic import ValidationError

from app.services.spec_engine.policy import default_profile_path, load_default_profile
from services.sandbox_poc.shared import ROOT

B = "cis-pg17-v1.1.0"
CODE_DIRS = ("backend/app", "services", "catalog", "scripts", "hermes")
APPROVAL_KEYS = {"approved_by", "approved_at", "approver", "approver_name"}
# A tool that approves (approve/approval/approver, not the read-only "approved" searches)
# or touches a policy profile.
ACTION_RE = re.compile(r"approv(?!ed_)|profile")


def _python_files():
    for folder in CODE_DIRS:
        for path in sorted((ROOT / folder).rglob("*.py")):
            if any(part in ("tests", "__pycache__", "node_modules") or part.startswith(".venv")
                   for part in path.parts):
                continue
            yield path


class _Scope(ast.NodeVisitor):
    """Collect (file, qualified function) for approved_by writes and .approve() calls."""

    def __init__(self, rel):
        self.rel, self.stack, self.writes, self.approve_calls = rel, [], set(), set()

    def where(self):
        return (self.rel, ".".join(self.stack) or "<module>")

    def _hit(self, value):
        if not (isinstance(value, ast.Constant) and value.value is None):
            self.writes.add(self.where())

    def generic_visit(self, node):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.stack.append(node.name)
            super().generic_visit(node)
            self.stack.pop()
            return
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "approved_by":
                    self._hit(value)
        if isinstance(node, ast.keyword) and node.arg == "approved_by":
            self._hit(node.value)
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Attribute) and target.attr == "approved_by":
                    self._hit(node.value)
                if (isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant)
                        and target.slice.value == "approved_by"):
                    self._hit(node.value)
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "approve"):
            self.approve_calls.add(self.where())
        super().generic_visit(node)


def _scan():
    writes, calls = set(), set()
    for path in _python_files():
        visitor = _Scope(str(path.relative_to(ROOT)))
        visitor.visit(ast.parse(path.read_text(encoding="utf-8"), str(path)))
        writes |= visitor.writes
        calls |= visitor.approve_calls
    return writes, calls


# ---------------------------------------------------------------------------
# The committed profile
# ---------------------------------------------------------------------------

def test_committed_reference_profile_keeps_approved_by_null():
    text = default_profile_path(B).read_text(encoding="utf-8")
    raw = yaml.safe_load(text)
    assert raw["approved_by"] is None and raw["approved_at"] is None
    # exactly one top-level line each, literally null (no anchors, merges or later override)
    assert re.findall(r"(?m)^approved_by:.*$", text) == ["approved_by: null"]
    assert re.findall(r"(?m)^approved_at:.*$", text) == ["approved_at: null"]
    assert "<<:" not in text and "&" not in text.split("values:")[0]
    from app.services.spec_engine import RecordsIndex
    records = RecordsIndex.load(ROOT / f"catalog/benchmarks/{B}/records.json")
    profile = load_default_profile(records)
    assert profile.approved is False and profile.approved_by is None


# ---------------------------------------------------------------------------
# Who can write approved_by
# ---------------------------------------------------------------------------

# Every non-None approved_by write in product code, reviewed. Policy-profile entries:
# approve() is the only writer of a NEW approval; document/summary/pin copy an existing
# hash-pinned value; parse_profile reads it from the pinned file bytes. The rest are the
# SQL template / knowledge-document registry (separate, human /approve endpoints).
REVIEWED_APPROVED_BY_WRITERS = {
    ("backend/app/services/policy_profile_store.py", "PolicyProfileStore.approve"),
    ("backend/app/services/policy_profile_store.py", "PolicyProfileStore.document"),
    ("backend/app/services/policy_profile_store.py", "PolicyProfileStore.summary"),
    ("backend/app/services/spec_engine/policy.py", "PolicyProfile.pin"),
    ("backend/app/services/spec_engine/policy.py", "parse_profile"),
    ("backend/app/main.py", "approve_knowledge_document"),
    ("backend/app/main.py", "approve_sql_template"),
    ("services/rag/rag_service.py", "DocumentMetadata.__init__"),
    ("services/rag/rag_service.py", "RAGService.get_applicable_documents"),
    ("services/rag/rag_service.py", "RAGService.get_document_metadata"),
    ("services/sandbox_poc/templates.py", "ApprovedTemplate.identity"),
}


def test_approved_by_writers_are_exactly_the_reviewed_set():
    writes, _ = _scan()
    assert writes == REVIEWED_APPROVED_BY_WRITERS


def test_profile_approve_is_called_only_by_the_ui_approval_route():
    _, calls = _scan()
    assert calls == {("services/sandbox_poc/router.py", "approve_policy_profile")}


def test_approve_takes_its_name_from_the_human_validator_only():
    source = (ROOT / "backend/app/services/policy_profile_store.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    approve = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "approve")
    assert [a.arg for a in approve.args.args] == ["self", "profile_ref", "approver_name"]
    first = approve.body[1] if isinstance(approve.body[0], ast.Expr) else approve.body[0]
    assert ast.unparse(first) == "name = validate_approver_name(approver_name)"
    update = next(n for n in ast.walk(approve) if isinstance(n, ast.Call)
                  and isinstance(n.func, ast.Attribute) and n.func.attr == "update")
    assert {k.arg: ast.unparse(k.value) for k in update.keywords}["approved_by"] == "name"


# ---------------------------------------------------------------------------
# HERMES / MCP surface
# ---------------------------------------------------------------------------

def _mcp_tools():
    tree = ast.parse((ROOT / "services/dbguard_mcp/server.py").read_text(encoding="utf-8"))
    tools = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and any(
                "mcp.tool" in ast.unparse(d) for d in node.decorator_list):
            tools[node.name] = node
    return tree, tools


def test_no_mcp_tool_takes_an_approval_or_a_policy_profile():
    tree, tools = _mcp_tools()
    assert tools, "MCP tools not found"
    forbidden = APPROVAL_KEYS | {"policy_profile", "policy_profile_sha256", "profile_ref", "profile",
                                 "values", "fixes"}
    for name, node in tools.items():
        params = {a.arg for a in [*node.args.args, *node.args.kwonlyargs]}
        assert not params & forbidden, (name, params & forbidden)
        assert not ACTION_RE.search(name), name
    # no request body or URL built by the MCP bridge can carry or reach an approval
    keys = {k.value for n in ast.walk(tree) if isinstance(n, ast.Dict)
            for k in n.keys if isinstance(k, ast.Constant)}
    assert not keys & (forbidden | {"policy_profile_sha256"}), keys & forbidden
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert not [s for s in strings if "policy-profiles" in s or "/approve" in s]


def test_hermes_enables_only_existing_non_approval_tools():
    _, tools = _mcp_tools()
    config = yaml.safe_load((ROOT / "hermes/config/config.yaml").read_text(encoding="utf-8"))
    text = yaml.safe_dump(config)
    assert "policy-profiles" not in text and "approve_policy" not in text
    included = config["mcp_servers"]["dbguard"]["tools"]["include"]
    assert included and set(included) <= set(tools)
    assert not [t for t in included if ACTION_RE.search(t)]


# ---------------------------------------------------------------------------
# API models: approval fields cannot be smuggled in
# ---------------------------------------------------------------------------

def test_request_models_refuse_approval_fields():
    from services.sandbox_poc.handoff import SandboxHandoff
    from services.sandbox_poc.router import PolicyProfileApproval, PolicyProfileDraft
    from services.sandbox_poc.upstream import PrepareRequest

    for key in ("approved_by", "approved_at"):
        with pytest.raises(ValidationError):
            PolicyProfileDraft(profile_id="site-a", values={}, **{key: "Melvin Loo"})
        with pytest.raises(ValidationError):
            PrepareRequest(snapshot_id="snap-abc", template_version=1, evidence_ids=["d"],
                           **{key: "Melvin Loo"})
    assert set(PolicyProfileApproval.model_fields) == {"approver_name"}
    assert not APPROVAL_KEYS & set(PolicyProfileDraft.model_fields)
    assert not APPROVAL_KEYS & set(PrepareRequest.model_fields)
    assert not APPROVAL_KEYS & set(SandboxHandoff.model_fields)
    # the handoff carries a profile only as a hash, resolved server-side
    assert "policy_profile_sha256" in SandboxHandoff.model_fields
    assert not {"values", "fixes", "policy_profile"} & set(SandboxHandoff.model_fields)


@pytest.fixture
def tmp_store(tmp_path, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "policy_profile_storage_dir", str(tmp_path / "profiles"))
    return tmp_path / "profiles"


def test_ui_routes_create_unapproved_drafts_and_refuse_non_human_approvers(tmp_store):
    from services.sandbox_poc import router
    seed_before = default_profile_path(B).read_bytes()
    values = {f"{B}:3.1.2": {"expected": ["stderr"], "fix": "stderr", "break": "csvlog"}}
    created = router.create_policy_profile_draft(B, router.PolicyProfileDraft(profile_id="site-a",
                                                                              values=values))
    assert created["profile"]["approved_by"] is None and created["profile"]["approved_at"] is None
    ref = created["profile_ref"]
    for name in ("HERMES", "Claude", "LLM reviewer", "gpt-4o", "dbguard agent", "  "):
        with pytest.raises(HTTPException) as exc:
            router.approve_policy_profile(B, ref, router.PolicyProfileApproval(approver_name=name))
        assert exc.value.status_code == 422, name
    approved = router.approve_policy_profile(B, ref, router.PolicyProfileApproval(approver_name="Test Human"))
    assert approved["profile"]["approved_by"] == "Test Human"
    assert approved["approved_from"] == ref and approved["profile_ref"] != ref
    # the committed seed is never written by an approval
    assert default_profile_path(B).read_bytes() == seed_before
    assert yaml.safe_load(seed_before)["approved_by"] is None
