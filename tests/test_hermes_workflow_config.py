"""Keep incompatible legacy tools out of the connected demo agent."""
import copy
import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("hermes_configure", ROOT / "hermes/configure.py")
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)


def config():
    return yaml.safe_load((ROOT / "hermes/config/config.yaml").read_text())


def test_demo_hides_legacy_assessment_and_proposal_tools():
    value = config()
    configure.configure_workflow(value, "demo")
    tools = value["mcp_servers"]["dbguard"]["tools"]["include"]
    assert set(tools) == {"get_demo_workflow_context", "get_snapshot_spec_assessment",
                          "prepare_sandbox_handoff", "run_sandbox_handoff",
                          "get_sandbox_handoff_status"}
    assert not value["mcp_servers"]["dbguard"]["tools"]["prompts"]
    assert not value["mcp_servers"]["dbguard"]["tools"]["resources"]


def test_standard_keeps_existing_tools_and_invalid_mode_fails():
    value = config()
    original = copy.deepcopy(value)
    configure.configure_workflow(value, "standard")
    assert value == original
    with pytest.raises(ValueError, match="standard or demo"):
        configure.configure_workflow(value, "typo")
