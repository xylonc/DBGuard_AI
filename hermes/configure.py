"""Materialize HERMES runtime configuration without baking secrets into images."""

import os
from pathlib import Path

import yaml


SOURCE = Path("/opt/dbguard/config.yaml")
DESTINATION = Path("/opt/data/config.yaml")


DEMO_TOOLS = [
    "get_demo_workflow_context", "get_snapshot_spec_assessment",
    "prepare_sandbox_handoff", "run_sandbox_handoff", "get_sandbox_handoff_status",
]


def configure_workflow(config: dict, mode: str) -> None:
    if mode not in ("standard", "demo"):
        raise ValueError("HERMES_WORKFLOW_MODE must be standard or demo")
    if mode == "demo":
        # Hide legacy proposal tools entirely, instead of relying on model routing.
        config["mcp_servers"]["dbguard"]["tools"]["include"] = list(DEMO_TOOLS)


def main() -> None:
    from plugins.dashboard_auth.basic import hash_password
    username = os.environ.get("HERMES_DASHBOARD_USERNAME", "dbguard")
    password = os.environ.get("HERMES_DASHBOARD_PASSWORD")
    if not password:
        raise SystemExit("HERMES_DASHBOARD_PASSWORD must be set")

    model = os.environ.get("HERMES_MODEL", "gpt-oss:20b")
    model_base_url = os.environ.get(
        "HERMES_MODEL_BASE_URL", "https://ollama.com/v1"
    ).rstrip("/")
    model_api_key = os.environ.get("HERMES_MODEL_API_KEY")
    if not model_api_key:
        raise SystemExit("HERMES_MODEL_API_KEY must be set")

    config = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
    configure_workflow(config, os.environ.get("HERMES_WORKFLOW_MODE", "standard"))
    if os.environ.get("HERMES_MCP_URL"):
        config["mcp_servers"]["dbguard"]["url"] = os.environ["HERMES_MCP_URL"]
    config["model"].update(
        {
            "provider": "custom",
            "default": model,
            "base_url": model_base_url,
            "api_key": model_api_key,
        }
    )
    config["dashboard"]["basic_auth"] = {
        "username": username,
        "password_hash": hash_password(password),
    }
    DESTINATION.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
    )
    DESTINATION.chmod(0o600)


if __name__ == "__main__":
    main()
