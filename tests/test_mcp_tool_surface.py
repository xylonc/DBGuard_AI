"""Parity test: MCP server tools vs HERMES allowlist must match.

This test ensures:
1. The set of tools registered by services/dbguard_mcp/server.py
   matches tools.include in hermes/config/config.yaml
2. The MCP server exposes no prompts or resources (only tools)

The test reads the real registered tools from the server object
and the real YAML file - it does NOT hardcode expected lists.
"""
import asyncio
import sys
from pathlib import Path
from typing import Set

import yaml

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Path constants
PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_YAML_PATH = PROJECT_ROOT / "hermes" / "config" / "config.yaml"
MCP_SERVER_MODULE = PROJECT_ROOT / "services" / "dbguard_mcp" / "server.py"


def load_mcp_tool_names() -> Set[str]:
    """Load tool names registered by the MCP server.
    
    Reads the actual MCPServer object from the server module.
    """
    import importlib.util
    
    # Import the MCP server module
    spec = importlib.util.spec_from_file_location("dbguard_mcp_server", MCP_SERVER_MODULE)
    server_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server_module)
    
    # Get the tools from the MCPServer instance
    loop = asyncio.new_event_loop()
    try:
        tools = loop.run_until_complete(server_module.mcp.list_tools())
    finally:
        loop.close()
    
    return {tool.name for tool in tools}


def load_config_tool_names() -> Set[str]:
    """Load allowed tool names from hermes/config/config.yaml.
    
    Reads the actual YAML file and extracts tools.include.
    """
    with open(CONFIG_YAML_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    mcp_servers = config.get("mcp_servers", {})
    dbguard = mcp_servers.get("dbguard", {})
    tools_config = dbguard.get("tools", {})
    include = tools_config.get("include", [])
    
    return set(include)


def load_mcp_prompts_resources() -> tuple[bool, bool]:
    """Check if MCP server exposes prompts or resources.
    
    Returns (has_prompts, has_resources).
    """
    import importlib.util
    
    spec = importlib.util.spec_from_file_location("dbguard_mcp_server", MCP_SERVER_MODULE)
    server_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(server_module)
    
    loop = asyncio.new_event_loop()
    try:
        prompts = loop.run_until_complete(server_module.mcp.list_prompts())
        resources = loop.run_until_complete(server_module.mcp.list_resources())
    finally:
        loop.close()
    
    # Check if prompts/resources have any entries
    has_prompts = len(prompts) > 0 if isinstance(prompts, list) else bool(prompts)
    has_resources = len(resources) > 0 if isinstance(resources, list) else bool(resources)
    
    return has_prompts, has_resources


def test_mcp_tool_surface_parity():
    """Test that MCP server tools match HERMES config allowlist."""
    mcp_tools = load_mcp_tool_names()
    config_tools = load_config_tool_names()
    
    print(f"MCP server registered tools: {sorted(mcp_tools)}")
    print(f"HERMES config allowed tools: {sorted(config_tools)}")
    
    # Exact match required
    assert mcp_tools == config_tools, (
        f"Tool mismatch!\n"
        f"  In server but not in config: {sorted(mcp_tools - config_tools)}\n"
        f"  In config but not in server: {sorted(config_tools - mcp_tools)}\n"
    )
    
    # Verify no prompts or resources are exposed
    has_prompts, has_resources = load_mcp_prompts_resources()
    assert not has_prompts, "MCP server must not expose prompts"
    assert not has_resources, "MCP server must not expose resources"
    
    print("✓ All checks passed: MCP tools match HERMES allowlist")
    print("✓ No prompts or resources exposed")


if __name__ == "__main__":
    test_mcp_tool_surface_parity()


def test_container_host_is_accepted_without_allowing_arbitrary_hosts():
    from starlette.testclient import TestClient
    from services.dbguard_mcp.server import mcp, MCP_PORT, TRANSPORT_SECURITY

    app = mcp.streamable_http_app(
        transport_security=TRANSPORT_SECURITY, stateless_http=True, json_response=True)
    request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-03-26", "capabilities": {},
        "clientInfo": {"name": "host-regression", "version": "1"}}}
    with TestClient(app) as client:
        for host, expected in [(f"mcp:{MCP_PORT}", 200),
                               (f"127.0.0.1:{MCP_PORT}", 200),
                               ("untrusted.example", 421)]:
            response = client.post("/mcp", json=request, headers={
                "Host": host, "Accept": "application/json, text/event-stream"})
            assert response.status_code == expected
