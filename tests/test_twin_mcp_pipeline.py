"""Tests for template-driven remediation proposal workflow.

⚠️ DEPRECATED - This module tests the OLD MCP tools that have been removed.
The current architecture uses the template registry directly via the API.

For the new template-driven proposal workflow, see test_remediation_proposal.py.
"""

import pytest

# The old app.mcp.tools module has been removed.
# The current architecture uses:
# - POST /api/v1/proposals/validate-and-render for proposal validation
# - MCP create_remediation_proposal tool (wrapper around the API)

# Tests for the old MCP tools are no longer applicable.


@pytest.mark.skip(reason="Legacy test for deleted app.mcp.tools module")
def test_mcp_tools_deleted():
    """Confirm the old MCP tools module is no longer available."""
    with pytest.raises(ModuleNotFoundError, match="No module named 'app.mcp.tools'"):
        from app.mcp.tools import validate_template_params  # noqa: F401
