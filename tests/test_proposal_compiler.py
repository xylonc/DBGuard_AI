"""Legacy tests for the OLD TypedAction-based proposal compiler.

⚠️ DEPRECATED - This module tests the old proposal compiler architecture.
The current remediation flow uses template-driven SQL rendering instead.

For the new template-driven proposal workflow, see test_remediation_proposal.py.
The OLD TypedAction/ProposalCompiler path is no longer used for remediation.
"""

import pytest

# The old proposal_compiler module has been removed.
# Tests that depend on it cannot run.
# These tests were for the old architecture where:
# - TypedAction objects defined remediation actions
# - ProposalCompiler generated SQL from TypedAction
#
# Current architecture:
# - Approved Jinja templates are the remediation catalogue
# - Agent selects template + parameters + reasoning
# - API validates and renders the template


@pytest.mark.skip(reason="Legacy test for deleted ProposalCompiler module")
def test_proposal_compiler_deleted():
    """Confirm the old proposal_compiler module is no longer available."""
    with pytest.raises(ModuleNotFoundError, match="No module named 'app.proposal_compiler'"):
        from app.proposal_compiler import ProposalCompiler  # noqa: F401
