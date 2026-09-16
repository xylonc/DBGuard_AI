"""Legacy Twin Execution Service for VALIDATE phase.

⚠️ DEPRECATED: This module contains the OLD twin execution implementation.
The current architecture uses SandboxValidationService with a clean boundary.

This legacy code is retained for reference during migration but should not
be used for new development. The new architecture is:

    HERMES
      ↓
    API (validate_in_sandbox)
      ↓
    SandboxValidationService
      ↓
    TwinRunner (restricted Docker interaction only)
      ↓
    Ephemeral PostgreSQL sandbox

Key improvements in the new architecture:
- TwinRunner is the ONLY component that contacts Docker
- No os.system/os.popen calls in the service layer
- SQL execution goes through TwinRunner.execute_sql() with controlled inputs
- Metadata replay goes through TwinRunner.replay_metadata()
- Clear separation of concerns between orchestration and execution
"""

from catalog.controls.assess.registry import CONTROL_REGISTRY
from app.models import (
    AssessmentReport,
    FindingStatus,
    ProposalReviewPackage,
    TwinExecutionResult,
    TwinExecutionStatus,
)

# Legacy code is intentionally not imported
# Use SandboxValidationService instead from app.services.sandbox_service

__all__ = []
