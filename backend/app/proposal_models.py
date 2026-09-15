"""Proposal compiler data contracts for DBGuardAI.

This module defines the data models representing SQL proposals generated
from assessment findings. These proposals are deterministic and never
generated via free-form LLM string interpolation.
"""

from datetime import datetime
from pydantic import BaseModel, Field
from typing import Any, List, Optional, Union


class CompiledProposal(BaseModel):
    """Represents a compiled SQL proposal from a single control finding.
    
    This is the output contract for the Proposal Compiler. Each proposal
    contains either executable SQL (for automatable controls) or manual
    step-by-step procedures (for non-SQL controls).
    """
    
    control_id: str = Field(
        description="Unique control identifier (e.g., CIS-3.1.2)"
    )
    title: str = Field(
        description="Human-readable control title"
    )
    is_executable_sql: bool = Field(
        description="True if remediation/rollback SQL can be executed directly"
    )
    remediation_sql: Optional[str] = Field(
        default=None,
        description="Remediation SQL string when is_executable_sql=True"
    )
    rollback_sql: Optional[str] = Field(
        default=None,
        description="Rollback SQL string for undoing remediation"
    )
    manual_steps: Optional[List[str]] = Field(
        default=None,
        description="Step-by-step human procedure when is_executable_sql=False"
    )
    requires_dba_review: bool = Field(
        default=True,
        description="Whether DBA review is required before execution"
    )
    risk_level: str = Field(
        default="medium",
        description="Risk assessment level (low, medium, high)"
    )


class ProposalPackage(BaseModel):
    """Complete package of proposals from an assessment report.
    
    Contains all compiled proposals for a single snapshot with summary
    statistics for easy review and reporting.
    """
    
    snapshot_id: str = Field(
        description="Content-addressed snapshot identifier"
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when this package was created"
    )
    proposals: List[CompiledProposal] = Field(
        default_factory=list,
        description="List of all compiled proposals"
    )
    summary: dict[str, int] = Field(
        default_factory=lambda: {
            "total_proposals": 0,
            "executable_count": 0,
            "manual_count": 0
        },
        description="Summary counts for the proposal package"
    )
