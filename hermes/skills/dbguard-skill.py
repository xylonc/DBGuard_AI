"""Typed proposal-phase contracts packaged with the HERMES agent."""

from typing import Any

from pydantic import BaseModel, Field


class EvidenceCitation(BaseModel):
    document_id: str
    title: str
    version: str
    section: str
    source_url: str | None = None


class HardeningProposal(BaseModel):
    snapshot_id: str
    requirement: str
    interpretation: str
    snapshot_facts: list[str] = Field(default_factory=list)
    unresolved_gaps: list[str] = Field(default_factory=list)
    template_ids: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    proposed_sql: str = ""
    risks: list[str] = Field(default_factory=list)
    compatibility_questions: list[str] = Field(default_factory=list)
    verification_steps: list[str] = Field(default_factory=list)
    rollback_guidance: list[str] = Field(default_factory=list)
    citations: list[EvidenceCitation] = Field(default_factory=list)
    requires_dba_approval: bool = True


class DBGuardProposalSkill:
    ALLOWED_TOOLS = {
        "get_snapshot_context",
        "search_approved_knowledge",
        "search_approved_templates",
        "create_hardening_proposal",
    }
    PROHIBITED_TOOLS = {
        "run_shell",
        "run_docker",
        "run_arbitrary_sql",
        "connect_to_database",
        "connect_to_production",
        "execute_hardening",
        "start_assessment",
        "approve_own_action",
    }

    @classmethod
    def tool_is_allowed(cls, tool_name: str) -> bool:
        return tool_name in cls.ALLOWED_TOOLS and tool_name not in cls.PROHIBITED_TOOLS
