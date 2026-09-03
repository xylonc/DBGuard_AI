"""
DBGuardAI Skill for HERMES Agent
This skill provides the DBGuard-specific workflows, controls, and guidelines.
"""
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum


class ControlStatus(str, Enum):
    PENDING = "PENDING"
    VALIDATED = "VALIDATED"
    REMEDIATED = "REMEDIATED"
    EXHAUSTED = "REMEDIATION_EXHAUSTED"
    EXCEPTION_PROPOSED = "EXCEPTION_PROPOSED"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DBGuardFinding(BaseModel):
    """Structured finding from security assessment."""
    control_id: str
    title: str
    severity: RiskLevel
    description: str
    baseline_result: str
    cis_cat_mapping: Optional[str] = None
    remediation_available: bool = True


class DBGuardAction(BaseModel):
    """Structured action proposed by HERMES."""
    control_id: str
    action_type: str  # remediation, rollback, validation
    parameters: Dict[str, Any] = Field(default_factory=dict)
    justification: str
    evidence_references: List[str] = Field(default_factory=list)
    compatibility_impacts: List[str] = Field(default_factory=list)


class DBGuardAssessmentSummary(BaseModel):
    """Summary of assessment results."""
    run_id: str
    target_db: str
    postgresql_version: str
    baseline_score: float
    twin_score: float
    controls_assessed: int
    controls_passed: int
    controls_failed: int
    exceptions_proposed: int
    coverage: float
    fidelity: str


class DBGuardException(BaseModel):
    """Exception request when remediation fails."""
    control_id: str
    reason: str
    attempts_made: int
    residual_risk: str
    compensating_controls: List[str] = Field(default_factory=list)
    business_justification: str
    proposed_expiry: Optional[datetime] = None


class DBGuardSkill:
    """
    DBGuardAI Skill for HERMES Agent.
    
    This skill defines:
    1. Allowed MCP tools and their schemas
    2. DBGuard-specific workflows
    3. Prompt templates for assessment and planning
    4. Data validation schemas
    """
    
    # === Allowed MCP Tools ===
    ALLOWED_TOOLS = {
        # Read-only tools
        "get_assessment_status": {
            "description": "Get current assessment run status and phase",
            "parameters": {
                "run_id": {"type": "string", "description": "Assessment run identifier"}
            }
        },
        "list_findings": {
            "description": "List all assessment findings with status",
            "parameters": {
                "run_id": {"type": "string"},
                "filter": {"type": "string", "enum": ["all", "critical", "high", "failed", "exception"]}
            }
        },
        "get_finding": {
            "description": "Get detailed information about a specific finding",
            "parameters": {
                "control_id": {"type": "string"},
                "run_id": {"type": "string"}
            }
        },
        "retrieve_policy_evidence": {
            "description": "Retrieve approved policy references for a control",
            "parameters": {
                "control_id": {"type": "string"},
                "document_id": {"type": "string"}
            }
        },
        "get_target_profile": {
            "description": "Get the normalized target database profile",
            "parameters": {"run_id": {"type": "string"}}
        },
        "get_twin_fidelity": {
            "description": "Get twin fidelity report",
            "parameters": {"run_id": {"type": "string"}}
        },
        "get_compatibility_requirements": {
            "description": "Get application compatibility contract",
            "parameters": {"run_id": {"type": "string"}}
        },
        "explain_control": {
            "description": "Get plain-language explanation of a control",
            "parameters": {"control_id": {"type": "string"}}
        },
        "get_evidence_requirements": {
            "description": "Get evidence requirements for a control",
            "parameters": {"control_id": {"type": "string"}}
        },
        
        # Controlled action tools
        "start_assessment": {
            "description": "Start a new assessment run",
            "parameters": {
                "snapshot_hash": {"type": "string"},
                "target_profile": {"type": "object"}
            }
        },
        "propose_hardening_action": {
            "description": "Propose a structured hardening action",
            "parameters": {
                "control_id": {"type": "string"},
                "parameters": {"type": "object"},
                "justification": {"type": "string"},
                "evidence_ids": {"type": "array"}
            }
        },
        "request_control_execution": {
            "description": "Request execution of an approved control in the twin",
            "parameters": {
                "control_id": {"type": "string"},
                "attempt_number": {"type": "integer", "minimum": 1, "maximum": 3}
            }
        },
        "request_compatibility_test": {
            "description": "Request compatibility validation in the twin",
            "parameters": {
                "test_type": {"type": "string", "enum": ["auth", "connection", "privilege", "monitoring"]},
                "control_id": {"type": "string"}
            }
        },
        "request_security_validation": {
            "description": "Request security validation after remediation",
            "parameters": {
                "control_id": {"type": "string"},
                "validations": {"type": "array"}
            }
        },
        "request_control_rollback": {
            "description": "Request rollback of a control in the twin",
            "parameters": {
                "control_id": {"type": "string"},
                "reason": {"type": "string"}
            }
        },
        "record_exception_proposal": {
            "description": "Propose an exception for a control",
            "parameters": {
                "control_id": {"type": "string"},
                "reason": {"type": "string"},
                "justification": {"type": "string"},
                "residual_risk": {"type": "string"},
                "compensating_controls": {"type": "array"}
            }
        },
        "generate_review_package": {
            "description": "Generate a human review package",
            "parameters": {
                "run_id": {"type": "string"},
                "package_type": {"type": "string", "enum": ["hardening", "rollback", "evidence"]}
            }
        }
    }
    
    # === Prohibited Tools ===
    PROHIBITED_TOOLS = [
        "run_shell",
        "run_docker",
        "run_arbitrary_sql",
        "mount_directory",
        "select_image_url",
        "connect_to_production",
        "modify_image_catalog",
        "modify_control_catalog",
        "approve_own_action",
        "export_production_data",
        "modify_twin_security",
        "bypass_approval_policy"
    ]
    
    # === Prompt Templates ===
    PROMPTS = {
        "assessment": """
You are a DBGuardAI security assessment assistant. Your role is to:

1. Analyze PostgreSQL security findings from the target database
2. Retrieve relevant CIS benchmark and policy evidence via RAG
3. Select applicable approved controls from the Hardening Control Catalog
4. Propose structured remediation actions with clear justifications
5. Flag compatibility risks based on the application contract

IMPORTANT RULES:
- ONLY propose actions that exist in the approved Control Catalog
- NEVER generate arbitrary SQL or shell commands
- ALWAYS cite policy evidence for recommendations
- ALWAYS check application compatibility before suggesting changes
- If no approved evidence is found, return MANUAL_REVIEW_REQUIRED

Current assessment phase: {phase}
Target database: {target_db}
PostgreSQL version: {pg_version}

Findings requiring attention:
{findings}

Approved controls available:
{controls}

Application compatibility requirements:
{compatibility}
""",
        
        "planning": """
You are DBGuardAI planning assistant. Create a hardening plan for the target database.

Requirements:
1. Select controls that address critical and high severity findings
2. Order controls by dependencies (e.g., SSL before SCRAM)
3. Flag high-risk changes for human review
4. Generate rollback procedures for each control
5. Calculate expected security score improvement

Control selection criteria:
- Supported by the target PostgreSQL version
- Not blocked by application compatibility
- Has an approved rollback procedure
- Has sufficient evidence in RAG knowledge base

Findings:
{findings}

Controls:
{controls}

Compatibility risks:
{risks}

Generate a structured hardening plan with:
- Ordered list of controls
- Dependencies
- Risk assessments
- Evidence requirements
- Exception candidates
""",
        
        "exception": """
You are DBGuardAI exception justification assistant.

When remediation fails after three attempts, propose an exception with:
1. Clear technical reason why the control cannot be implemented
2. Residual risk assessment
3. Compensating controls (if any)
4. Business justification (if applicable)
5. Proposed review period and expiry

Be specific about:
- What was attempted
- Why each attempt failed
- What the risk actually is (quantify if possible)
- What mitigations are already in place

Control: {control_id}
Attempts: {attempts}
Results: {results}
""",
        
        "review": """
You are DBGuardAI review assistant. Help the DBA review the hardening package.

For each control in the package, provide:
1. Plain-language explanation of the change
2. Why it's being proposed
3. What will happen if applied
4. What will happen if rejected
5. Rollback procedure summary
6. Application impact assessment

Package summary:
{summary}

Controls:
{controls}

Warnings:
{warnings}
""",
        
        "natural_language": """
You are DBGuardAI natural language assistant. Help users understand and execute the hardening workflow.

Rules:
- Provide plain-language explanations of technical terms
- Reference approved controls when suggesting changes
- Never propose unapproved actions
- Flag high-risk changes for human review
- Guide users through the assessment workflow step by step

User query: {query}

Context:
{context}
""",
    }
    
    # === Skill Documentation ===
    SKILL_DOCS = """
# DBGuardAI Skill for HERMES Agent

## Purpose
This skill configures HERMES as a DBGuardAI assistant for PostgreSQL security hardening.

## Security Boundaries
- HERMES is an AI reasoning layer, NOT an execution engine
- All actions must be validated by the deterministic Control Service
- HERMES cannot touch Docker, production DBs, or arbitrary SQL
- Every action requires approval before reaching the twin

## MCP Tool Usage
### Read-Only Tools
Use these to gather information about the target database and assessment state.

### Controlled-Action Tools
Use these to propose actions, but never to execute them directly.
The Control Service validates and executes all actions.

### Prohibited Tools
Never attempt to call these tools. The MCP configuration will reject them.

## Workflow
1. **Assessment**: Gather findings from target database
2. **Planning**: Select and order approved controls
3. **Validation**: Verify controls against Control Catalog
4. **Remediation**: Propose actions for twin testing
5. **Review**: Generate package for human approval
6. **Evidence**: Collect and validate evidence for audit

## Output Schemas
All HERMES output must conform to typed schemas defined in `apps/api/app/models.py`.
Malformed or untyped output is rejected automatically.
"""
