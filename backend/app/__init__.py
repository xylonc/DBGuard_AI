# DBGuardAI application package

# Export models
from app.models import (
    HardenResponse,
    ProposalCompileRequest,
    TemplateIngestRequest,
    TemplateIngestResponse,
    TemplateApprovalRequest,
    TemplateSearchResponse,
    KnowledgeIngestRequest,
    KnowledgeApprovalRequest,
    KnowledgeSearchResult,
    KnowledgeSearchResponse,
    KnowledgeIngestResponse,
    # ASSESS Evaluation Contracts
    FindingStatus,
    TypedAction,
    SetConfigParameterAction,
    RevokeSchemaPrivilegeAction,
    ManualProcedureAction,
    AnyTypedAction,
    Finding,
    AssessmentSummary,
    AssessmentReport,
    # VALIDATE Phase Contracts
    SetConfigTemplateParams,
    RevokePrivilegeTemplateParams,
    TwinExecutionResult,
    TwinExecutionStatus,
    ProposalReviewPackage,
)

# Export proposal models
from app.proposal_models import CompiledProposal, ProposalPackage

# Export services
from app.proposal_compiler import ProposalCompiler
from app.services.assessment_service import AssessmentService
from app.services.template_service import compile_sql_plan_from_templates, safe_render_template, quote_identifier
from app.services.twin_service import TwinExecutionService, build_proposal_review_package

# Export MCP tools
from app.mcp.tools import (
    validate_template_params,
    generate_and_validate_sql,
    propose_and_validate_remediation,
    execute_remediation_in_twin,
    get_proposal_for_review,
)
