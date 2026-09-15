# DBGuardAI application package
#
# Export models - CURRENT ARCHITECTURE
from app.models import (
    HardenResponse,
    RemediationProposalRequest,
    TemplateIngestRequest,
    TemplateIngestResponse,
    TemplateApprovalRequest,
    TemplateSearchResponse,
    KnowledgeIngestRequest,
    KnowledgeApprovalRequest,
    KnowledgeSearchResult,
    KnowledgeSearchResponse,
    KnowledgeIngestResponse,
    # ASSESS Evaluation Contracts - for offline assessment
    FindingStatus,
    Finding,
    AssessmentSummary,
    AssessmentReport,
    # Template parameter validation
    SetConfigTemplateParams,
    RevokePrivilegeTemplateParams,
    TwinExecutionResult,
    TwinExecutionStatus,
)

# Export services
from app.services.assessment_service import AssessmentService
from app.services.snapshot_service import SnapshotStore, SnapshotNotFoundError
from app.services.template_service import compile_sql_plan_from_templates, validate_params, quote_identifier
from app.services.twin_service import TwinExecutionService, build_proposal_review_package
