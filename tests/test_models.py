import unittest
from datetime import datetime

from pydantic import ValidationError

from app.models import (
    KnowledgeIngestRequest,
    ProposalCompileRequest,
    TemplateIngestRequest,
)


class ApprovalContractTests(unittest.TestCase):
    def test_active_knowledge_requires_approver(self):
        with self.assertRaises(ValidationError):
            KnowledgeIngestRequest(
                document_id="postgres-security",
                title="PostgreSQL security guidance",
                version="1",
                content="x" * 100,
                effective_date=datetime.now(),
                status="active",
            )

    def test_active_template_requires_approver(self):
        with self.assertRaises(ValidationError):
            TemplateIngestRequest(
                template_name="safe-template",
                description="Reviewed database hardening template",
                sql_template="SELECT 1;",
                status="active",
            )

    def test_drafts_are_allowed_without_approver(self):
        request = TemplateIngestRequest(
            template_name="draft-template",
            description="Pending human review",
            sql_template="SELECT 1;",
        )
        self.assertEqual(request.status, "draft")

    def test_proposal_requires_at_least_one_template(self):
        with self.assertRaises(ValidationError):
            ProposalCompileRequest(
                snapshot_id="snap-abc123",
                requirement="Remove unnecessary public access",
                template_ids=[],
            )

    def test_proposal_limits_template_selection(self):
        with self.assertRaises(ValidationError):
            ProposalCompileRequest(
                snapshot_id="snap-abc123",
                requirement="Apply reviewed hardening",
                template_ids=[f"template-{index}" for index in range(6)],
            )


if __name__ == "__main__":
    unittest.main()
