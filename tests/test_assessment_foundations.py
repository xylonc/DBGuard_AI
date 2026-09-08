"""Tests for the strict catalogue and initial template assessment definitions."""

import copy
import tempfile
import unittest
from pathlib import Path

import yaml
from pydantic import ValidationError

from services.assessment import (
    AssessmentCatalogError,
    AssessmentDefinitionNotFound,
    AssessmentService,
    AssessmentStatus,
    AssessmentSuite,
    BaselineCatalogStatus,
    CheckObservation,
    EvidenceReference,
    EvidenceType,
    ObservationState,
    get_baseline_catalog_status,
    get_assessment_definition,
    list_assessment_templates,
    load_assessment_catalog,
)


CATALOG_PATH = (
    Path(__file__).resolve().parents[1]
    / "catalog"
    / "controls"
    / "hardening-controls.yaml"
)


def catalog_data():
    return yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))


class FakeExecutor:
    def __init__(self, values=None, *, evidence_types=None, omit_evidence=None, errors=None):
        self.values = values or {}
        self.evidence_types = evidence_types or {}
        self.omit_evidence = set(omit_evidence or [])
        self.errors = set(errors or [])
        self.calls = []

    def run_check(self, verifier_id, parameters):
        self.calls.append((verifier_id, parameters))
        if verifier_id in self.errors:
            raise RuntimeError("simulated executor failure")
        value = self.values.get(verifier_id)
        evidence = []
        if verifier_id not in self.omit_evidence:
            evidence = [
                EvidenceReference(
                    evidence_id=f"evidence-{verifier_id}",
                    evidence_type=self.evidence_types.get(
                        verifier_id, EvidenceType.QUERY_OUTPUT
                    ),
                    description=f"Observed {verifier_id}",
                )
            ]
        return CheckObservation(
            state=ObservationState.OBSERVED,
            observed_value=value,
            detail=f"{verifier_id} returned {value}",
            evidence=evidence,
        )


def passing_values(template_name):
    definition = get_assessment_definition(template_name, 1)
    return {
        criterion.verifier_id: criterion.expected_value
        for criterion in definition.criteria
    }


def required_evidence_types(template_name):
    definition = get_assessment_definition(template_name, 1)
    return {
        criterion.verifier_id: criterion.evidence_types[0]
        for criterion in definition.criteria
    }


def passing_executor(template_name, **kwargs):
    return FakeExecutor(
        passing_values(template_name),
        evidence_types=required_evidence_types(template_name),
        **kwargs,
    )


class AssessmentRegistryTests(unittest.TestCase):
    def test_only_current_templates_are_registered(self):
        self.assertEqual(
            list_assessment_templates(),
            (("create_read_only_rule", 1), ("revoke_public_access", 1)),
        )

    def test_unknown_template_has_no_fallback(self):
        with self.assertRaises(AssessmentDefinitionNotFound):
            get_assessment_definition("llm_generated_template", 1)

    def test_unreviewed_template_version_has_no_fallback(self):
        with self.assertRaises(AssessmentDefinitionNotFound):
            get_assessment_definition("create_read_only_rule", 2)

    def test_read_only_parameters_reject_extra_fields(self):
        definition = get_assessment_definition("create_read_only_rule", 1)
        with self.assertRaises(ValidationError):
            definition.validate_parameters({
                "role_name": "reporting_user",
                "database_name": "postgres",
                "schema_name": "public",
                "raw_sql": "DROP DATABASE postgres",
            })


class AssessmentCatalogLoaderTests(unittest.TestCase):
    def assert_catalog_rejected(self, data, message_pattern):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hardening-controls.yaml"
            path.write_text(
                yaml.safe_dump(data, sort_keys=False),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AssessmentCatalogError, message_pattern):
                load_assessment_catalog(path)

    def test_current_catalog_loads_and_baseline_is_not_ready(self):
        loaded = load_assessment_catalog()

        self.assertEqual(
            tuple(sorted(loaded.template_definitions)),
            (("create_read_only_rule", 1), ("revoke_public_access", 1)),
        )
        self.assertEqual(
            loaded.baseline_catalog_status,
            BaselineCatalogStatus.NOT_READY,
        )
        self.assertEqual(get_baseline_catalog_status(), BaselineCatalogStatus.NOT_READY)
        self.assertFalse(loaded.active_baseline_profiles)
        self.assertFalse(loaded.active_baseline_controls)

    def test_unknown_parameter_model_is_rejected(self):
        data = catalog_data()
        data["template_assessments"][0]["parameter_model"] = "dynamic_import"
        self.assert_catalog_rejected(data, "unknown parameter_model")

    def test_unknown_verifier_id_is_rejected(self):
        data = catalog_data()
        data["template_assessments"][0]["criteria"][0][
            "verifier_id"
        ] = "run_llm_supplied_sql"
        self.assert_catalog_rejected(data, "unknown verifier_id")

    def test_duplicate_template_version_is_rejected(self):
        data = catalog_data()
        data["template_assessments"].append(
            copy.deepcopy(data["template_assessments"][0])
        )
        self.assert_catalog_rejected(data, "duplicate template name/version pairs")

    def test_duplicate_criterion_id_is_rejected(self):
        data = catalog_data()
        duplicate = data["template_assessments"][0]["criteria"][0]["criterion_id"]
        data["template_assessments"][1]["criteria"][0]["criterion_id"] = duplicate
        self.assert_catalog_rejected(data, "duplicate template criterion IDs")

    def test_duplicate_yaml_mapping_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hardening-controls.yaml"
            path.write_text(
                CATALOG_PATH.read_text(encoding="utf-8") + "\nstatus: draft\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                AssessmentCatalogError,
                "duplicate mapping key 'status'",
            ):
                load_assessment_catalog(path)

    def test_approved_control_cannot_use_draft_source(self):
        data = catalog_data()
        data["baseline_controls"] = [
            {
                "control_id": "TEST-DRAFT-SOURCE",
                "title": "A control that must not activate",
                "review_status": "approved",
                "source_references": [
                    {
                        "source_id": "cis-postgresql-17-v1.1.0",
                        "source_version": "1.1.0",
                        "control_reference": "test-only",
                    }
                ],
                "applicability": {
                    "postgresql_versions": ["17"],
                    "environment_applicability": ["all"],
                },
                "assessment": {
                    "provider": "dbguard",
                    "verifier_id": "role_exists",
                    "cis_rule_id": None,
                    "expected_value": True,
                    "expected_status": "PASS",
                },
                "evidence_types": ["query_output"],
                "remediation": {
                    "template_name": None,
                    "template_version": None,
                    "reconcile_on_failure": False,
                },
            }
        ]
        self.assert_catalog_rejected(data, "not approved for control authoring")

    def test_exact_source_version_is_required(self):
        data = catalog_data()
        control = {
            "control_id": "TEST-WRONG-VERSION",
            "title": "A version-bound control",
            "review_status": "draft",
            "source_references": [
                {
                    "source_id": "cis-postgresql-17-v1.1.0",
                    "source_version": "1.0.0",
                    "control_reference": "test-only",
                }
            ],
            "applicability": {
                "postgresql_versions": ["17"],
                "environment_applicability": ["all"],
            },
            "assessment": {
                "provider": "dbguard",
                "verifier_id": "role_exists",
                "cis_rule_id": None,
                "expected_value": True,
                "expected_status": "PASS",
            },
            "evidence_types": ["query_output"],
            "remediation": {
                "template_name": None,
                "template_version": None,
                "reconcile_on_failure": False,
            },
        }
        data["baseline_controls"] = [control]
        self.assert_catalog_rejected(data, "source-version mismatch")

    def test_public_access_parameters_reject_extra_fields(self):
        definition = get_assessment_definition("revoke_public_access", 1)
        with self.assertRaises(ValidationError):
            definition.validate_parameters({
                "schema_name": "public",
                "verifier_id": "run_arbitrary_sql",
            })


class ReadOnlyRoleAssessmentTests(unittest.TestCase):
    parameters = {
        "role_name": "reporting_user",
        "database_name": "postgres",
        "schema_name": "public",
    }

    def test_defined_checks_pass_but_incomplete_global_baseline_is_unknown(self):
        executor = passing_executor("create_read_only_rule")
        report = AssessmentService().assess_template(
            "create_read_only_rule", 1, self.parameters, executor
        )

        self.assertEqual(report.overall_status, AssessmentStatus.UNKNOWN)
        self.assertEqual(
            report.baseline_catalog_status,
            BaselineCatalogStatus.NOT_READY,
        )
        self.assertEqual(report.suite_status[AssessmentSuite.BASELINE], AssessmentStatus.PASS)
        self.assertEqual(report.suite_status[AssessmentSuite.REQUIREMENT], AssessmentStatus.PASS)
        self.assertTrue(executor.calls)
        self.assertTrue(all(call[1] == self.parameters for call in executor.calls))

    def test_schema_create_failure_maps_to_existing_revoke_template(self):
        values = passing_values("create_read_only_rule")
        values["role_can_create_in_schema"] = True
        report = AssessmentService().assess_template(
            "create_read_only_rule",
            1,
            self.parameters,
            FakeExecutor(values, evidence_types=required_evidence_types("create_read_only_rule")),
        )

        result = next(
            item for item in report.results
            if item.verifier_id == "role_can_create_in_schema"
        )
        self.assertEqual(result.status, AssessmentStatus.FAIL)
        self.assertEqual(result.remediation_template_name, "revoke_public_access")
        self.assertTrue(result.reconcile_on_failure)

    def test_future_table_gap_requires_human_review(self):
        values = passing_values("create_read_only_rule")
        values["role_can_select_future_probe_table"] = False
        report = AssessmentService().assess_template(
            "create_read_only_rule",
            1,
            self.parameters,
            FakeExecutor(values, evidence_types=required_evidence_types("create_read_only_rule")),
        )

        result = next(
            item for item in report.results
            if item.verifier_id == "role_can_select_future_probe_table"
        )
        self.assertEqual(result.status, AssessmentStatus.FAIL)
        self.assertIsNone(result.remediation_template_name)
        self.assertFalse(result.reconcile_on_failure)

    def test_matching_result_without_evidence_is_unknown(self):
        verifier_id = "role_exists"
        report = AssessmentService().assess_template(
            "create_read_only_rule",
            1,
            self.parameters,
            FakeExecutor(
                passing_values("create_read_only_rule"),
                evidence_types=required_evidence_types("create_read_only_rule"),
                omit_evidence={verifier_id},
            ),
        )
        result = next(item for item in report.results if item.verifier_id == verifier_id)
        self.assertEqual(result.status, AssessmentStatus.UNKNOWN)
        self.assertIn("Evidence was not captured", result.detail)

    def test_wrong_evidence_type_is_unknown(self):
        verifier_id = "role_can_connect_database"
        evidence_types = required_evidence_types("create_read_only_rule")
        evidence_types[verifier_id] = EvidenceType.QUERY_OUTPUT
        report = AssessmentService().assess_template(
            "create_read_only_rule",
            1,
            self.parameters,
            FakeExecutor(
                passing_values("create_read_only_rule"),
                evidence_types=evidence_types,
            ),
        )

        result = next(
            item for item in report.results if item.verifier_id == verifier_id
        )
        self.assertEqual(result.status, AssessmentStatus.UNKNOWN)
        self.assertIn("command_output", result.detail)

    def test_executor_exception_is_error(self):
        verifier_id = "role_exists"
        report = AssessmentService().assess_template(
            "create_read_only_rule",
            1,
            self.parameters,
            FakeExecutor(
                passing_values("create_read_only_rule"),
                evidence_types=required_evidence_types("create_read_only_rule"),
                errors={verifier_id},
            ),
        )
        result = next(item for item in report.results if item.verifier_id == verifier_id)
        self.assertEqual(result.status, AssessmentStatus.ERROR)
        self.assertEqual(report.overall_status, AssessmentStatus.ERROR)


class RevokePublicAccessAssessmentTests(unittest.TestCase):
    def test_revoke_all_checks_create_usage_and_owner_access(self):
        definition = get_assessment_definition("revoke_public_access", 1)
        verifier_ids = {criterion.verifier_id for criterion in definition.criteria}
        self.assertEqual(verifier_ids, {
            "public_has_schema_create",
            "public_has_schema_usage",
            "schema_owner_has_schema_usage",
        })

        report = AssessmentService().assess_template(
            "revoke_public_access",
            1,
            {"schema_name": "public"},
            passing_executor("revoke_public_access"),
        )
        self.assertEqual(report.overall_status, AssessmentStatus.UNKNOWN)
        self.assertEqual(
            report.baseline_catalog_status,
            BaselineCatalogStatus.NOT_READY,
        )
        self.assertEqual(report.suite_status, {
            AssessmentSuite.BASELINE: AssessmentStatus.PASS,
        })

    def test_remaining_public_create_privilege_fails(self):
        values = passing_values("revoke_public_access")
        values["public_has_schema_create"] = True
        report = AssessmentService().assess_template(
            "revoke_public_access",
            1,
            {},
            FakeExecutor(values, evidence_types=required_evidence_types("revoke_public_access")),
            iteration=2,
        )
        result = next(
            item for item in report.results
            if item.verifier_id == "public_has_schema_create"
        )
        self.assertEqual(result.status, AssessmentStatus.FAIL)
        self.assertEqual(result.remediation_template_name, "revoke_public_access")
        self.assertEqual(report.parameters["schema_name"], "public")


if __name__ == "__main__":
    unittest.main()
