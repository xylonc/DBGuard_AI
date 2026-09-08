"""Strict loader for DBGuard's reviewed hardening-control catalogue."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Mapping

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    model_validator,
)

from services.assessment.definition import (
    AssessmentParameters,
    TemplateAssessmentDefinition,
)
from services.assessment.models import (
    AssessmentCriterion,
    AssessmentSuite,
    BaselineCatalogStatus,
    EvidenceType,
)
from services.assessment.verifiers.read_only_role import (
    READ_ONLY_ROLE_VERIFIER_IDS,
    ReadOnlyRoleParameters,
)
from services.assessment.verifiers.revoke_public_access import (
    REVOKE_PUBLIC_ACCESS_VERIFIER_IDS,
    RevokePublicAccessParameters,
)


DEFAULT_CATALOG_PATH = (
    Path(__file__).resolve().parents[2]
    / "catalog"
    / "controls"
    / "hardening-controls.yaml"
)


class AssessmentCatalogError(ValueError):
    """Raised when catalogue content is malformed or escapes an allowlist."""


class CatalogLifecycle(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    RETIRED = "retired"


class SourceReviewStatus(str, Enum):
    PLANNED = "planned"
    CONVERSION_IN_PROGRESS = "conversion_in_progress"
    DRAFT = "draft"
    REVIEWED = "reviewed"
    APPROVED = "approved"
    RETIRED = "retired"


class AssessmentProviderName(str, Enum):
    DBGUARD = "dbguard"
    CIS_CAT = "cis_cat"


class _CatalogModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ControlActivationPolicy(_CatalogModel):
    allowed_source_review_statuses: tuple[SourceReviewStatus, ...] = Field(
        min_length=1
    )
    require_exact_source_version: Literal[True]
    require_environment_applicability: Literal[True]
    require_reviewed_assessment_provider: Literal[True]
    require_evidence_types: Literal[True]
    unmapped_cis_cat_result: Literal["pending_human_review"]
    unsupported_control: Literal["pending_human_review"]

    @model_validator(mode="after")
    def executable_sources_must_be_approved(self):
        if set(self.allowed_source_review_statuses) != {
            SourceReviewStatus.APPROVED
        }:
            raise ValueError(
                "allowed_source_review_statuses must contain only approved"
            )
        return self


class KnowledgeSource(_CatalogModel):
    source_id: str = Field(min_length=1, max_length=255)
    source_type: str = Field(min_length=1, max_length=128)
    publisher: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=512)
    version: str = Field(min_length=1, max_length=128)
    postgresql_versions: tuple[str, ...] = Field(min_length=1)
    classification: str = Field(min_length=1, max_length=128)
    review_status: SourceReviewStatus
    artifact_name: str | None = Field(default=None, max_length=512)
    rag_document_id: str | None = Field(default=None, max_length=255)
    source_url: str = Field(min_length=1, max_length=2048)
    approved_for_control_authoring: StrictBool
    notes: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def authoring_requires_approval(self):
        if (
            self.approved_for_control_authoring
            and self.review_status != SourceReviewStatus.APPROVED
        ):
            raise ValueError(
                "a source approved for control authoring must have approved status"
            )
        return self


class DbguardProvider(_CatalogModel):
    enabled: StrictBool
    purpose: str = Field(min_length=1, max_length=1000)
    allow_arbitrary_sql: Literal[False]


class CisCatProvider(_CatalogModel):
    enabled: StrictBool
    product: str = Field(min_length=1, max_length=255)
    purpose: str = Field(min_length=1, max_length=1000)
    target_boundary: Literal["twin_only"]
    connection_type: Literal["postgresql_jdbc"]
    accepted_report_formats: tuple[Literal["json", "xml"], ...] = Field(
        min_length=1
    )
    retain_original_report: Literal[True]
    required_run_metadata: tuple[str, ...] = Field(min_length=1)
    required_result_fields: tuple[str, ...] = Field(min_length=1)
    unmapped_results_are_failures: Literal[False]
    unmapped_results_require_human_review: Literal[True]


class AssessmentProviders(_CatalogModel):
    dbguard: DbguardProvider
    cis_cat: CisCatProvider


class ParameterSpec(_CatalogModel):
    type: Literal["postgresql_identifier"]
    required: StrictBool
    default: Any | None = None
    description: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def required_parameters_have_no_default(self):
        if self.required and self.default is not None:
            raise ValueError("required parameters cannot declare a default")
        return self


class RemediationSpec(_CatalogModel):
    template_name: str | None = Field(default=None, min_length=1, max_length=255)
    template_version: int | None = Field(default=None, ge=1, strict=True)
    reconcile_on_failure: StrictBool

    @model_validator(mode="after")
    def template_and_version_are_paired(self):
        if (self.template_name is None) != (self.template_version is None):
            raise ValueError(
                "remediation template_name and template_version must be set together"
            )
        if self.reconcile_on_failure and self.template_name is None:
            raise ValueError(
                "reconcile_on_failure requires an approved remediation template"
            )
        return self


class TemplateCriterionSpec(_CatalogModel):
    criterion_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    suite: AssessmentSuite
    verifier_id: str = Field(min_length=1, max_length=128)
    expected_value: StrictBool
    evidence_types: tuple[EvidenceType, ...] = Field(min_length=1)
    remediation: RemediationSpec
    notes: str | None = Field(default=None, max_length=4000)


class TemplateAssessmentSpec(_CatalogModel):
    template_name: str = Field(min_length=1, max_length=255)
    template_version: int = Field(ge=1, strict=True)
    template_path: str = Field(min_length=1, max_length=1024)
    title: str = Field(min_length=1, max_length=512)
    parameter_model: str = Field(min_length=1, max_length=128)
    parameters: dict[str, ParameterSpec] = Field(min_length=1)
    criteria: tuple[TemplateCriterionSpec, ...] = Field(min_length=1)


class BaselineSourceReference(_CatalogModel):
    source_id: str = Field(min_length=1, max_length=255)
    source_version: str = Field(min_length=1, max_length=128)
    control_reference: str = Field(min_length=1, max_length=255)
    section: str | None = Field(default=None, max_length=512)


class BaselineApplicability(_CatalogModel):
    postgresql_versions: tuple[str, ...] = Field(min_length=1)
    environment_applicability: tuple[str, ...] = Field(min_length=1)


class BaselineAssessmentSpec(_CatalogModel):
    provider: AssessmentProviderName
    verifier_id: str | None = Field(default=None, min_length=1, max_length=128)
    cis_rule_id: str | None = Field(default=None, min_length=1, max_length=255)
    expected_value: StrictBool | None = None
    expected_status: Literal["PASS"] = "PASS"

    @model_validator(mode="after")
    def provider_has_one_reviewed_execution_key(self):
        if self.provider == AssessmentProviderName.DBGUARD:
            if self.verifier_id is None or self.cis_rule_id is not None:
                raise ValueError(
                    "dbguard controls require verifier_id and forbid cis_rule_id"
                )
            if self.expected_value is None:
                raise ValueError("dbguard controls require expected_value")
        elif (
            self.cis_rule_id is None
            or self.verifier_id is not None
            or self.expected_value is not None
        ):
            raise ValueError(
                "cis_cat controls require cis_rule_id and forbid verifier_id "
                "and expected_value"
            )
        return self


class BaselineControlSpec(_CatalogModel):
    control_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    review_status: SourceReviewStatus
    source_references: tuple[BaselineSourceReference, ...] = Field(min_length=1)
    applicability: BaselineApplicability
    assessment: BaselineAssessmentSpec
    evidence_types: tuple[EvidenceType, ...] = Field(min_length=1)
    remediation: RemediationSpec


class BaselineProfileSpec(_CatalogModel):
    profile_id: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=512)
    review_status: SourceReviewStatus
    source_id: str = Field(min_length=1, max_length=255)
    source_version: str = Field(min_length=1, max_length=128)
    profile_reference: str = Field(min_length=1, max_length=255)
    postgresql_versions: tuple[str, ...] = Field(min_length=1)
    environment_applicability: tuple[str, ...] = Field(min_length=1)
    control_ids: tuple[str, ...] = Field(min_length=1)


def _duplicates(values: list[Any]) -> set[Any]:
    seen: set[Any] = set()
    return {value for value in values if value in seen or seen.add(value)}


class HardeningControlsCatalog(_CatalogModel):
    schema_version: int = Field(ge=1, strict=True)
    catalog_id: str = Field(min_length=1, max_length=255)
    catalog_version: int = Field(ge=1, strict=True)
    status: CatalogLifecycle
    engine: Literal["postgresql"]
    maximum_reconciliation_iterations: int = Field(ge=1, le=3, strict=True)
    control_activation_policy: ControlActivationPolicy
    knowledge_sources: tuple[KnowledgeSource, ...] = Field(min_length=1)
    assessment_providers: AssessmentProviders
    baseline_profiles: tuple[BaselineProfileSpec, ...]
    baseline_controls: tuple[BaselineControlSpec, ...]
    template_assessments: tuple[TemplateAssessmentSpec, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def identifiers_are_unique(self):
        checks = {
            "knowledge source IDs": [item.source_id for item in self.knowledge_sources],
            "template name/version pairs": [
                (item.template_name, item.template_version)
                for item in self.template_assessments
            ],
            "template criterion IDs": [
                criterion.criterion_id
                for template in self.template_assessments
                for criterion in template.criteria
            ],
            "baseline profile IDs": [item.profile_id for item in self.baseline_profiles],
            "baseline control IDs": [item.control_id for item in self.baseline_controls],
        }
        for label, values in checks.items():
            repeated = _duplicates(values)
            if repeated:
                raise ValueError(f"duplicate {label}: {sorted(repeated)!r}")
        return self


@dataclass(frozen=True)
class LoadedAssessmentCatalog:
    catalog_path: Path
    catalog: HardeningControlsCatalog
    template_definitions: Mapping[
        tuple[str, int], TemplateAssessmentDefinition
    ]
    active_baseline_profiles: tuple[BaselineProfileSpec, ...]
    active_baseline_controls: tuple[BaselineControlSpec, ...]
    baseline_catalog_status: BaselineCatalogStatus


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate mapping key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


_PARAMETER_MODELS: Mapping[str, type[AssessmentParameters]] = MappingProxyType(
    {
        "read_only_role": ReadOnlyRoleParameters,
        "revoke_public_access": RevokePublicAccessParameters,
    }
)

_VERIFIER_IDS = frozenset(
    READ_ONLY_ROLE_VERIFIER_IDS | REVOKE_PUBLIC_ACCESS_VERIFIER_IDS
)


def _parameter_model_for(name: str) -> type[AssessmentParameters]:
    try:
        return _PARAMETER_MODELS[name]
    except KeyError as exc:
        raise AssessmentCatalogError(
            f"unknown parameter_model {name!r}; no AI or dynamic import fallback is allowed"
        ) from exc


def _validate_template_path(template_path: str) -> None:
    repository_root = Path(__file__).resolve().parents[2]
    candidate = (repository_root / template_path).resolve()
    try:
        candidate.relative_to(repository_root)
    except ValueError as exc:
        raise AssessmentCatalogError(
            f"template_path escapes the repository: {template_path!r}"
        ) from exc
    if not candidate.is_file():
        raise AssessmentCatalogError(
            f"template_path does not identify a file: {template_path!r}"
        )


def _validate_parameter_contract(
    template: TemplateAssessmentSpec,
    parameter_model: type[AssessmentParameters],
) -> None:
    fields = parameter_model.model_fields
    yaml_names = set(template.parameters)
    model_names = set(fields)
    if yaml_names != model_names:
        raise AssessmentCatalogError(
            f"parameter contract mismatch for {template.template_name!r}: "
            f"YAML={sorted(yaml_names)!r}, model={sorted(model_names)!r}"
        )

    for name, spec in template.parameters.items():
        field = fields[name]
        if spec.required != field.is_required():
            raise AssessmentCatalogError(
                f"required flag mismatch for {template.template_name}.{name}"
            )
        if not field.is_required() and spec.default != field.default:
            raise AssessmentCatalogError(
                f"default mismatch for {template.template_name}.{name}: "
                f"YAML={spec.default!r}, model={field.default!r}"
            )


def _build_template_definitions(
    catalog: HardeningControlsCatalog,
) -> Mapping[tuple[str, int], TemplateAssessmentDefinition]:
    known_templates = {
        (item.template_name, item.template_version)
        for item in catalog.template_assessments
    }
    definitions: dict[tuple[str, int], TemplateAssessmentDefinition] = {}

    for template in catalog.template_assessments:
        _validate_template_path(template.template_path)
        parameter_model = _parameter_model_for(template.parameter_model)
        _validate_parameter_contract(template, parameter_model)

        criteria: list[AssessmentCriterion] = []
        for criterion in template.criteria:
            if criterion.verifier_id not in _VERIFIER_IDS:
                raise AssessmentCatalogError(
                    f"unknown verifier_id {criterion.verifier_id!r}; "
                    "only reviewed executor checks may be registered"
                )
            remediation = criterion.remediation
            if remediation.template_name is not None:
                remediation_key = (
                    remediation.template_name,
                    remediation.template_version,
                )
                if remediation_key not in known_templates:
                    raise AssessmentCatalogError(
                        f"criterion {criterion.criterion_id!r} references unknown "
                        f"remediation template {remediation_key!r}"
                    )

            criteria.append(
                AssessmentCriterion(
                    criterion_id=criterion.criterion_id,
                    title=criterion.title,
                    suite=criterion.suite,
                    verifier_id=criterion.verifier_id,
                    expected_value=criterion.expected_value,
                    evidence_types=criterion.evidence_types,
                    remediation_template_name=remediation.template_name,
                    remediation_template_version=remediation.template_version,
                    reconcile_on_failure=remediation.reconcile_on_failure,
                )
            )

        key = (template.template_name, template.template_version)
        definitions[key] = TemplateAssessmentDefinition(
            template_name=template.template_name,
            template_version=template.template_version,
            parameter_model=parameter_model,
            criteria=tuple(criteria),
        )

    return MappingProxyType(definitions)


def _validate_baseline_catalog(
    catalog: HardeningControlsCatalog,
    template_definitions: Mapping[tuple[str, int], TemplateAssessmentDefinition],
) -> tuple[
    tuple[BaselineProfileSpec, ...],
    tuple[BaselineControlSpec, ...],
    BaselineCatalogStatus,
]:
    sources = {source.source_id: source for source in catalog.knowledge_sources}
    controls = {control.control_id: control for control in catalog.baseline_controls}
    allowed_statuses = set(
        catalog.control_activation_policy.allowed_source_review_statuses
    )

    for control in catalog.baseline_controls:
        if (
            control.assessment.provider == AssessmentProviderName.DBGUARD
            and control.assessment.verifier_id not in _VERIFIER_IDS
        ):
            raise AssessmentCatalogError(
                f"baseline control {control.control_id!r} uses unknown verifier_id "
                f"{control.assessment.verifier_id!r}"
            )

        for reference in control.source_references:
            source = sources.get(reference.source_id)
            if source is None:
                raise AssessmentCatalogError(
                    f"baseline control {control.control_id!r} references unknown "
                    f"source {reference.source_id!r}"
                )
            if source.version != reference.source_version:
                raise AssessmentCatalogError(
                    f"baseline control {control.control_id!r} source-version mismatch: "
                    f"{reference.source_version!r} != {source.version!r}"
                )
            if control.review_status == SourceReviewStatus.APPROVED and (
                source.review_status not in allowed_statuses
                or not source.approved_for_control_authoring
            ):
                raise AssessmentCatalogError(
                    f"approved baseline control {control.control_id!r} uses source "
                    f"{source.source_id!r} that is not approved for control authoring"
                )

        remediation = control.remediation
        if remediation.template_name is not None and (
            remediation.template_name,
            remediation.template_version,
        ) not in template_definitions:
            raise AssessmentCatalogError(
                f"baseline control {control.control_id!r} references an unknown "
                "remediation template version"
            )

        provider = control.assessment.provider
        provider_enabled = (
            catalog.assessment_providers.dbguard.enabled
            if provider == AssessmentProviderName.DBGUARD
            else catalog.assessment_providers.cis_cat.enabled
        )
        if control.review_status == SourceReviewStatus.APPROVED and not provider_enabled:
            raise AssessmentCatalogError(
                f"approved baseline control {control.control_id!r} uses disabled "
                f"provider {provider.value!r}"
            )

    for profile in catalog.baseline_profiles:
        source = sources.get(profile.source_id)
        if source is None or source.version != profile.source_version:
            raise AssessmentCatalogError(
                f"baseline profile {profile.profile_id!r} has an unknown or mismatched source"
            )
        missing = set(profile.control_ids) - set(controls)
        if missing:
            raise AssessmentCatalogError(
                f"baseline profile {profile.profile_id!r} references unknown controls: "
                f"{sorted(missing)!r}"
            )
        if profile.review_status == SourceReviewStatus.APPROVED:
            if (
                source.review_status not in allowed_statuses
                or not source.approved_for_control_authoring
            ):
                raise AssessmentCatalogError(
                    f"approved baseline profile {profile.profile_id!r} uses an "
                    "unapproved source"
                )
            unapproved = [
                control_id
                for control_id in profile.control_ids
                if controls[control_id].review_status != SourceReviewStatus.APPROVED
            ]
            if unapproved:
                raise AssessmentCatalogError(
                    f"approved baseline profile {profile.profile_id!r} contains "
                    f"unapproved controls: {unapproved!r}"
                )

    active_profiles = tuple(
        item
        for item in catalog.baseline_profiles
        if item.review_status == SourceReviewStatus.APPROVED
    )
    active_controls = tuple(
        item
        for item in catalog.baseline_controls
        if item.review_status == SourceReviewStatus.APPROVED
    )
    ready = (
        catalog.status == CatalogLifecycle.APPROVED
        and bool(active_profiles)
        and bool(active_controls)
    )
    status = (
        BaselineCatalogStatus.READY
        if ready
        else BaselineCatalogStatus.NOT_READY
    )
    return active_profiles, active_controls, status


def load_assessment_catalog(
    catalog_path: str | Path | None = None,
) -> LoadedAssessmentCatalog:
    """Load and validate the catalogue without dynamic or AI-driven fallback."""
    path = Path(catalog_path) if catalog_path is not None else DEFAULT_CATALOG_PATH
    try:
        raw = yaml.load(
            path.read_text(encoding="utf-8"),
            Loader=_UniqueKeySafeLoader,
        )
    except (OSError, yaml.YAMLError) as exc:
        raise AssessmentCatalogError(
            f"unable to read assessment catalogue {path}: {exc}"
        ) from exc

    try:
        catalog = HardeningControlsCatalog.model_validate(raw)
    except ValidationError as exc:
        raise AssessmentCatalogError(
            f"invalid assessment catalogue {path}: {exc}"
        ) from exc

    definitions = _build_template_definitions(catalog)
    profiles, controls, baseline_status = _validate_baseline_catalog(
        catalog, definitions
    )
    return LoadedAssessmentCatalog(
        catalog_path=path.resolve(),
        catalog=catalog,
        template_definitions=definitions,
        active_baseline_profiles=profiles,
        active_baseline_controls=controls,
        baseline_catalog_status=baseline_status,
    )
