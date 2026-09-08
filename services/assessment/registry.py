"""Closed registry loaded from the reviewed hardening-control catalogue."""

from services.assessment.catalog_loader import (
    LoadedAssessmentCatalog,
    load_assessment_catalog,
)
from services.assessment.definition import TemplateAssessmentDefinition
from services.assessment.models import BaselineCatalogStatus


class AssessmentDefinitionNotFound(LookupError):
    """Raised when a template has no reviewed assessment definition."""


_CATALOG: LoadedAssessmentCatalog = load_assessment_catalog()
_DEFINITIONS = _CATALOG.template_definitions


def get_assessment_definition(
    template_name: str,
    template_version: int,
) -> TemplateAssessmentDefinition:
    """Load an exact allowlisted definition without fuzzy or AI fallback."""
    try:
        return _DEFINITIONS[(template_name, template_version)]
    except KeyError as exc:
        raise AssessmentDefinitionNotFound(
            "No approved assessment definition exists for template "
            f"{template_name!r} version {template_version}"
        ) from exc


def list_assessment_templates() -> tuple[tuple[str, int], ...]:
    """Return exact template versions defined by the validated YAML catalogue."""
    return tuple(sorted(_DEFINITIONS))


def get_baseline_catalog_status() -> BaselineCatalogStatus:
    """Return READY only when an approved, non-empty baseline is loaded."""
    return _CATALOG.baseline_catalog_status


def get_loaded_assessment_catalog() -> LoadedAssessmentCatalog:
    """Expose immutable validated catalogue data to trusted backend services."""
    return _CATALOG
