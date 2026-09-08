"""Evidence capture boundary for deterministic PostgreSQL assessments."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Protocol

from services.assessment.models import EvidenceReference, EvidenceType


@dataclass(frozen=True)
class EvidenceArtifact:
    """One immutable assessment observation retained by an evidence sink."""

    evidence_id: str
    run_id: str
    verifier_id: str
    evidence_type: EvidenceType
    captured_at: datetime
    description: str
    content: str
    content_sha256: str


class EvidenceSink(Protocol):
    """Storage boundary that a later persistent evidence service can implement."""

    def record(
        self,
        *,
        verifier_id: str,
        evidence_type: EvidenceType,
        description: str,
        content: str,
    ) -> EvidenceReference:
        ...


class InMemoryEvidenceSink:
    """Retain immutable evidence for one assessment run without filesystem I/O."""

    def __init__(self, run_id: str):
        if not run_id:
            raise ValueError("run_id is required")
        self.run_id = run_id
        self._artifacts: list[EvidenceArtifact] = []

    @property
    def artifacts(self) -> tuple[EvidenceArtifact, ...]:
        return tuple(self._artifacts)

    def record(
        self,
        *,
        verifier_id: str,
        evidence_type: EvidenceType,
        description: str,
        content: str,
    ) -> EvidenceReference:
        captured_at = datetime.now(timezone.utc)
        content_digest = sha256(content.encode("utf-8")).hexdigest()
        sequence = len(self._artifacts) + 1
        evidence_id = (
            f"evidence-{self.run_id}-{sequence:03d}-{content_digest[:12]}"
        )
        artifact = EvidenceArtifact(
            evidence_id=evidence_id,
            run_id=self.run_id,
            verifier_id=verifier_id,
            evidence_type=evidence_type,
            captured_at=captured_at,
            description=description,
            content=content,
            content_sha256=content_digest,
        )
        self._artifacts.append(artifact)
        return EvidenceReference(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            description=(
                f"{description}; sha256={content_digest}"
            )[:1000],
        )
