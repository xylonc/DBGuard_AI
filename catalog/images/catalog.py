"""
Image Catalog — Approved PostgreSQL Images
Deterministic, version-controlled inventory of images DBGuard is permitted to execute.
NOT part of RAG. Cannot be modified by HERMES.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ImageStatus(str, Enum):
    """Image catalog lifecycle states."""
    DISCOVERED = "DISCOVERED"
    CANDIDATE = "CANDIDATE"
    TESTING = "TESTING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    DEPRECATED = "DEPRECATED"
    REVOKED = "REVOKED"


class ImageCapabilities(BaseModel):
    """Capabilities of a PostgreSQL image for hardening testing."""
    extensions: List[str] = Field(default_factory=list)
    supports_hba_testing: bool = True
    supports_tls_testing: bool = True
    supports_ssl_testing: bool = True
    supports_host_controls: bool = False


class ImageFingerprint(BaseModel):
    """Security and compliance fingerprint of a PostgreSQL image."""
    signature_verified: bool = False
    sbom_available: bool = False
    sbom_hash: Optional[str] = None
    vulnerability_scan_status: str = "pending"  # passed, failed, pending
    vulnerability_scan_date: Optional[datetime] = None
    license_compliance: bool = True


class ImageDigest(BaseModel):
    """Immutable image references."""
    internal_registry: str  # registry.company.example
    repository: str  # dbguard/postgresql-community
    digest: str  # sha256:abc123...
    upstream_registry: str  # docker.io
    upstream_repository: str  # library/postgres
    upstream_digest: str  # sha256:def456...


class ApprovalInfo(BaseModel):
    """Approval metadata for the image catalog entry."""
    approved_by: List[str]  # database-security-team, platform-security-team
    approved_at: datetime
    evidence_id: str  # Reference to approval documentation
    next_review_date: datetime


class CatalogEntry(BaseModel):
    """
    Approved PostgreSQL image entry.
    
    This is the source of truth for which images can be used for twin creation.
    Only APPROVED entries that haven't expired can be selected.
    """
    schema_version: str = "1.0"
    
    # Profile identity
    profile_id: str  # e.g., postgresql-community-16.13-bookworm-amd64
    
    # Database properties
    database: dict = Field(default_factory=lambda: {
        "engine": "postgresql",
        "distribution": "community",
        "version": {
            "major": 16,
            "minor": 13,
            "server_version_num": 160013,
        }
    })
    
    # Platform properties
    platform: dict = Field(default_factory=lambda: {
        "operating_system": "debian",
        "operating_system_release": "bookworm",
        "architecture": "amd64",
    })
    
    # Image references
    image: ImageDigest
    capabilities: ImageCapabilities
    
    # Security
    security: ImageFingerprint = Field(default_factory=ImageFingerprint)
    
    # Lifecycle
    lifecycle: dict = Field(default_factory=lambda: {
        "status": ImageStatus.CANDIDATE,
        "approved_at": None,
        "expires_at": None,
    })
    
    # Approval metadata
    approval: Optional[ApprovalInfo] = None
    
    # Notes
    notes: str = ""
    
    def is_approved_and_valid(self) -> bool:
        """Check if image is approved and not expired."""
        if not self.lifecycle.get("status") == ImageStatus.APPROVED:
            return False
        expires = self.lifecycle.get("expires_at")
        if expires and datetime.utcnow() > expires:
            return False
        return True
    
    def resolve_fidelity(self, target_version_major: int) -> str:
        """
        Resolve fidelity between target and approved image.
        
        Returns one of:
        - EXACT_MATCH
        - COMPATIBLE_APPROXIMATION
        - UNSUPPORTED_TARGET
        """
        image_major = self.database.get("version", {}).get("major", 0)
        
        if image_major == target_version_major:
            # Check if exact or approximate
            target_minor = target_version_major  # Simplified
            image_minor = self.database.get("version", {}).get("minor", 0)
            
            if abs(image_minor - target_minor) <= 1:
                return "COMPATIBLE_APPROXIMATION"
            return "EXACT_MATCH"
        
        return "UNSUPPORTED_TARGET"


def load_catalog_entries() -> List[CatalogEntry]:
    """
    Load all approved image catalog entries.
    
    In production, this reads from the catalog/images/ directory.
    """
    import os
    import yaml
    
    catalog_dir = os.path.join(os.path.dirname(__file__), "..", "..", "catalog", "images")
    
    if not os.path.exists(catalog_dir):
        return []
    
    entries = []
    for filename in os.listdir(catalog_dir):
        if filename.endswith(".yaml"):
            filepath = os.path.join(catalog_dir, filename)
            with open(filepath, "r") as f:
                data = yaml.safe_load(f)
                entries.append(CatalogEntry(**data))
    
    return entries


def get_approved_images() -> List[CatalogEntry]:
    """Get all approved and non-expired image entries."""
    entries = load_catalog_entries()
    return [e for e in entries if e.is_approved_and_valid()]


def resolve_image(profile_id: str) -> Optional[CatalogEntry]:
    """Resolve a specific image profile."""
    entries = get_approved_images()
    for entry in entries:
        if entry.profile_id == profile_id:
            return entry
    return None


def find_by_version(major: int, minor: int) -> List[CatalogEntry]:
    """Find all approved images matching a version."""
    entries = get_approved_images()
    results = []
    for entry in entries:
        db_version = entry.database.get("version", {})
        if db_version.get("major") == major and db_version.get("minor") == minor:
            results.append(entry)
    return results
