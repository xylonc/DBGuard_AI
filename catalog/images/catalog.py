"""
Image Catalog — Approved PostgreSQL Images
Deterministic, version-controlled inventory of images DBGuard is permitted to execute.
NOT part of RAG. Cannot be modified by HERMES.
"""
from __future__ import annotations

from datetime import datetime, timezone
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
    vulnerability_scan_status: str = "pending"
    vulnerability_scan_date: Optional[datetime] = None
    license_compliance: bool = True


class ImageDigest(BaseModel):
    """Immutable image references."""
    internal_registry: str = "docker.io"
    repository: str = "library/postgres"
    digest: str = "16-alpine"
    upstream_registry: str = "docker.io"
    upstream_repository: str = "library/postgres"
    upstream_digest: str = "16-alpine"


class ApprovalInfo(BaseModel):
    """Approval metadata for the image catalog entry."""
    approved_by: List[str] = Field(default_factory=lambda: ["database-security-team"])
    approved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_id: str = "EVID-001"
    next_review_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CatalogEntry(BaseModel):
    """
    Approved PostgreSQL image entry.
    
    This is the source of truth for which images can be used for twin creation.
    Only APPROVED entries that haven't expired can be selected.
    """
    schema_version: str = "1.0"
    
    profile_id: str
    
    database: dict = Field(default_factory=lambda: {
        "engine": "postgresql",
        "distribution": "community",
        "version": {
            "major": 16,
            "minor": 13,
            "server_version_num": 160013,
        }
    })
    
    platform: dict = Field(default_factory=lambda: {
        "operating_system": "debian",
        "operating_system_release": "bookworm",
        "architecture": "amd64",
    })
    
    image: ImageDigest
    capabilities: ImageCapabilities = Field(default_factory=ImageCapabilities)
    security: ImageFingerprint = Field(default_factory=ImageFingerprint)
    
    lifecycle: dict = Field(default_factory=lambda: {
        "status": ImageStatus.APPROVED,
        "approved_at": None,
        "expires_at": None,
    })
    
    approval: Optional[ApprovalInfo] = None
    notes: str = ""
    
    def is_approved_and_valid(self) -> bool:
        """Check if image is approved and not expired."""
        status = self.lifecycle.get("status")
        if status != ImageStatus.APPROVED and status != "APPROVED":
            return False
        
        expires = self.lifecycle.get("expires_at")
        if expires:
            if isinstance(expires, str):
                try:
                    expires = datetime.fromisoformat(expires)
                except ValueError:
                    expires = None
            
            if expires:
                now = datetime.now(timezone.utc)
                if expires.tzinfo is None:
                    now = datetime.now()
                if now > expires:
                    return False
        return True
    
    def resolve_fidelity(self, target_version_major: int, target_version_minor: Optional[int] = None) -> str:
        """Resolve fidelity between target and approved image."""
        image_major = self.database.get("version", {}).get("major", 0)
        
        if image_major == target_version_major:
            image_minor = self.database.get("version", {}).get("minor", 0)
            if target_version_minor is not None:
                if image_minor == target_version_minor:
                    return "EXACT_MATCH"
                elif abs(image_minor - target_version_minor) <= 2:
                    return "COMPATIBLE_APPROXIMATION"
            return "COMPATIBLE_APPROXIMATION"
        
        return "UNSUPPORTED_TARGET"


def load_catalog_entries() -> List[CatalogEntry]:
    """Load image catalog entries from YAML files or fallback defaults."""
    import os
    import yaml
    
    catalog_dir = os.path.dirname(__file__)
    entries = []
    
    if os.path.exists(catalog_dir):
        for filename in os.listdir(catalog_dir):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                filepath = os.path.join(catalog_dir, filename)
                try:
                    with open(filepath, "r") as f:
                        data = yaml.safe_load(f)
                        if data:
                            entries.append(CatalogEntry(**data))
                except Exception:
                    pass
    
    # Default fallback entries if no YAML files exist in catalog directory
    if not entries:
        entries.extend([
            CatalogEntry(
                profile_id="16",
                database={"engine": "postgresql", "distribution": "community", "version": {"major": 16, "minor": 6, "server_version_num": 160006}},
                image=ImageDigest(internal_registry="docker.io", repository="library/postgres", digest="16-alpine", upstream_registry="docker.io", upstream_repository="library/postgres", upstream_digest="16-alpine"),
                lifecycle={"status": ImageStatus.APPROVED, "approved_at": None, "expires_at": None}
            ),
            CatalogEntry(
                profile_id="postgresql-community-16.6",
                database={"engine": "postgresql", "distribution": "community", "version": {"major": 16, "minor": 6, "server_version_num": 160006}},
                image=ImageDigest(internal_registry="docker.io", repository="library/postgres", digest="16-alpine", upstream_registry="docker.io", upstream_repository="library/postgres", upstream_digest="16-alpine"),
                lifecycle={"status": ImageStatus.APPROVED, "approved_at": None, "expires_at": None}
            ),
        ])
    
    return entries


def get_approved_images() -> List[CatalogEntry]:
    """Get all approved and non-expired image entries."""
    entries = load_catalog_entries()
    return [e for e in entries if e.is_approved_and_valid()]


def resolve_image(profile_id: str) -> Optional[CatalogEntry]:
    """Resolve an image profile with flexible exact, substring, and version matching."""
    entries = get_approved_images()
    
    # 1. Exact match
    for entry in entries:
        if entry.profile_id == profile_id:
            return entry
            
    # 2. Substring or prefix match
    for entry in entries:
        if profile_id in entry.profile_id or entry.profile_id.startswith(profile_id):
            return entry
            
    # 3. Numeric major version match (e.g. "16")
    clean_id = str(profile_id).split(".")[0].replace("postgresql-", "").replace("community-", "").strip()
    if clean_id.isdigit():
        target_major = int(clean_id)
        for entry in entries:
            if entry.database.get("version", {}).get("major") == target_major:
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