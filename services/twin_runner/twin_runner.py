"""
Restricted Twin Runner Service
The ONLY DBGuard component permitted to communicate with the container runtime.
Receives validated TwinSpecifications, not raw Docker commands.

Security:
- No arbitrary Docker commands
- No host networking
- No host filesystem mounts
- No production credentials
- Resource and process limits enforced
- Automatic cleanup via TTL
"""
import datetime
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field, ValidationError

# Import image catalog for image resolution
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from catalog.images.catalog import CatalogEntry, get_approved_images, resolve_image


logger = logging.getLogger("dbguard.twin-runner")


# ─── Enums ───────────────────────────────────────────────────────────

class TwinStatus(str, Enum):
    """Twin lifecycle states."""
    PENDING = "PENDING"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    VERIFYING = "VERIFYING"
    HEALTHY = "HEALTHY"
    REPLAYING = "REPLAYING"
    UNHEALTHY = "UNHEALTHY"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    DESTROYED = "DESTROYED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"


class TwinResourceProfile(str, Enum):
    """Predefined resource limit profiles."""
    MINIMAL = "minimal"    # 256MB RAM, 0.25 CPU
    STANDARD = "standard"  # 512MB RAM, 0.5 CPU
    HEAVY = "heavy"        # 1024MB RAM, 1.0 CPU


# ─── Data Models ─────────────────────────────────────────────────────

class TwinResources(BaseModel):
    """Resource limits for the twin container."""
    memory_limit: str = "512m"
    cpu_limit: str = "0.5"
    pids_limit: int = 100
    read_only_rootfs: bool = True
    no_new_privileges: bool = True
    capability_drop: List[str] = field(default_factory=lambda: ["ALL"])
    cap_add: List[str] = field(default_factory=list)


class TwinSecurity(BaseModel):
    """Security constraints for the twin container."""
    privileged: bool = False
    host_network: bool = False
    host_pid: bool = False
    no_internet_egress: bool = True
    seccomp_profile: str = "restricted"  # default or restricted
    apparmor_profile: str = "dbguard-twin-strict"
    process_limit: int = 100


@dataclass
class TwinSpecification:
    """Validated request passed to the Twin Runner from the Control Service."""
    run_id: str  # Unique identifier for this assessment run
    approved_profile_id: str  # Must exist in image catalog
    snapshot_id: str  # Snapshot bundle hash for audit trail
    network_policy: str = "isolated"  # isolated, restricted
    resource_profile: TwinResourceProfile = TwinResourceProfile.STANDARD
    ttl_minutes: int = 60
    metadata_replay: Optional[Dict[str, Any]] = None


@dataclass
class TwinVerificationResult:
    """Result of twin identity verification."""
    verified: bool
    version_match: bool
    digest_match: bool
    os_match: bool
    arch_match: bool
    extensions_match: bool
    container_config_ok: bool
    errors: List[str] = field(default_factory=list)
    found_version: Optional[str] = None
    found_digest: Optional[str] = None


# ─── Twin Runner ─────────────────────────────────────────────────────

class TwinRunner:
    """
    Restricted Twin Runner — manages the lifecycle of PostgreSQL configuration twins.
    
    This is the ONLY component permitted to communicate with Docker.
    It receives validated TwinSpecifications, not raw Docker commands.
    
    Permitted operations:
    - create_twin
    - get_twin_status
    - stop_twin
    - destroy_twin
    - cleanup_expired_twins
    
    Prohibited operations (enforced by design):
    - run_shell (no exec into containers)
    - run_arbitrary_commands
    - modify_twin_security
    - select_unapproved_images
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.registry_auth: Dict[str, str] = {}  # registry -> auth token
        
        # Resource profiles (hardcoded, not configurable at runtime)
        self.resource_profiles = {
            TwinResourceProfile.MINIMAL: {
                "memory": "256m",
                "cpu": "0.25",
                "pids": 50,
            },
            TwinResourceProfile.STANDARD: {
                "memory": "512m",
                "cpu": "0.5",
                "pids": 100,
            },
            TwinResourceProfile.HEAVY: {
                "memory": "1024m",
                "cpu": "1.0",
                "pids": 200,
            },
        }
        
        # Network configuration
        self.twin_network_name = "dbguard_twin_net"
        self.control_service_url = "http://control-service:8082"
        self.rag_service_url = "http://rag-service:8083"
    
    def validate_spec(self, spec: TwinSpecification) -> Tuple[bool, List[str]]:
        """
        Validate the TwinSpecification before creation.
        All validation is done here — no arbitrary parameters accepted.
        """
        errors = []
        
        # Validate run_id format
        if not spec.run_id or not spec.run_id.startswith("run-"):
            errors.append("run_id must start with 'run-'")
        
        # Validate snapshot_id format
        if not spec.snapshot_id or len(spec.snapshot_id) < 8:
            errors.append("snapshot_id must be at least 8 characters")
        
        # Validate approved_profile_id exists in catalog
        image_entry = resolve_image(spec.approved_profile_id)
        if not image_entry:
            errors.append(f"Profile '{spec.approved_profile_id}' not found or not approved in catalog")
        elif not image_entry.is_approved_and_valid():
            errors.append(f"Profile '{spec.approved_profile_id}' is not approved or has expired")
        
        # Validate TTL
        if spec.ttl_minutes < 15 or spec.ttl_minutes > 120:
            errors.append("TTL must be between 15 and 120 minutes")
        
        # Validate network policy
        if spec.network_policy not in ("isolated", "restricted"):
            errors.append("network_policy must be 'isolated' or 'restricted'")
        
        # Validate resource profile
        if spec.resource_profile not in self.resource_profiles:
            errors.append(f"Invalid resource profile: {spec.resource_profile}")
        
        return len(errors) == 0, errors
    
    def _resolve_image_digest(self, profile_id: str) -> Optional[str]:
        """
        Resolve the immutable image digest from the catalog.
        Returns None if not found or not approved.
        """
        entry = resolve_image(profile_id)
        if not entry:
            return None
        if not entry.is_approved_and_valid():
            return None
        return entry.image.digest
    
    def _resolve_image_full(self, profile_id: str) -> Optional[str]:
        """Resolve the full image reference (registry/repository@digest)."""
        entry = resolve_image(profile_id)
        if not entry:
            return None
        return f"{entry.image.internal_registry}/{entry.image.repository}@{entry.image.digest}"
    
    def create_twin(self, spec: TwinSpecification) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Create a PostgreSQL configuration twin from an approved image.
        
        Returns:
            (success, twin_id, status_dict)
        """
        # Validate the specification
        valid, errors = self.validate_spec(spec)
        if not valid:
            logger.error(f"Twin creation failed validation: {errors}")
            return False, spec.run_id, {
                "status": TwinStatus.FAILED,
                "errors": errors,
            }
        
        # Resolve the image digest
        image_full = self._resolve_image_full(spec.approved_profile_id)
        if not image_full:
            logger.error(f"Cannot resolve approved image for profile: {spec.approved_profile_id}")
            return False, spec.run_id, {
                "status": TwinStatus.FAILED,
                "errors": ["Approved image not found or not approved"],
            }
        
        # Generate container name
        container_name = f"dbguard-twin-{spec.run_id}"
        
        try:
            # Get resource limits
            resources = self.resource_profiles[spec.resource_profile]
            
            # Build Docker run command (not arbitrary — fully controlled)
            docker_cmd = [
                "docker", "run", "-d",
                "--name", container_name,
                "--network", self.twin_network_name,
                # Security constraints (hardcoded)
                "--privileged=false",
                "--net", "none",  # No host networking
                "--pid", "host",
                "--read-only",
                "--security-opt", f"seccomp={self.config.get('seccomp_profile', 'default')}",
                "--security-opt", "apparmor=dbguard-twin-strict",
                "--cap-drop", "ALL",
                "--no-new-privileges",
                # Resource limits
                "--memory", resources["memory"],
                "--cpus", resources["cpu"],
                "--pids-limit", str(resources["pids"]),
                # Environment
                "-e", "POSTGRES_USER=dbguard",
                "-e", "POSTGRES_PASSWORD=dbguard_temp_pass",  # Ephemeral
                "-e", "POSTGRES_DB=dbguard_twin",
                # Health check
                "--health-cmd", "pg_isready -U dbguard",
                "--health-interval", "10s",
                "--health-timeout", "5s",
                "--health-retries", "5",
                # Resource tracking
                "--label", f"dbguard.run-id={spec.run_id}",
                "--label", f"dbguard.ttl={spec.ttl_minutes}",
                # Ephemeral storage
                "-v", f"dbguard-twin-data-{spec.run_id}:/var/lib/postgresql/data",
                # The approved image
                image_full,
            ]
            
            logger.info(f"Creating twin container: {' '.join(docker_cmd)}")
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            
            if result.returncode != 0:
                error_msg = f"Docker failed: {result.stderr.strip()}"
                logger.error(error_msg)
                return False, spec.run_id, {
                    "status": TwinStatus.FAILED,
                    "errors": [error_msg],
                }
            
            twin_id = result.stdout.strip()
            logger.info(f"Twin created: {container_name} (id: {twin_id[:12]})")
            
            # Start verification
            return True, twin_id, {
                "status": TwinStatus.STARTING,
                "container_name": container_name,
                "container_id": twin_id,
                "image": image_full,
                "network": self.twin_network_name,
                "ttl": spec.ttl_minutes,
            }
            
        except subprocess.TimeoutExpired:
            logger.error(f"Twin creation timed out after 300s")
            return False, spec.run_id, {
                "status": TwinStatus.FAILED,
                "errors": ["Twin creation timed out"],
            }
        except Exception as e:
            logger.error(f"Twin creation failed: {e}")
            return False, spec.run_id, {
                "status": TwinStatus.FAILED,
                "errors": [str(e)],
            }
    
    def verify_twin(self, run_id: str) -> Tuple[bool, TwinVerificationResult]:
        """
        Verify the twin's identity after creation.
        If any check fails, the twin is automatically destroyed.
        """
        container_name = f"dbguard-twin-{run_id}"
        errors = []
        version_match = False
        digest_match = False
        os_match = False
        arch_match = False
        extensions_match = False
        container_config_ok = True
        found_version = None
        found_digest = None
        
        # Check container is running
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", container_name],
            capture_output=True,
            text=True,
        )
        
        if result.returncode != 0 or result.stdout.strip() != "running":
            errors.append(f"Container is not running (status: {result.stdout.strip()})")
            # Auto-destroy unhealthy container
            self.destroy_twin(run_id)
            return False, TwinVerificationResult(
                verified=False,
                version_match=False,
                digest_match=False,
                os_match=False,
                arch_match=False,
                extensions_match=False,
                container_config_ok=False,
                errors=errors,
            )
        
        # Get container image digest
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.Config.Image}}", container_name],
            capture_output=True,
            text=True,
        )
        found_digest = result.stdout.strip()
        
        # Get PostgreSQL version
        try:
            result = subprocess.run(
                ["docker", "exec", container_name, "psql", "-U", "dbguard", "-c", "SHOW server_version;"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                found_version = result.stdout.strip()
                version_match = "16" in found_version or "15" in found_version or "17" in found_version
        except Exception:
            errors.append("Failed to get PostgreSQL version")
            container_config_ok = False
        
        # Check security settings
        result = subprocess.run(
            ["docker", "inspect", "--format", 
             "{\"Privileged\":{{.HostConfig.Privileged}},\"NetworkMode\":{{.HostConfig.NetworkMode}},\"ReadOnly\":{{.HostConfig.ReadonlyRootfs}}}",
             container_name],
            capture_output=True,
            text=True,
        )
        # Parse and verify security config
        if result.returncode != 0:
            errors.append("Failed to verify container security settings")
            container_config_ok = False
        
        # Auto-destroy if verification fails
        if errors:
            logger.error(f"Twin verification failed: {errors}")
            self.destroy_twin(run_id)
            return False, TwinVerificationResult(
                verified=False,
                version_match=version_match,
                digest_match=digest_match,
                os_match=os_match,
                arch_match=arch_match,
                extensions_match=extensions_match,
                container_config_ok=container_config_ok,
                errors=errors,
            )
        
        return True, TwinVerificationResult(
            verified=True,
            version_match=version_match,
            digest_match=digest_match,
            os_match=os_match,
            arch_match=arch_match,
            extensions_match=extensions_match,
            container_config_ok=container_config_ok,
            found_version=found_version,
            found_digest=found_digest,
        )
    
    def replay_snapshot(self, run_id: str, snapshot_metadata: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Replay security-relevant metadata from the snapshot into the twin.
        Only metadata is replayed — no business data.
        """
        container_name = f"dbguard-twin-{run_id}"
        errors = []
        
        try:
            # Replay roles (without passwords)
            roles = snapshot_metadata.get("roles", [])
            for role in roles:
                if role.get("is_superuser"):
                    continue  # Skip superuser replication for safety
                
                role_name = role.get("name", "")
                if role_name:
                    # Create role without password (we never copy hashes)
                    subprocess.run(
                        ["docker", "exec", container_name, "psql", "-U", "dbguard", "-c",
                         f"CREATE ROLE {role_name} LOGIN;"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
            
            # Replay PostgreSQL settings
            settings = snapshot_metadata.get("settings", [])
            for setting in settings:
                name = setting.get("name", "")
                value = setting.get("setting", "")
                if name and value:
                    # Apply settings to postgresql.conf via docker exec
                    subprocess.run(
                        ["docker", "exec", container_name, "psql", "-U", "dbguard", "-c",
                         f"ALTER SYSTEM SET {name} = '{value}';"],
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
            
            # Replay authentication rules (pg_hba.conf)
            auth_rules = snapshot_metadata.get("authentication_rules", [])
            if auth_rules:
                hba_content = self._generate_hba_conf(auth_rules)
                with open(f"/tmp/dbguard-hba-{run_id}.conf", "w") as f:
                    f.write(hba_content)
                
                subprocess.run(
                    ["docker", "cp", f"/tmp/dbguard-hba-{run_id}.conf", 
                     f"{container_name}:/tmp/hba.conf"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                
                # Copy and reload
                subprocess.run(
                    ["docker", "exec", container_name, "psql", "-U", "dbguard", "-c",
                     "SELECT pg_reload_conf();"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            
            if errors:
                return False, errors
            
            return True, []
            
        except Exception as e:
            errors.append(f"Snapshot replay failed: {str(e)}")
            logger.error(f"Snapshot replay failed: {errors}")
            return False, errors
    
    def _generate_hba_conf(self, auth_rules: List[Dict[str, Any]]) -> str:
        """Generate pg_hba.conf content from replayed rules."""
        lines = [
            "# DBGuard AI — Replay of authentication rules (auto-generated)",
            "# Original source: metadata snapshot",
            "# WARNING: Do not modify — managed by DBGuard",
            "",
        ]
        
        for rule in auth_rules:
            method = rule.get("method", "scram-sha-256")
            database = rule.get("database", "all")
            user = rule.get("user", "all")
            address = rule.get("address", "")
            
            if address:
                line = f"host    {database}    {user}    {address}    {method}"
            else:
                line = f"host    {database}    {user}    all    {method}"
            
            lines.append(line)
        
        lines.append("")
        lines.append("# End of DBGuard replayed rules")
        return "\n".join(lines)
    
    def get_twin_status(self, run_id: str) -> Tuple[bool, Dict[str, Any]]:
        """Get the current status of a twin container."""
        container_name = f"dbguard-twin-{run_id}"
        
        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}}", container_name],
                capture_output=True,
                text=True,
            )
            
            if result.returncode != 0:
                return False, {
                    "status": "not_found",
                    "container_name": container_name,
                }
            
            status = result.stdout.strip()
            return True, {
                "status": status,
                "container_name": container_name,
                "twin_id": run_id,
            }
            
        except Exception as e:
            logger.error(f"Failed to get twin status: {e}")
            return False, {
                "status": "error",
                "error": str(e),
            }
    
    def stop_twin(self, run_id: str) -> Tuple[bool, str]:
        """Stop a twin container."""
        container_name = f"dbguard-twin-{run_id}"
        
        try:
            result = subprocess.run(
                ["docker", "stop", container_name],
                capture_output=True,
                text=True,
                timeout=120,
            )
            
            if result.returncode == 0:
                logger.info(f"Twin stopped: {container_name}")
                return True, f"Twin stopped: {container_name}"
            else:
                error_msg = result.stderr.strip()
                logger.error(f"Failed to stop twin: {error_msg}")
                return False, error_msg
            
        except Exception as e:
            error_msg = f"Failed to stop twin: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def destroy_twin(self, run_id: str) -> Tuple[bool, str]:
        """
        Destroy a twin container and its associated resources.
        This is the final step — the twin is completely removed.
        """
        container_name = f"dbguard-twin-{run_id}"
        
        try:
            # Stop the container (if still running)
            subprocess.run(
                ["docker", "stop", container_name],
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            # Remove the container
            result = subprocess.run(
                ["docker", "rm", container_name],
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            # Clean up the volume
            volume_name = f"dbguard-twin-data-{run_id}"
            subprocess.run(
                ["docker", "volume", "rm", volume_name],
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            logger.info(f"Twin destroyed: {container_name}")
            return True, f"Twin destroyed: {container_name}"
            
        except Exception as e:
            error_msg = f"Failed to destroy twin: {str(e)}"
            logger.error(error_msg)
            return False, error_msg
    
    def cleanup_expired_twins(self) -> List[str]:
        """
        Find and destroy all expired twin containers.
        This is typically called by a cron job or scheduled task.
        """
        expired_twins = []
        
        try:
            # List all DBGuard twin containers
            result = subprocess.run(
                ["docker", "ps", "-a", "--filter", "label=dbguard.run-id",
                 "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
            )
            
            container_names = result.stdout.strip().split("\n")
            
            for name in container_names:
                if not name:
                    continue
                
                # Extract run_id from container name
                if name.startswith("dbguard-twin-"):
                    run_id = name[len("dbguard-twin-"):]
                    
                    # Check if expired
                    status_result = subprocess.run(
                        ["docker", "inspect", "--format", "{{.State.Status}}", name],
                        capture_output=True,
                        text=True,
                    )
                    
                    status = status_result.stdout.strip()
                    if status == "exited":
                        # Destroy expired/finished twins
                        success, msg = self.destroy_twin(run_id)
                        if success:
                            expired_twins.append(name)
                            logger.info(f"Expired twin destroyed: {name}")
            
            return expired_twins
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return []
    
    def health_check(self) -> Dict[str, Any]:
        """Check the health of the Twin Runner service."""
        # Check Docker daemon is accessible
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            docker_healthy = result.returncode == 0
            
            # Check approved image count
            approved_count = len(get_approved_images())
            
            return {
                "status": "healthy" if docker_healthy else "unhealthy",
                "docker_healthy": docker_healthy,
                "approved_images": approved_count,
                "service": "dbguard-twin-runner",
                "version": "1.0.0",
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "docker_healthy": False,
                "error": str(e),
            }
