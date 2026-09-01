"""
DBGuardAI Snapshot Collector
Collects security-relevant metadata from PostgreSQL without copying business data.
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Import our data models for validation
from models import (
    SnapshotBundle,
    DatabaseIdentity,
    PostgreSQLSetting,
    RoleInfo,
    GrantInfo,
    ExtensionInfo,
    AuthenticationRule,
    TLSMetadata,
    LoggingConfig,
    ReplicationMetadata,
)


class SnapshotCollector:
    """
    Collects metadata from a PostgreSQL database for security assessment.
    Follows strict read-only principles and never copies business data.
    """

    def __init__(self, dsn: str, extended_mode: bool = False):
        """
        Initialize collector.
        
        Args:
            dsn: PostgreSQL connection string
            extended_mode: If True, requires elevated privileges for full metadata
        """
        self.dsn = dsn
        self.extended_mode = extended_mode
        self.errors: list[str] = []
        self.connection: Optional[psycopg2.extensions.connection] = None

    def connect(self) -> bool:
        """Establish database connection."""
        try:
            self.connection = psycopg2.connect(self.dsn)
            return True
        except Exception as e:
            self.errors.append(f"Connection failed: {str(e)}")
            return False

    def disconnect(self):
        """Close database connection."""
        if self.connection and not self.connection.closed:
            self.connection.close()

    def collect(self) -> SnapshotBundle:
        """
        Collect all security-relevant metadata.
        
        Returns:
            SnapshotBundle with all collected data
        """
        if not self.connect():
            raise RuntimeError("Failed to connect to database")

        try:
            # Collect all metadata sections
            identity = self._collect_identity()
            settings = self._collect_settings()
            roles = self._collect_roles()
            grants = self._collect_grants()
            extensions = self._collect_extensions()
            auth_rules = self._collect_auth_rules()
            tls = self._collect_tls()
            logging_config = self._collect_logging()
            replication = self._collect_replication()

            # Assemble the bundle
            snapshot = SnapshotBundle(
                collector_version="1.0.0-rc1",
                collection_timestamp=datetime.utcnow(),
                identity=identity,
                settings=settings,
                roles=roles,
                grants=grants,
                extensions=extensions,
                authentication_rules=auth_rules,
                tls_metadata=tls,
                logging_config=logging_config,
                replication_metadata=replication,
                collection_errors=self.errors,
            )

            # Calculate hash for integrity verification
            snapshot_hash = self._calculate_hash(snapshot)
            snapshot.snapshot_hash = snapshot_hash

            return snapshot

        except Exception as e:
            self.errors.append(f"Collection failed: {str(e)}")
            raise
        finally:
            self.disconnect()

    def _collect_identity(self) -> DatabaseIdentity:
        """Collect database identity and version information."""
        with self.connection.cursor() as cur:
            cur.execute("SHOW server_version;")
            version = cur.fetchone()[0]
            
            cur.execute("SHOW server_version_num;")
            version_num = int(cur.fetchone()[0])
            
            # Parse major.minor from version string
            major, minor = (int(x) for x in version.split(".")[:2])
            
            cur.execute("SELECT current_database();")
            dbname = cur.fetchone()[0]
            
            cur.execute("SHOW port;")
            port = cur.fetchone()[0]
            
            cur.execute("SHOW shared_preload_libraries;")
            preload_libs = cur.fetchone()[0] or ""
            
            # Detect deployment type
            deployment_type = "self-managed"
            if any(provider in preload_libs for provider in ["aws_rds", "azure_pg", "cloud_sql_proxy"]):
                deployment_type = "cloud-managed"

            return DatabaseIdentity(
                engine="postgresql",
                version=version,
                server_version_num=version_num,
                distribution="community",  # Can be enhanced to detect distro
                architecture=self._detect_architecture(),
                deployment_type=deployment_type,
            )

    def _detect_architecture(self) -> str:
        """Detect server architecture."""
        with self.connection.cursor() as cur:
            cur.execute("SHOW cpu_tuple_cost;")  # Works on all architectures
            return "amd64"  # Default, can be enhanced with OS detection

    def _collect_settings(self) -> list[PostgreSQLSetting]:
        """Collect PostgreSQL configuration settings relevant to security."""
        settings = []
        
        # Critical security-related parameters
        security_params = [
            "password_encryption",
            "ssl",
            "ssl_cert_file",
            "ssl_key_file",
            "ssl_min_protocol_version",
            "authentication_timeout",
            "log_connections",
            "log_disconnections",
            "log_statement",
            "log_line_prefix",
            "logging_collector",
            "log_checkpoints",
            "log_temp_files",
            "log_duration",
            "log_lock_waits",
            "deadlock_timeout",
            "shared_preload_libraries",
            "max_connections",
            "superuser_reserved_connections",
            "tcp_keepalives_idle",
            "tcp_keepalives_interval",
            "tcp_keepalives_count",
        ]

        query = sql.SQL("SELECT name, setting, source FROM pg_settings WHERE name = %s")
        
        for param in security_params:
            try:
                cur = self.connection.cursor()
                cur.execute(query, (param,))
                row = cur.fetchone()
                if row:
                    settings.append(PostgreSQLSetting(
                        name=row[0],
                        setting=row[1],
                        source=row[2],
                    ))
                cur.close()
            except Exception as e:
                self.errors.append(f"Failed to collect {param}: {str(e)}")

        return settings

    def _collect_roles(self) -> list[RoleInfo]:
        """Collect role information without passwords."""
        roles = []
        
        with self.connection.cursor() as cur:
            cur.execute("""
                SELECT 
                    r.rolname,
                    r.rolsuper,
                    r.rolcreaterole,
                    r.rolcreatedb,
                    r.rolcanlogin,
                    r.rolreplication,
                    r.rolbypassrls,
                    r.rolvaliduntil,
                    r.rolconnlimit,
                    ARRAY(
                        SELECT pg_catalog.array_agg(b.rolname)
                        FROM pg_catalog.pg_auth_members m
                        JOIN pg_catalog.pg_roles b ON (m.roleid = b.oid)
                        WHERE m.member = r.oid
                    ) as member_of
                FROM pg_catalog.pg_roles r
                WHERE r.rolname !~ '^pg_'
                ORDER BY r.rolname;
            """)
            
            for row in cur.fetchall():
                roles.append(RoleInfo(
                    name=row[0],
                    is_superuser=row[1],
                    can_create_db=row[3],
                    can_create_role=row[2],
                    member_of=row[9] if row[9] else [],
                ))

        return roles

    def _collect_grants(self) -> list[GrantInfo]:
        """Collect table privileges and grants."""
        grants = []
        
        with self.connection.cursor() as cur:
            cur.execute("""
                SELECT 
                    n.nspname as schema_name,
                    c.relname as table_name,
                    r.rolname as role_name,
                    g.grantee::regrole::text as grantee_name,
                    g.privilege_type,
                    g.is_grantable
                FROM pg_catalog.pg_class c
                JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles r ON r.oid = c.relowner
                JOIN information_schema.role_table_grants g 
                    ON g.table_name = c.relname 
                    AND g.table_schema = n.nspname
                WHERE c.relkind = 'r'  -- tables only
                AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                ORDER BY n.nspname, c.relname, r.rolname;
            """)
            
            for row in cur.fetchall():
                if row[5]:  # Only include if grantable
                    grants.append(GrantInfo(
                        table_name=row[1],
                        schema_name=row[0],
                        role_name=row[2],
                        privilege_type=row[4],
                        with_grant_option=True,
                    ))

        return grants

    def _collect_extensions(self) -> list[ExtensionInfo]:
        """Collect installed extensions."""
        extensions = []
        
        with self.connection.cursor() as cur:
            cur.execute("""
                SELECT 
                    extname,
                    extversion,
                    extnamespace::regnamespace
                FROM pg_extension
                ORDER BY extname;
            """)
            
            for row in cur.fetchall():
                extensions.append(ExtensionInfo(
                    name=row[0],
                    version=row[1],
                    schema_name=row[2] if row[2] else "public",
                ))

        return extensions

    def _collect_auth_rules(self) -> list[AuthenticationRule]:
        """
        Collect pg_hba.conf rules.
        This requires superuser or pg_read_all_files privilege.
        """
        rules = []
        
        try:
            with self.connection.cursor() as cur:
                # Query pg_hba_file_rules if available (PostgreSQL 12+)
                cur.execute("""
                    SELECT 
                        type,
                        database,
                        user_name,
                        address,
                        netmask,
                        auth_method,
                        options,
                        error
                    FROM pg_hba_file_rules
                    ORDER BY line_number;
                """)
                
                for row in cur.fetchall():
                    rules.append(AuthenticationRule(
                        database=row[1] if row[1] else "all",
                        user=row[2] if row[2] else "all",
                        address=row[3] if row[3] else None,
                        method=row[5],
                        auth_delay_enabled="auth_delay" in (row[6] or ""),
                    ))

        except Exception as e:
            self.errors.append(f"Failed to collect HBA rules: {str(e)}")
            if self.extended_mode:
                raise  # In extended mode, this is required
            else:
                pass  # In standard mode, skip gracefully

        return rules

    def _collect_tls(self) -> Optional[TLSMetadata]:
        """Collect TLS/SSL configuration metadata."""
        with self.connection.cursor() as cur:
            cur.execute("SHOW ssl;")
            ssl_enabled = cur.fetchone()[0] == "on"
            
            if not ssl_enabled:
                return TLSMetadata(ssl_enabled=False)
            
            cur.execute("SHOW ssl_cert_file;")
            cert_file = cur.fetchone()[0]
            
            cur.execute("SHOW ssl_key_file;")
            key_file = cur.fetchone()[0]
            
            cur.execute("SHOW ssl_min_protocol_version;")
            min_protocol = cur.fetchone()[0]
            
            return TLSMetadata(
                ssl_enabled=True,
                ssl_cert_file=cert_file,
                ssl_key_file=key_file,
                ssl_min_protocol_version=min_protocol,
            )

    def _collect_logging(self) -> Optional[LoggingConfig]:
        """Collect logging configuration."""
        with self.connection.cursor() as cur:
            cur.execute("SHOW log_statement;")
            log_statement = cur.fetchone()[0]
            
            cur.execute("SHOW log_connections;")
            log_connections = cur.fetchone()[0] == "on"
            
            cur.execute("SHOW log_disconnections;")
            log_disconnections = cur.fetchone()[0] == "on"
            
            cur.execute("SHOW log_line_prefix;")
            line_prefix = cur.fetchone()[0]
            
            cur.execute("SHOW logging_collector;")
            collector = cur.fetchone()[0] == "on"
            
            return LoggingConfig(
                log_statement=log_statement,
                log_connections=log_connections,
                log_disconnections=log_disconnections,
                log_line_prefix=line_prefix,
                logging_collector=collector,
            )

    def _collect_replication(self) -> Optional[ReplicationMetadata]:
        """Collect replication configuration."""
        with self.connection.cursor() as cur:
            cur.execute("SHOW wal_level;")
            wal_level = cur.fetchone()[0]
            
            if wal_level == "minimal":
                return None  # No replication configured
            
            cur.execute("SHOW max_wal_senders;")
            max_senders = int(cur.fetchone()[0])
            
            return ReplicationMetadata(
                replication_enabled=max_senders > 0,
                max_wal_senders=max_senders,
                wal_level=wal_level,
            )

    def _calculate_hash(self, snapshot: SnapshotBundle) -> str:
        """
        Calculate SHA-256 hash of the snapshot for integrity verification.
        """
        # Convert snapshot to JSON, excluding hash itself
        data = snapshot.model_dump(exclude={"snapshot_hash"})
        json_str = json.dumps(data, sort_keys=True, default=str)
        
        return hashlib.sha256(json_str.encode()).hexdigest()


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Collect PostgreSQL security metadata")
    parser.add_argument("--dsn", required=True, help="PostgreSQL DSN")
    parser.add_argument("--extended", action="store_true", help="Extended mode (requires elevated privileges)")
    parser.add_argument("--output", "-o", default="snapshot.json", help="Output file path")
    parser.add_argument("--format", choices=["json", "yaml"], default="json", help="Output format")
    
    args = parser.parse_args()
    
    try:
        collector = SnapshotCollector(dsn=args.dsn, extended_mode=args.extended)
        snapshot = collector.collect()
        
        # Output results
        if args.format == "json":
            output = snapshot.model_dump_json(indent=2, default=str)
        else:
            # YAML would require pyyaml, falling back to JSON for now
            output = snapshot.model_dump_json(indent=2, default=str)
        
        with open(args.output, "w") as f:
            f.write(output)
        
        print(f"✓ Snapshot collected successfully")
        print(f"  Hash: {snapshot.snapshot_hash}")
        print(f"  Identity: {snapshot.identity.engine} {snapshot.identity.version}")
        print(f"  Settings: {len(snapshot.settings)}")
        print(f"  Roles: {len(snapshot.roles)}")
        print(f"  Grants: {len(snapshot.grants)}")
        print(f"  Extensions: {len(snapshot.extensions)}")
        print(f"  Auth Rules: {len(snapshot.authentication_rules)}")
        
        if snapshot.collection_errors:
            print(f"\n⚠ Collection errors ({len(snapshot.collection_errors)}):")
            for error in snapshot.collection_errors:
                print(f"  - {error}")
        
        return 0
        
    except Exception as e:
        print(f"✗ Collection failed: {str(e)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
