"""Blocking error report for Tier B tests.

Tier B tests require a live pgvector/PostgreSQL database connection which is not
available in this environment. The tests are blocked until the following are met:

1. PostgreSQL database running with pgvector extension
2. psycopg2 or similar PostgreSQL driver available
3. DATABASE_URL environment variable properly configured

To enable Tier B tests, install the required dependencies and ensure database connectivity:

    pip install psycopg2-binary
    # Or on Ubuntu: apt-get install postgresql-client psycopg2
    
Then set the DATABASE_URL and run the tests:
    
    export DATABASE_URL="postgresql://user:pass@localhost:5432/dbname"
    pytest tests/test_template_registry_tier_b.py -v

Alternatively, run the tests via Docker with a database service:

    docker-compose up -d
    pytest tests/ -m tier_b -v

Blocking error report ends here.
"""
import sys

def check_database_availability():
    """Check if database is available and return blocking status."""
    errors = []
    
    try:
        import psycopg2
    except ImportError:
        errors.append("Missing dependency: psycopg2 or psycopg2-binary")
    
    try:
        import app.config
        from app.config import settings
        # Try to connect (but catch connection errors)
        import os
        db_url = os.environ.get("DATABASE_URL", settings.database_url)
        if "localhost" in db_url or "127.0.0.1" in db_url:
            errors.append(f"Database URL points to localhost: {db_url[:50]}...")
    except Exception:
        errors.append("Failed to load database configuration")
    
    if errors:
        return False, errors
    return True, []


if __name__ == "__main__":
    available, errors = check_database_availability()
    
    if not available:
        print("⚠️  TIER B TESTS BLOCKED - Database not available", file=sys.stderr)
        print("\nBlocking errors:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        print("\nTo enable Tier B tests, install psycopg2 and ensure database connectivity.", file=sys.stderr)
        sys.exit(1)
    else:
        print("✅ Database available - Tier B tests can run")
        sys.exit(0)
