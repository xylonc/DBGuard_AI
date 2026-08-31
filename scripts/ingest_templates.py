"""Ingestion script — run once to populate pgvector with SQL templates.

Usage:
    python -m scripts.ingest_templates          # Ingest templates
    python -m scripts.ingest_templates --init   # Init DB + ingest templates
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.vector_service import init_db, ingest_all_templates


def main():
    print("=" * 60)
    print("DBGuardAI — Template RAG Ingestion")
    print("=" * 60)

    # Initialize DB tables if needed
    print("\n🔧 Initializing database schema...")
    init_db()

    # Ingest all templates
    print("\n📥 Ingesting templates...")
    ingest_all_templates()

    print("\n✅ Done!")


if __name__ == "__main__":
    main()
