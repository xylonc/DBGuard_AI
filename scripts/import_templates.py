#!/usr/bin/env python3
"""
Import templates from JSON into the database.

Usage:
    python import_templates.py <export_dir> [db_url]
"""

import json
import sys
from pathlib import Path

import psycopg2
import psycopg2.extras


def import_templates(
    export_dir: str,
    db_url: str = "postgresql://dbguard:***@localhost:5433/dbguard"
) -> dict:
    """Import templates from JSON file."""
    export_path = Path(export_dir)
    
    # Load templates
    templates_file = export_path / "templates.json"
    if not templates_file.exists():
        raise FileNotFoundError(f"Templates file not found: {templates_file}")
    
    with open(templates_file) as f:
        templates = json.load(f)
    
    # Connect to database
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    
    # Start transaction
    cur.execute("BEGIN")
    
    inserted = 0
    skipped = 0
    
    try:
        for template_data in templates:
            template_id = template_data["template_id"]
            
            # Check if template exists
            cur.execute(
                "SELECT template_id FROM templates WHERE template_id = %s",
                (template_id,)
            )
            existing = cur.fetchone()
            
            if existing:
                skipped += 1
                continue
            
            # Insert template
            cur.execute("""
                INSERT INTO templates (
                    template_id, title, version, status,
                    content, tags, postgresql_versions,
                    environment_applicability, classification,
                    source_url, policy_owner,
                    approved_by, approved_at,
                    effective_date, expiry_date,
                    created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                template_data["template_id"],
                template_data["title"],
                template_data["version"],
                template_data["status"],
                template_data["content"],
                template_data.get("tags", []),
                template_data.get("postgresql_versions", []),
                template_data.get("environment_applicability", []),
                template_data.get("classification", "internal"),
                template_data.get("source_url"),
                template_data.get("policy_owner", ""),
                template_data.get("approved_by"),
                template_data.get("approved_at"),
                template_data.get("effective_date"),
                template_data.get("expiry_date"),
                template_data.get("created_at"),
                template_data.get("updated_at"),
            ))
            inserted += 1
        
        # Commit
        conn.commit()
        
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cur.close()
        conn.close()
    
    return {
        "templates_inserted": inserted,
        "templates_skipped": skipped
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python import_templates.py <export_dir> [db_url]")
        sys.exit(1)
    
    export_dir = sys.argv[1]
    db_url = sys.argv[2] if len(sys.argv) > 2 else "postgresql://dbguard:***@localhost:5433/dbguard"
    
    print(f"Importing templates from {export_dir}")
    
    result = import_templates(export_dir, db_url)
    
    print("=== Import Complete ===")
    print(f"Templates inserted: {result['templates_inserted']}")
    print(f"Templates skipped (already exist): {result['templates_skipped']}")
