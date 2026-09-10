#!/usr/bin/env python3
"""
Export templates from the database to JSON.

Output:
- templates.json - Template metadata and content
"""

import json
import sys
from pathlib import Path
from datetime import datetime

import psycopg2
import psycopg2.extras


def export_templates(
    db_url: str = "postgresql://dbguard:***@localhost:5433/dbguard",
    output_dir: str = "export"
) -> dict:
    """Export templates to JSON file."""
    conn = psycopg2.connect(db_url)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Export templates
    cur.execute("""
        SELECT 
            id,
            template_id,
            title,
            version,
            status,
            content,
            tags,
            postgresql_versions,
            environment_applicability,
            classification,
            source_url,
            policy_owner,
            approved_by,
            approved_at,
            effective_date,
            expiry_date,
            created_at,
            updated_at
        FROM templates
        ORDER BY created_at DESC
    """)
    templates = cur.fetchall()
    
    templates_file = output_path / "templates.json"
    with open(templates_file, "w") as f:
        json.dump([dict(t) for t in templates], f, indent=2, default=str)
    
    print(f"Exported {len(templates)} templates to {templates_file}")
    
    # Export metadata summary
    summary = {
        "export_timestamp": datetime.utcnow().isoformat(),
        "database_url": db_url,
        "templates_count": len(templates),
        "templates": [
            {
                "template_id": t["template_id"],
                "title": t["title"],
                "version": t["version"],
                "status": t["status"]
            }
            for t in templates
        ]
    }
    
    summary_file = output_path / "templates_summary.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)
    
    print(f"Exported summary to {summary_file}")
    
    cur.close()
    conn.close()
    
    return summary


if __name__ == "__main__":
    db_url = sys.argv[1] if len(sys.argv) > 1 else "postgresql://dbguard:***@localhost:5433/dbguard"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "export"
    
    summary = export_templates(db_url, output_dir)
    
    print("\n=== Export Complete ===")
    print(f"Templates: {summary['templates_count']}")
