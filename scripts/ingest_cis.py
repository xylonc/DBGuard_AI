from pathlib import Path
import requests

path = Path("local docs/CIS_PostgreSQL_17_Benchmark_v1.1.0.cleaned.md")
content = path.read_text(encoding="utf-8")

print(f"Loaded {len(content)} characters")

payload = {
    "document_id": "cis-postgresql-17-v1.1.0",
    "title": "CIS PostgreSQL 17 Benchmark",
    "version": "1.1.0",
    "content": content,
    "effective_date": "2026-07-20T00:00:00Z",
    "status": "draft",
    "postgresql_versions": ["17"],
    "environment_applicability": ["all"],
    "policy_owner": "Center for Internet Security",
    "classification": "licensed",
}

print("Sending document to DBGuardAI...")

response = requests.post(
    "http://localhost:8000/api/v1/knowledge/documents",
    json=payload,
    timeout=None,
)

print("HTTP status:", response.status_code)
print(response.text)