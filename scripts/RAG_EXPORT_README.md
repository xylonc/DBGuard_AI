# RAG Data Export/Import - Complete Solution

This directory contains comprehensive scripts to export and import all RAG data for team sharing.

## Why?

When you've ingested:
- **Knowledge data** - CIS benchmarks, policies, procedures (from XLSX uploads)
- **Templates** - Remediation templates
- **Snapshots** - Assessment snapshot data
- **Ingestion status** - Track what's been ingested

You can now:
1. Export everything to JSON files
2. Commit the JSON files to your repo
3. Teammates can import everything without re-uploading files

## Files

| File | Purpose |
|------|---------|
| `export_all.py` | **All-in-one** - Export everything (documents, chunks, templates, snapshots) |
| `import_all.py` | **All-in-one** - Import everything from JSON |
| `export_rag_data.py` | Export only RAG knowledge (documents + chunks) |
| `import_rag_data.py` | Import only RAG knowledge |
| `export_templates.py` | Export only templates |
| `import_templates.py` | Import only templates |
| `Makefile` | Convenience commands |

## Usage

### Option 1: All-in-One (Recommended)

**Export everything in one command:**
```bash
make all
```
Or:
```bash
python scripts/export_all.py
```

**Import everything in one command:**
```bash
make import-all
```
Or:
```bash
python scripts/import_all.py export
```

### Option 2: Selective Export/Import

**Export/import only knowledge:**
```bash
make export    # Export knowledge data
make import    # Import knowledge data
```

**Export/import only templates:**
```bash
make templates    # Export templates
```

## Database Connection

Default: `postgresql://dbguard:***@localhost:5433/dbguard`

Override with `DATABASE_URL` environment variable:
```bash
DATABASE_URL=postgresql://user:pass@host:5432/dbname make all
```

## What Gets Exported

### 1. Knowledge Documents (`documents.json`)
- Document metadata (title, version, status)
- Applicable PostgreSQL versions
- Environment applicability
- Classification (public/internal/confidential)
- Source URLs
- Approval information

### 2. Knowledge Chunks (`chunks.json`)
- Full chunk content
- Section headers
- Chunk hash for integrity
- Source document references
- Applicable versions/environments

### 3. Templates (`templates.json`)
- Template ID and title
- Full remediation content
- Tags for categorization
- PostgreSQL version filters
- Classification

### 4. Snapshots (`snapshot_*.json`)
- Assessment snapshot data
- Counters: up to 1000 records per table

### 5. Ingestion Status (`template_ingestion_status.json`)
- Track which templates were ingested
- Chunk counts
- Ingestion timestamps

## Commit to Git

```bash
git add export/
git commit -m "Add RAG data: knowledge, templates, snapshots"
```

## Restore from Git

```bash
# Clone repo
git clone <your-repo>
cd dbguard-ai

# Import everything
make import-all
```

## Example Workflow

**On your machine (after ingesting CIS benchmark):**
```bash
$ make all
Exporting all RAG data...
Exporting knowledge documents...
  - 2 documents
Exporting knowledge chunks...
  - 1027 chunks
Exporting templates...
  - 50 templates
Exporting snapshots...
  - 0 records
Exporting assessment catalog...
  - 0 records
Exporting template ingestion status...
  - 50 records

=== Export Summary ===
Documents: 2
Chunks: 1027
Templates: 50

Exported to: export

$ ls -la export/
documents.json    chunks.json   templates.json
template_ingestion_status.json  summary.json
```

**On teammate's machine:**
```bash
$ make import-all
Importing all RAG data from export
Importing documents...
  - 2 documents
Importing chunks...
  - 1027 chunks
Importing templates...
  - 50 templates
Importing template ingestion status...
  - 50 records

=== Import Summary ===
Documents: 2
Chunks: 1027
Templates: 50

Import complete from: export
```

## Notes

- **Embeddings are regenerated** on import (not stored in JSON)
- **Existing data is skipped** (no overwrite - safe to run multiple times)
- **Chunk content is included** (can be large - ~500 chars per chunk)
- **Snapshots limited to 1000 records** per table (adjust in script if needed)

## Troubleshooting

**"Connection refused"** - PostgreSQL isn't running. Start with:
```bash
docker-compose up -d postgres
```

**"Table doesn't exist"** - Some tables may not exist in your schema. The script will skip them.

**"Document already exists"** - Skipped automatically (no overwrite). Use `import_all.py` to force update if needed.
