# DBGuardAI — RAG XLSX Ingestion: What We Accomplished

## Overview

DBGuardAI is a PostgreSQL security-hardening POC with a RAG (Retrieval-Augmented Generation)
knowledge base backed by PostgreSQL + pgvector. This README documents the work done to make the
XLSX upload endpoint functional and to understand why it can only store the first 1000 chunks.

## What was built

1. **XLSX Upload Endpoint** (`POST /api/v1/knowledge/upload`) — Accepts `.xlsx` files, extracts
   their content, and feeds them into the existing RAG pipeline.

2. **Deterministic XLSX Extractor** (`backend/app/xlsx_extractor.py`) — Converts worksheet rows
   into normalized text using a fixed pipeline: `_guard_cell` prevents shell commands from being
   misidentified as Markdown headers, `_wrap_tab` breaks long lines, `_format_row` renders
   `Header: Value` pairs. All non-empty source columns are preserved.

3. **Chunking & Embedding** — Normalized text is split into ~500-char chunks (50-char overlap)
   by section header boundaries. Each chunk gets a semantic embedding and is stored in
   `knowledge_chunks` + `knowledge_embeddings`.

## Current Limitation: First 1000 Chunks Only

The real CIS XLSX benchmark (PostgreSQL 17 v1.1.0) produces **approximately 1,002 chunks**
before truncation. The system caps ingestion at `MAX_CHUNKS = 1000`, so the last ~2 chunks
are silently discarded with a warning:

```
Document xxx exceeds MAX_CHUNKS (1000); truncating to first 1000 chunks
```

### Why this is not a bug

The 1000-chunk limit is an intentional hard cap in the RAG service. It prevents runaway
memory usage during embedding generation and database writes. The limit is enforced at two
points:

- In `_chunk_document()` at line ~331 — truncates the chunk list after splitting
- In `ingest_document()` at line ~219 — breaks the embedding loop at 1000

### Why it is not fixed in this task

Per project requirements, `MAX_CHUNKS` must NOT be changed. The limitation is acknowledged
and documented but not addressed by the refactoring.

## Known Fix: openpyxl Dependency

The `openpyxl` package was missing from `requirements.txt`. It was imported in
`xlsx_extractor.py` and used in tests, but never listed as a dependency. Without it, the
Docker build succeeded (other endpoints didn't need it) but the XLSX endpoint failed at
runtime with `ImportError`.

**Fix applied:** Added `openpyxl>=3.1.0,<4.0.0` to `requirements.txt`.

## Current Error Investigation

During XLSX upload, the system logs:

```
Failed to store chunks: value too long for type character varying(255)
```

### What we know

- The `section` field is properly clamped to 255 chars in code (`new_section[:255]`)
- All other VARCHAR(255) fields have short default values
- Local tests pass because they mock the database — no INSERT actually runs
- The exact failing field has not been proven from the live PostgreSQL runtime
- Diagnostic logging (`DOC_OVER`, `CHUNK_OVER`) has been added to `rag_service.py` to
  identify the culprit when deployed

### What is needed next

1. Rebuild the API container: `docker compose -f deploy/compose.yaml up -d --build --force-recreate api`
2. Stream logs: `docker compose -f deploy/compose.yaml logs -f api`
3. Upload the XLSX through Swagger and watch for `DOC_OVER` or `CHUNK_OVER` warnings
4. The first warning identifies the exact field and length

## Project Structure After Refactoring

```
/workspace/DBGuardAI/
├── ARCHITECTURE.md          # System design
├── README.md                # This file
├── requirements.txt         # Python dependencies (includes openpyxl now)
├── backend/
│   ├── app/
│   │   ├── xlsx_extractor.py  # XLSX -> text extraction
│   │   ├── main.py            # FastAPI app
│   │   └── ...
│   ├── tests/
│   │   ├── test_app.py           # App routing tests
│   │   ├── test_knowledge_endpoint.py  # XLSX upload tests
│   │   ├── test_runs.py          # RAG service tests
│   │   ├── test_overflow.py      # VARCHAR(255) reproduction script (moved from root)
│   │   └── measure_full.py       # XLSX measurement script (moved from root)
│   └── Dockerfile
├── services/
│   └── rag/
│       └── rag_service.py      # Chunking, embedding, DB storage (with DOC_OVER/CHUNK_OVER logging)
├── scripts/
│   ├── run_tests.sh            # Collector acceptance test harness (moved from root)
│   ├── ingest_cis.py           # CIS benchmark ingestion script
│   ├── ingest_cis_benchmark.py
│   ├── ingest_templates.py
│   ├── test-out/               # Collector test output (moved from root)
│   └── verify-out/             # Verify output (moved from root)
├── tests/                      # Root-level pytest tests (still here — app-level tests)
├── db/
│   └── init.sql                # PostgreSQL schema
├── deploy/
│   └── compose.yaml            # Docker Compose
├── catalog/
├── collector/
├── hermes/
└── local docs/                 # XLSX benchmark files for testing
```

## Files Moved (Refactoring)

| File | From | To | Reason |
|------|------|----|--------|
| `test_overflow.py` | root/ | `backend/tests/` | XLSX RAG reproduction — belongs with RAG tests |
| `measure_full.py` | root/ | `backend/tests/` | XLSX measurement — belongs with XLSX tests |
| `run_tests.sh` | root/ | `scripts/` | Collector acceptance harness — belongs in scripts/ |
| `test-out/` | root/ | `scripts/` | Collector test output |
| `verify-out/` | root/ | `scripts/` | Verify output |

The root directory is now clean: only project-level docs, dependencies, and top-level directories.
