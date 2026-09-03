## Phase 1: Template RAG - MVP Implementation

### What was built

**Template discovery via semantic search** — replaced static `os.listdir()` disk-scan with pgvector-based RAG retrieval.

### Files added

| File | Purpose |
|---|---|
| `backend/db/init.sql` | pgvector schema: `templates` table with `vector(1536)`, ivfflat index |
| `backend/app/services/vector_service.py` | `get_embedding()`, `search_templates()`, `ingest_all_templates()` |
| `scripts/ingest_templates.py` | CLI tool: reads .sql.j2 files -> embeds descriptions -> stores in pgvector |
| `backend/app/config.py` | Pydantic settings for env vars (database_url, LLM model, etc.) |
| `backend/app/models.py` | Pydantic request/response schemas |
| `requirements.txt` | All Python dependencies |
| `.env.example` | Environment variable template |

### Files modified

| File | Change |
|---|---|
| `backend/app/main.py` | Updated to use RAG pipeline: search -> LLM with context -> compile SQL |
| `backend/app/services/ai_service.py` | Replaced disk-scan with `vector_service.search_templates()`. LLM now receives top-3 most relevant templates by semantic relevance |
| `backend/app/services/template_service.py` | Minor: added template name to rendered output |

### How it works

1. User types natural language request
2. `vector_service.search_templates()` embeds the query -> cosine similarity search -> top-3 templates
3. LLM receives user prompt + top-3 template descriptions
4. LLM returns JSON with selected template_ids and parameters
5. `template_service.compile_sql_plan()` renders final SQL via Jinja2

### Bug fixes included

1. **Error handling** - LLM response wrapped in try/except, returns empty plan gracefully
2. **Hardcoded credentials** -> moved to `.env` via `config.py`
3. **Missing `requirements.txt`** -> all deps listed

### To test

1. Start PostgreSQL with pgvector: `docker-compose up -d`
2. Copy `.env.example` to `.env` and set your `OPENAI_API_KEY`
3. Ingest templates: `python -m scripts.ingest_templates`
4. Test endpoint: `curl -X POST http://localhost:8000/api/v1/harden -H "Content-Type: application/json" -d '{"user_prompt": "create a read-only auditor", "metadata_snapshot": {"engine": "postgresql"}}'`

### Notes

- No Python metadata config file - ingestion auto-generates descriptions from `-- comments` in template files
- Embedding uses OpenAI `text-embedding-3-small` (1536 dimensions)
- Cosine similarity via pgvector ivfflat index (lists=10)
