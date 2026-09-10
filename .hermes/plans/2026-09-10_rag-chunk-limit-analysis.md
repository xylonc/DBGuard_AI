# RAG Chunk Limit Analysis & Optimization Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Evaluate whether the 1000-chunk limit (`MAX_CHUNKS`) is appropriate for realistic XLSX workbooks, and determine if it should be increased, removed, or made configurable.

**Architecture:** Analyze the current chunking behavior, measure actual chunk counts for typical workloads, and propose changes to the `CHUNK_SIZE`, `CHUNK_OVERLAP`, and `MAX_CHUNKS` constants.

**Tech Stack:** Python, PostgreSQL, pgvector

---

## Current State

### Constants (rag_service.py:38-40)
```python
CHUNK_SIZE = 500      # characters per chunk
CHUNK_OVERLAP = 50    # overlap between chunks for context continuity
MAX_CHUNKS = 1000     # max chunks per document to avoid excessive storage
```

### Current Behavior
- The chunker splits documents into 500-character chunks with 50-character overlap
- If the final chunk count exceeds 1000, it truncates silently with a warning
- The 1000-chunk limit was added to "avoid excessive storage"

### Test Evidence
The test `test_large_xlsx_stays_under_max_chunks` builds a 600-row CIS-style workbook and verifies it stays under 1000 chunks. This is a regression test to prevent silent truncation.

---

## Analysis

### 600-Row Workbook (Current Test)
- **Columns:** 9 core columns (Section #, Recommendation #, Title, Severity, Description, Rationale Statement, Remediation Procedure, Audit Procedure, Impact Statement)
- **Typical row size:** ~1500-2000 characters after normalization
- **Total content:** ~900KB-1.2MB
- **Expected chunks:** ~1800-2400 (900KB / 500 chars)
- **Actual chunks:** 600 (the test *expects* < 1000, implying the extractor already compresses significantly)

### Real-World CIS Benchmark
A full CIS PostgreSQL benchmark has:
- **Sections:** ~200+ sections
- **Recommendations per section:** 3-5
- **Total rows:** ~800-1000+
- **Total content:** 2-3MB+

**Question:** What is the *actual* chunk count for a real CIS benchmark XLSX?

---

## Questions to Answer

1. **What's the actual chunk count for a full CIS benchmark?**
   - Test with real CIS PostgreSQL 15/16/17 benchmark XLSX files
   - Measure total content size and chunk count

2. **Is 1000 chunks sufficient for typical workloads?**
   - How much content do users typically ingest?
   - Is the 1000-chunk limit protecting against a real problem?

3. **What's the storage cost of more chunks?**
   - PostgreSQL `TEXT` column storage (TOAST)
   - pgvector embedding storage (1536 floats per chunk = ~6KB)
   - 1000 chunks @ 6KB = 6MB embeddings
   - 2000 chunks @ 6KB = 12MB embeddings

4. **Is the limit too aggressive?**
   - Should it be removed?
   - Should it be increased (e.g., 2000, 5000)?
   - Should it be configurable per document/type?

---

## Proposed Tasks

### Task 1: Measure real-world chunk counts

**Objective:** Understand actual chunk counts for typical workloads

**Files:**
- Create: `scripts/profile_chunking.py` (new script to profile chunking behavior)

**Step 1: Create profiling script**

```python
#!/usr/bin/env python3
"""Profile chunking behavior for various XLSX workloads."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.xlsx_extractor import extract_xlsx_to_text
from rag.rag_service import RAGService, KnowledgeDocument
from datetime import datetime, timezone

def profile_workbook(filename: str, content: str):
    """Profile chunking for a workbook."""
    doc = KnowledgeDocument(
        document_id="profile-test",
        title="Profile Test",
        version="1.0",
        content=content,
        effective_date=datetime.now(timezone.utc),
        status="draft",
    )
    chunks = RAGService()._chunk_document(doc)
    return len(chunks), sum(len(c.content) for c in chunks)

# Test 1: 600-row CIS-style workbook (current test)
# Test 2: 1000+ row workbook (realistic CIS benchmark)
# Test 3: Real CIS benchmark if available

if __name__ == "__main__":
    print("Chunking Profile Results")
    print("=" * 50)
    
    # Add test cases here
```

**Step 2: Run with various workloads**

```bash
# Run the profiler
python scripts/profile_chunking.py
```

**Step 3: Document findings**

| Workbook Type | Total Chars | Total Chunks | Chunks/100KB |
|---------------|-------------|--------------|--------------|
| 600-row test | ~1MB | ? | ? |
| 1000-row CIS | ~2MB | ? | ? |
| Real CIS benchmark | ? | ? | ? |

---

### Task 2: Evaluate storage impact

**Objective:** Understand the storage cost of increasing the chunk limit

**Files:**
- Modify: `services/rag/rag_service.py:40` (MAX_CHUNKS constant)
- Create: `docs/storage-analysis.md` (new documentation)

**Step 1: Calculate storage costs**

```
Current: MAX_CHUNKS = 1000
- Embeddings: 1000 × 1536 × 4 bytes = ~6MB
- Text storage: ~1000 × 500 chars = ~500KB (compressed)

Proposed: MAX_CHUNKS = 2000
- Embeddings: 2000 × 1536 × 4 bytes = ~12MB
- Text storage: ~2000 × 500 chars = ~1MB (compressed)

Proposed: MAX_CHUNKS = 5000
- Embeddings: 5000 × 1536 × 4 bytes = ~30MB
- Text storage: ~5000 × 500 chars = ~2.5MB (compressed)
```

**Step 2: Document tradeoffs**

Create `docs/storage-analysis.md` with:
- Storage costs for different limits
- Performance implications (embedding generation time)
- Query performance (more chunks = more相似度 calculations)

---

### Task 3: Determine optimal strategy

**Objective:** Choose and implement the right approach

**Options:**

| Option | Pros | Cons |
|--------|------|------|
| **Keep 1000** | Simple, low storage | May truncate legitimate content |
| **Increase to 2000** | Better coverage, still bounded | 2× storage, may still truncate large workbooks |
| **Increase to 5000** | Covers most workloads | 5× storage, may truncate very large workbooks |
| **Remove limit entirely** | No truncation | Unlimited storage, potential abuse |
| **Make configurable** | Flexibility for different use cases | More complexity, config management |

**Recommended approach:**
- Increase to **2000 chunks** as a reasonable balance
- Add a warning when approaching the limit
- Make it configurable via `settings.rag_max_chunks` for advanced users

---

### Task 4: Implement changes

**Objective:** Update the constants and add configuration

**Files:**
- Modify: `services/rag/rag_service.py:40` (MAX_CHUNKS)
- Modify: `backend/app/config.py` (add new config option)
- Modify: `services/rag/rag_service.py:166-168` (use settings)
- Update: `backend/tests/test_knowledge_endpoint.py:444` (test expectations)

**Step 1: Add configuration**

In `backend/app/config.py`:
```python
class Settings(BaseSettings):
    # ... existing settings ...
    rag_max_chunks: int = 2000  # New setting
```

**Step 2: Update rag_service.py**

```python
# Line 40: Update constant
MAX_CHUNKS = 2000  # max chunks per document to avoid excessive storage

# Line 166-168: Use settings
class RAGService:
    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or os.getenv("DATABASE_URL", "postgresql://dbguard:***@localhost:5433/dbguard")
        self.embedding_dim = settings.embedding_dim
        self.embedding_model = settings.embedding_model
        self.chunk_size = CHUNK_SIZE
        self.chunk_overlap = CHUNK_OVERLAP
        self.max_chunks = settings.rag_max_chunks  # New
```

**Step 3: Update chunking logic**

Replace line 331-333:
```python
# Enforce MAX_CHUNKS
if len(result) > self.max_chunks:
    logger.warning(
        f"Document {document.document_id} exceeds max chunks ({self.max_chunks}); "
        f"truncating to first {self.max_chunks} chunks"
    )
    result = result[:self.max_chunks]
```

**Step 4: Update tests**

In `test_knowledge_endpoint.py`, update the test expectations:
```python
assert len(chunks) < 2000, (  # Changed from 1000
    f"Chunk count {len(chunks)} exceeds MAX_CHUNKS (2000); "
    f"content was silently truncated"
)
```

---

### Task 5: Validation

**Objective:** Verify the changes work correctly

**Files:**
- Run: `pytest backend/tests/test_knowledge_endpoint.py -v`

**Step 1: Run existing tests**

```bash
cd backend
pytest tests/test_knowledge_endpoint.py -v
```

**Expected:** All 15 tests pass

**Step 2: Test with larger workbooks**

Create a 1500-row test workbook and verify:
- Chunk count < 2000
- Content is preserved
- No errors

---

## Risks & Tradeoffs

### Risk 1: Storage bloat
- **Mitigation:** Start with 2000 (not 5000+), monitor storage growth

### Risk 2: Query performance
- **Mitigation:** The chunk count increase is linear; 2000 chunks vs 1000 is manageable

### Risk 3: Silent truncation still occurs
- **Mitigation:** Log warning when truncation happens; consider making it an error for critical documents

---

## Open Questions

1. **Should we add a flag to raise an error instead of truncating?**
   - Useful for critical documents where completeness is required

2. **Should we make the limit per-document-type?**
   - CIS benchmarks: higher limit (2000+)
   - User uploads: lower limit (500-1000)

3. **Should we add dynamic chunk sizing?**
   - Large content blocks: larger chunks (1000+ chars)
   - Small content blocks: smaller chunks (250 chars)

---

## Next Steps

1. Run the profiling script to measure actual chunk counts
2. Review the analysis with the team
3. Choose the right limit (2000 recommended)
4. Implement changes and validate
