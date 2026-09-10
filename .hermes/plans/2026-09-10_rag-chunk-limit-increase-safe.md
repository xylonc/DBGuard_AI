# RAG Chunk Limit Increase - Safe Incremental Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Safely increase `MAX_CHUNKS` from 1000 to a higher value that accommodates the full CIS benchmark XLS file without breaking the current working system.

**Strategy:** Incremental testing with rollback points
1. Increase to 1500 (50% increase) → Test → Verify
2. If issues, rollback to 1500
3. Continue to 2000, 2500, 3000 as needed

**Tech Stack:** Python, PostgreSQL, pgvector

---

## Current State

```python
CHUNK_SIZE = 500      # characters per chunk
CHUNK_OVERLAP = 50    # overlap between chunks for context continuity
MAX_CHUNKS = 1000     # max chunks per document
```

**Problem:** CIS benchmark XLS produces >1000 chunks, causing silent truncation.

---

## Safe Incremental Plan

### Phase 1: Increase to 1500 (50% increase, low risk)

**Why 1500:** Conservative 50% increase, still bounded, easy to verify

**Files to modify:**
1. `services/rag/rag_service.py` line 40: `MAX_CHUNKS = 1500`
2. `backend/tests/test_knowledge_endpoint.py` line 444: `assert len(chunks) < 1500`

**Test steps:**
```bash
# 1. Run existing tests
cd backend
pytest tests/test_knowledge_endpoint.py -v

# 2. Upload your CIS benchmark XLS
# Use: POST /api/v1/knowledge/upload

# 3. Verify chunk count
# Check logs for: "Document {id} exceeds MAX_CHUNKS (1500)"
# Or query DB: SELECT COUNT(*) FROM knowledge_chunks WHERE document_id = 'xlsx-...'

# 4. Verify content completeness
# Check if the document ends with expected content (tail marker or final section)
```

**Rollback plan:** If issues, revert `MAX_CHUNKS = 1000` and investigate.

---

### Phase 2: Monitor and adjust

**If 1500 is still too small:**
- Increase to 2000 (100% from original)
- Run same tests
- Monitor PostgreSQL storage growth

**If 2000 is still too small:**
- Increase to 2500
- Increase to 3000
- Continue until CIS benchmark fits

---

## Implementation Tasks

### Task 1: Increase MAX_CHUNKS to 1500

**Objective:** Safely increase limit to 1500 chunks

**Files:**
- Modify: `services/rag/rag_service.py:40`
- Modify: `backend/tests/test_knowledge_endpoint.py:444`

**Step 1: Update rag_service.py**

```bash
# Backup first
cp services/rag/rag_service.py services/rag/rag_service.py.bak

# Change line 40
sed -i 's/MAX_CHUNKS = 1000/MAX_CHUNKS = 1500/' services/rag/rag_service.py
```

**Step 2: Update test expectations**

```bash
# Change line 444 in test file
sed -i 's/assert len(chunks) < 1000/assert len(chunks) < 1500/' backend/tests/test_knowledge_endpoint.py
```

**Step 3: Run tests**

```bash
cd backend
pytest tests/test_knowledge_endpoint.py -v
```

**Expected:** All 15 tests pass

**Step 4: Test with CIS benchmark XLS**

Upload your CIS benchmark XLS and verify:
- No truncation warning
- Chunk count > 1000 (proving we can now ingest more)
- Content completeness (last sections present)

---

### Task 2: Monitor storage impact

**Objective:** Verify storage growth is acceptable

**Files:**
- Query: PostgreSQL database

**Step 1: Check current storage**

```sql
-- Before increase
SELECT 
    COUNT(*) as chunk_count,
    pg_size_pretty(SUM(LENGTH(content))) as content_size,
    pg_size_pretty(SUM(LENGTH(embedding::text))) as embedding_size
FROM knowledge_chunks;
```

**Step 2: After ingestion, check again**

```sql
-- After increase
SELECT 
    COUNT(*) as chunk_count,
    pg_size_pretty(SUM(LENGTH(content))) as content_size,
    pg_size_pretty(SUM(LENGTH(embedding::text))) as embedding_size
FROM knowledge_chunks;
```

**Acceptable growth:** < 2× increase from original 1000 chunks

---

### Task 3: If still too small, increase to 2000

**Only if Phase 1 (1500) is insufficient:**

**Files:**
- Modify: `services/rag/rag_service.py:40`
- Modify: `backend/tests/test_knowledge_endpoint.py:444`

**Change:**
```python
MAX_CHUNKS = 2000  # was 1500
```

**Test:** Same as Phase 1

---

### Task 4: Document the new limit

**Files:**
- Create/modify: `docs/RAG_LIMITS.md` (new or update existing)

**Document:**
```
RAG Chunking Limits
===================

CHUNK_SIZE:    500 characters
CHUNK_OVERLAP: 50 characters
MAX_CHUNKS:    2000 (increased from 1000 on 2026-09-10)

Reason for increase: Full CIS PostgreSQL benchmark ingestion requires ~1800 chunks.
```

---

## Rollback Plan

If any issue occurs:

```bash
# Restore backup
cp services/rag/rag_service.py.bak services/rag/rag_service.py

# Revert test changes
sed -i 's/assert len(chunks) < 1500/assert len(chunks) < 1000/' backend/tests/test_knowledge_endpoint.py

# Run tests to verify
pytest tests/test_knowledge_endpoint.py -v
```

---

## Success Criteria

✅ All 15 existing tests pass  
✅ CIS benchmark XLS ingests without truncation  
✅ Chunk count is documented (e.g., 1800 chunks)  
✅ Storage growth is acceptable (< 2× from baseline)  
✅ No regression in query performance  

---

## Next Steps

1. Implement Phase 1 (increase to 1500)
2. Test with existing test suite
3. Test with your CIS benchmark XLS
4. Report results: chunk count, any issues, storage impact
