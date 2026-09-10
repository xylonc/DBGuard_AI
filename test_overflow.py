#!/usr/bin/env python3
"""Reproduce the VARCHAR(255) overflow."""
import re, sys, os, io, types
from datetime import datetime, timezone

os.chdir('/workspace/DBGuardAI')
sys.path.insert(0, '/workspace/DBGuardAI/backend')

# Load xlsx_extractor BEFORE mocking
from app.xlsx_extractor import extract_xlsx_to_text

# Mock app.config
import app
app.settings = types.SimpleNamespace(
    embedding_model='nomic-embed-text',
    embedding_dim=768,
    ollama_api_url='http://localhost:11434',
)

# Mock embedding_service
es_mod = types.ModuleType('app.services.embedding_service')
es_mod.generate_embedding = lambda text, model=None, dimension=None: [0.01] * 768
app_services = types.ModuleType('app.services')
app_services.embedding_service = es_mod
sys.modules['app.services'] = app_services
sys.modules['app.services.embedding_service'] = es_mod

os.environ['DATABASE_URL'] = 'postgresql://dbguard:dbguard_password@localhost:5433/dbguard'

# Now exec rag_service.py directly
with open('/workspace/DBGuardAI/services/rag/rag_service.py', 'r') as f:
    code = f.read()
exec(compile(code, 'rag_service.py', 'exec'))

KnowledgeDocument = locals()['KnowledgeDocument']
RAGService = locals()['RAGService']

# Extract XLSX
xlsx_path = '/workspace/DBGuardAI/local docs/CIS_PostgreSQL_17_Benchmark_v1.1.0-Certification.xlsx'
with open(xlsx_path, 'rb') as f:
    content = f.read()

text = extract_xlsx_to_text(content)
print(f"Extracted: {len(text)} chars, {text.count(chr(10))} lines")

# Build document
title = "CIS PostgreSQL 17 Benchmark V1.1.0-Certification"
doc = KnowledgeDocument(
    document_id="xlsx-test123",
    title=title,
    version="1.0.0",
    content=text,
    effective_date=datetime.now(timezone.utc),
    status="draft",
)

# Chunk
service = RAGService.__new__(RAGService)
service.chunk_size = 500
service.chunk_overlap = 50
chunks = service._chunk_document(doc)
print(f"Chunks: {len(chunks)}")

# Check all fields
max_sec = 0
max_sec_idx = 0
for c in chunks:
    if len(c.section) > max_sec:
        max_sec = len(c.section)
        max_sec_idx = c.chunk_index

print(f"Max section len: {max_sec} (chunk {max_sec_idx})")
print(f"Title len: {len(doc.title)}")
print(f"policy_owner len: {len(doc.policy_owner)}")
print(f"postgresql_versions: {doc.postgresql_versions}")
print(f"environment_applicability: {doc.environment_applicability}")

# Try actual DB
import psycopg2
conn = psycopg2.connect(os.environ['DATABASE_URL'])
cur = conn.cursor()
doc_hash = doc.document_hash

# Insert document
try:
    cur.execute("""
        INSERT INTO knowledge_documents (
            document_id, title, version, status,
            effective_date, expiry_date,
            postgresql_versions, environment_applicability,
            policy_owner, classification, source_url, superseded_by,
            document_hash, approved_by, approved_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (document_id) DO UPDATE SET title = EXCLUDED.title
    """, (
        doc.document_id, doc.title, doc.version, doc.status,
        doc.effective_date, doc.expiry_date,
        doc.postgresql_versions, doc.environment_applicability,
        doc.policy_owner, doc.classification, doc.source_url,
        doc.superseded_by, doc_hash, doc.approved_by,
        datetime.utcnow() if doc.status == "active" else None,
    ))
    print("knowledge_documents INSERT: OK")
except Exception as e:
    conn.rollback()
    print(f"knowledge_documents INSERT FAILED: {type(e).__name__}")
    print(f"  {e}")
    if hasattr(e, 'diag'):
        print(f"  Table: {e.diag.table_name}, Column: {e.diag.column_name}")
        print(f"  Detail: {e.diag.message_detail}")

cur.execute("DELETE FROM knowledge_chunks WHERE document_id = %s", (doc.document_id,))

# Insert chunks
failed = False
for i, chunk in enumerate(chunks):
    try:
        cur.execute("""
            INSERT INTO knowledge_chunks (
                document_id, section, content, chunk_hash,
                chunk_index, postgresql_versions,
                environment_applicability, source_document_title,
                source_document_version
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            chunk.document_id, chunk.section, chunk.content,
            chunk.chunk_hash, chunk.chunk_index,
            chunk.postgresql_versions, chunk.environment_applicability,
            chunk.source_document_title, chunk.source_document_version,
        ))
        conn.commit()
    except Exception as e:
        conn.rollback()
        failed = True
        print(f"chunk[{i}] FAILED: {type(e).__name__}")
        print(f"  {e}")
        if hasattr(e, 'diag'):
            print(f"  Table: {e.diag.table_name}, Column: {e.diag.column_name}")
            print(f"  Detail: {e.diag.message_detail}")
        break

if not failed:
    print(f"All {len(chunks)} chunks inserted OK!")
    
conn.close()
