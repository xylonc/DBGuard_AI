-- DBGuardAI POC — Database Schema
-- PostgreSQL 15/16/17 compatible with pgvector extension.
-- Tables:
--   1. knowledge_documents  — Document metadata and lifecycle
--   2. knowledge_chunks     — Text chunks for embedding
--   3. knowledge_embeddings — pgvector vectors linked to chunks
--   4. templates            — Legacy template RAG (from original repo)

-- ─── Extensions ───────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS vector;

-- ─── 1. knowledge_documents ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS knowledge_documents (
    document_id       VARCHAR(255) PRIMARY KEY,
    title             VARCHAR(512) NOT NULL,
    version           VARCHAR(64)  NOT NULL,
    status            VARCHAR(32)  NOT NULL DEFAULT 'active',
    effective_date    TIMESTAMP    NOT NULL,
    expiry_date       TIMESTAMP,
    postgresql_versions VARCHAR(255)[],  -- e.g. {15,16,17}
    environment_applicability VARCHAR(255)[], -- e.g. {all,prod,dev}
    policy_owner      VARCHAR(255),
    classification    VARCHAR(32)  NOT NULL DEFAULT 'internal',
    source_url        TEXT,
    superseded_by     VARCHAR(255),
    document_hash     VARCHAR(64),  -- SHA-256
    created_at        TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMP    NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE knowledge_documents IS 'Source documents for RAG knowledge base';
COMMENT ON COLUMN knowledge_documents.status IS 'active | superseded | archived';
COMMENT ON COLUMN knowledge_documents.classification IS 'public | internal | confidential | licensed';
COMMENT ON COLUMN knowledge_documents.postgresql_versions IS 'PostgreSQL major versions this document applies to';
COMMENT ON COLUMN knowledge_documents.environment_applicability IS 'Environments where this document is relevant';

CREATE INDEX IF NOT EXISTS idx_knowledge_docs_status
    ON knowledge_documents (status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_knowledge_docs_pg_versions
    ON knowledge_documents USING GIN (postgresql_versions);
CREATE INDEX IF NOT EXISTS idx_knowledge_docs_env
    ON knowledge_documents USING GIN (environment_applicability);

-- ─── 2. knowledge_chunks ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS knowledge_chunks (
    id                  SERIAL PRIMARY KEY,
    document_id         VARCHAR(255) NOT NULL REFERENCES knowledge_documents(document_id),
    section             VARCHAR(255) NOT NULL,
    content             TEXT         NOT NULL,
    chunk_hash          VARCHAR(64)  NOT NULL,  -- SHA-256 of content
    chunk_index         INT          NOT NULL,  -- order within document
    postgresql_versions VARCHAR(255)[],
    environment_applicability VARCHAR(255)[],
    source_document_title VARCHAR(512),
    source_document_version VARCHAR(64),
    created_at          TIMESTAMP    NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE knowledge_chunks IS 'Chunked text from knowledge_documents';
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_doc
    ON knowledge_chunks (document_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_hash
    ON knowledge_chunks (chunk_hash);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_pg
    ON knowledge_chunks USING GIN (postgresql_versions);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_env
    ON knowledge_chunks USING GIN (environment_applicability);

-- ─── 3. knowledge_embeddings ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS knowledge_embeddings (
    id              SERIAL PRIMARY KEY,
    chunk_id        INT NOT NULL REFERENCES knowledge_chunks(id) ON DELETE CASCADE,
    embedding       vector(1536),  -- default dim; adjust to match embedding model
    embedding_model VARCHAR(128)  NOT NULL DEFAULT 'text-embedding-3-small',
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE knowledge_embeddings IS 'pgvector embeddings linked to knowledge_chunks';
CREATE INDEX IF NOT EXISTS idx_knowledge_emb_chunk
    ON knowledge_embeddings (chunk_id);
-- IVFFlat index for fast approximate nearest-neighbour search
CREATE INDEX IF NOT EXISTS idx_knowledge_emb_vector
    ON knowledge_embeddings USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- ─── 4. templates (legacy — from original repo) ──────────────────
CREATE TABLE IF NOT EXISTS templates (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    sql_template    TEXT,
    tags            TEXT[],
    risk_level      VARCHAR(32),
    pg_version      VARCHAR(32),
    embedding       vector(768),  -- nomic-embed-text dimension
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_templates_embedding
    ON templates USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 50);
