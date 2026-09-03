-- DBGuardAI — Database initialization
-- Run against the dbguard_rag database

-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Templates table for RAG retrieval
CREATE TABLE IF NOT EXISTS templates (
    id              SERIAL PRIMARY KEY,
    template_name   TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL,
    sql_template    TEXT NOT NULL,
    tags            TEXT[] DEFAULT '{}',
    risk_level      TEXT,
    pg_version      TEXT,
    embedding       vector(768),           -- nomic-embed-text default dim
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- IVFFlat index for cosine similarity search (best for large datasets)
-- Requires: CALL ivfflat_index_build('templates', 'embedding', 'lists', 10);
-- after inserting data. For small datasets, Gist works without training.
CREATE INDEX IF NOT EXISTS templates_embedding_idx
    ON templates USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 10);
