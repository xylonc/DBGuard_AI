-- Phase 1: Template RAG - pgvector schema
-- Run against the dbguard_rag database

-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Templates table for RAG retrieval
CREATE TABLE IF NOT EXISTS templates (
    id            SERIAL PRIMARY KEY,
    template_name TEXT NOT NULL UNIQUE,
    description   TEXT NOT NULL,
    sql_template  TEXT NOT NULL,
    tags          TEXT[] DEFAULT '{}',
    risk_level    TEXT,
    pg_version    TEXT,
    created_at    TIMESTAMP DEFAULT NOW(),
    updated_at    TIMESTAMP DEFAULT NOW(),
    embedding     vector(1536)
);

-- IVFFlat index for cosine similarity search
CREATE INDEX IF NOT EXISTS templates_embedding_idx
    ON templates USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 10);
