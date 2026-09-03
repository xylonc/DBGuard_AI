"""
RAG Service for DBGuardAI
Retrieval-Augmented Generation service for PostgreSQL security knowledge.

Stores approved reference material in PostgreSQL with pgvector:
- CIS PostgreSQL benchmarks
- Company database-security policies
- Approved hardening procedures
- PostgreSQL operating standards
- Historical approved decisions

Every indexed document contains metadata for versioning, filtering, and
traceability. Retrieved chunks are always cited with source references.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras
import yaml

from app.config import settings
from app.services.embedding_service import generate_embedding

logger = logging.getLogger("dbguard.rag")


# ─── Constants ───────────────────────────────────────────────────────

CHUNK_SIZE = 500  # characters per chunk
CHUNK_OVERLAP = 50  # overlap between chunks for context continuity
MAX_CHUNKS = 1000  # max chunks per document to avoid excessive storage


# ─── RAG Data Models (inlined to avoid cross-package import issues) ──

class DocumentMetadata:
    """Metadata for a document in the RAG knowledge base."""
    def __init__(self, document_id: str, title: str, version: str, status: str,
                 effective_date: datetime, expiry_date: Optional[datetime],
                 postgresql_versions: List[str], environment_applicability: List[str],
                 policy_owner: str, classification: str, source_url: Optional[str],
                 created_at: datetime, updated_at: datetime,
                 approved_by: Optional[str] = None,
                 approved_at: Optional[datetime] = None):
        self.document_id = document_id
        self.title = title
        self.version = version
        self.status = status
        self.effective_date = effective_date
        self.expiry_date = expiry_date
        self.postgresql_versions = postgresql_versions
        self.environment_applicability = environment_applicability
        self.policy_owner = policy_owner
        self.classification = classification
        self.source_url = source_url
        self.created_at = created_at
        self.updated_at = updated_at
        self.approved_by = approved_by
        self.approved_at = approved_at


class KnowledgeChunk:
    """A chunk of a knowledge document for embedding and retrieval."""
    def __init__(self, document_id: str, section: str, content: str,
                 chunk_hash: str, chunk_index: int,
                 postgresql_versions: List[str],
                 environment_applicability: List[str],
                 source_document_title: str, source_document_version: str):
        self.document_id = document_id
        self.section = section
        self.content = content
        self.chunk_hash = chunk_hash
        self.chunk_index = chunk_index
        self.postgresql_versions = postgresql_versions
        self.environment_applicability = environment_applicability
        self.source_document_title = source_document_title
        self.source_document_version = source_document_version


class RetrievalResult:
    """A result from a RAG knowledge search."""
    def __init__(self, chunk_id: int, document_id: str, section: str, content: str,
                 chunk_hash: str, postgresql_versions: List[str],
                 environment_applicability: List[str],
                 source_document_title: str, source_document_version: str,
                 source_url: Optional[str],
                 similarity_score: float, retrieval_timestamp: datetime):
        self.chunk_id = chunk_id
        self.document_id = document_id
        self.section = section
        self.content = content
        self.chunk_hash = chunk_hash
        self.postgresql_versions = postgresql_versions
        self.environment_applicability = environment_applicability
        self.source_document_title = source_document_title
        self.source_document_version = source_document_version
        self.source_url = source_url
        self.similarity_score = similarity_score
        self.retrieval_timestamp = retrieval_timestamp


# ─── Data Classes ────────────────────────────────────────────────────

@dataclass
class KnowledgeDocument:
    """A document to be ingested into the RAG knowledge base."""
    document_id: str
    title: str
    version: str
    content: str  # Full text content
    effective_date: datetime
    status: str = "draft"
    approved_by: Optional[str] = None
    expiry_date: Optional[datetime] = None
    postgresql_versions: List[str] = field(default_factory=lambda: ["15", "16", "17"])
    environment_applicability: List[str] = field(default_factory=lambda: ["all"])
    policy_owner: str = ""
    classification: str = "internal"  # public, internal, confidential, licensed
    source_url: Optional[str] = None
    superseded_by: Optional[str] = None
    
    @property
    def document_hash(self) -> str:
        """SHA-256 hash of document content for integrity verification."""
        return hashlib.sha256(self.content.encode()).hexdigest()


@dataclass
class IngestionResult:
    """Result of a document ingestion operation."""
    document_id: str
    chunks_created: int
    status: str = "ingested"
    errors: List[str] = field(default_factory=list)
    skipped_sections: List[str] = field(default_factory=list)
    metadata_stored: bool = True


# ─── RAG Service ─────────────────────────────────────────────────────

class RAGService:
    """
    RAG Service for DBGuardAI.
    
    Handles:
    - Document ingestion (parsing, chunking, embedding, storage)
    - Retrieval (semantic search with pgvector, filtering, ranking)
    - Knowledge pack management (import, versioning, supersede)
    - Document lifecycle (supersede, archive, re-index)
    
    All documents are stored with full metadata for traceability and
    filtering. Retrieved chunks always include source citations.
    """
    
    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or os.getenv("DATABASE_URL", "postgresql://dbguard:dbguard@localhost:5433/dbguard")
        self.embedding_dim = settings.embedding_dim
        self.embedding_model = settings.embedding_model
        self.chunk_size = CHUNK_SIZE
        self.chunk_overlap = CHUNK_OVERLAP
        
        logger.info("RAG Service initialized: model=%s", self.embedding_model)
    
    def _get_db_connection(self) -> psycopg2.extensions.connection:
        """Get a database connection for RAG operations."""
        return psycopg2.connect(self.db_url)
    
    def _generate_embedding(self, text: str) -> List[float]:
        """Generate a vector through the application's shared provider adapter."""
        return generate_embedding(
            text,
            model=self.embedding_model,
            dimension=self.embedding_dim,
        )
    
    def ingest_document(self, document: KnowledgeDocument) -> IngestionResult:
        """
        Ingest a document into the RAG knowledge base.
        
        Process:
        1. Validate document
        2. Split into chunks by section (preserving headers as context)
        3. Generate embeddings for each chunk
        4. Store chunks with metadata in pgvector
        5. Update document metadata
        
        Returns IngestionResult with chunks created and any errors.
        """
        result = IngestionResult(
            document_id=document.document_id,
            chunks_created=0,
        )
        
        try:
            # Validate document
            if not self._validate_document(document):
                result.status = "rejected"
                result.errors.append("Document validation failed")
                return result
            
            # Split document into chunks
            chunks = self._chunk_document(document)
            result.skipped_sections = [
                chunk.section for chunk in chunks if not chunk.content.strip()
            ]
            
            # Generate embeddings and store
            embeddings = []
            for i, chunk in enumerate(chunks):
                if i >= MAX_CHUNKS:
                    logger.warning(f"Max chunks ({MAX_CHUNKS}) reached for document {document.document_id}")
                    break
                
                if not chunk.content.strip():
                    continue
                
                # Generate embedding
                try:
                    embedding = self._generate_embedding(chunk.content)
                    embeddings.append((chunk, embedding))
                except Exception as e:
                    logger.error(f"Failed to generate embedding for chunk {i}: {e}")
                    result.errors.append(f"Embedding failed for chunk {i}: {str(e)}")
            
            # Store chunks in database
            stored_count = self._store_chunks(document, embeddings)
            result.chunks_created = stored_count
            result.status = "ingested" if stored_count > 0 else "failed"
            
            logger.info(
                f"Document ingested: {document.document_id} "
                f"({stored_count} chunks, {len(embeddings)} embeddings)"
            )
            
        except Exception as e:
            logger.error(f"Document ingestion failed: {e}")
            result.status = "failed"
            result.errors.append(str(e))
        
        return result
    
    def _validate_document(self, document: KnowledgeDocument) -> bool:
        """Validate document before ingestion."""
        if not document.document_id or not document.title:
            return False
        
        if not document.content or len(document.content) < 100:
            return False
        
        if not document.effective_date:
            return False

        if document.status not in {"draft", "active"}:
            return False

        if document.status == "active" and not document.approved_by:
            return False
        
        # Check for supersession
        if document.superseded_by:
            existing = self.get_document_metadata(document.superseded_by)
            if existing and existing.status in ('active', 'superseded'):
                return True  # Superseding an existing document is fine
        
        return True
    
    def _chunk_document(self, document: KnowledgeDocument) -> List[KnowledgeChunk]:
        """
        Split document into chunks by section headers, then further split
        any section larger than CHUNK_SIZE using sliding window overlap.
        
        Preserves section headers as context for each chunk.
        """
        chunks = []
        lines = document.content.split('\n')
        current_chunk_lines = []
        current_section = "Introduction"
        
        for line in lines:
            # Detect section headers (Markdown-style or YAML-style)
            header_match = re.match(r'^(#{1,3})\s+(.+)$', line)
            if header_match:
                # Finalize current chunk if it has content
                if current_chunk_lines:
                    chunk = self._create_chunk(
                        document=document,
                        section=current_section,
                        content='\n'.join(current_chunk_lines),
                        chunk_index=len(chunks),
                    )
                    if chunk:
                        chunks.append(chunk)
                
                # Start new section
                current_section = header_match.group(2).strip()
                current_chunk_lines = [line]  # Include header in chunk
            else:
                current_chunk_lines.append(line)
        
        # Finalize last chunk
        if current_chunk_lines:
            chunk = self._create_chunk(
                document=document,
                section=current_section,
                content='\n'.join(current_chunk_lines),
                chunk_index=len(chunks),
            )
            if chunk:
                chunks.append(chunk)
        
        # Split oversized chunks using sliding window (P1 fix)
        result = []
        for c in chunks:
            if len(c.content) <= self.chunk_size:
                result.append(c)
            else:
                result.extend(self._split_oversized_chunk(c))
        
        # Enforce MAX_CHUNKS
        if len(result) > MAX_CHUNKS:
            logger.warning(f"Document {document.document_id} exceeds MAX_CHUNKS ({MAX_CHUNKS}); truncating to first {MAX_CHUNKS} chunks")
            result = result[:MAX_CHUNKS]

        # Oversized sections can consume multiple indexes. Re-number the final
        # sequence so later sections cannot collide with those sub-chunks.
        for chunk_index, chunk in enumerate(result):
            chunk.chunk_index = chunk_index

        return result

    def _create_chunk(
        self,
        document: KnowledgeDocument,
        section: str,
        content: str,
        chunk_index: int,
    ) -> Optional[KnowledgeChunk]:
        """Create a traceable chunk while preserving document applicability."""
        normalized_content = content.strip()
        if not normalized_content:
            return None
        return KnowledgeChunk(
            document_id=document.document_id,
            section=section,
            content=normalized_content,
            chunk_hash=hashlib.sha256(normalized_content.encode("utf-8")).hexdigest(),
            chunk_index=chunk_index,
            postgresql_versions=document.postgresql_versions,
            environment_applicability=document.environment_applicability,
            source_document_title=document.title,
            source_document_version=document.version,
        )

    def _split_oversized_chunk(self, chunk: KnowledgeChunk) -> List[KnowledgeChunk]:
        """Split a chunk larger than chunk_size using sliding window overlap."""
        text = chunk.content
        size = self.chunk_size
        overlap = self.chunk_overlap
        sub_chunks = []
        start = 0
        idx = chunk.chunk_index
        
        while start < len(text):
            end = min(start + size, len(text))
            sub_text = text[start:end]
            sub_hash = hashlib.sha256(sub_text.encode()).hexdigest()
            sub_chunks.append(KnowledgeChunk(
                document_id=chunk.document_id,
                section=f"{chunk.section} (cont.)" if start > 0 else chunk.section,
                content=sub_text,
                chunk_hash=sub_hash,
                chunk_index=idx,
                postgresql_versions=chunk.postgresql_versions,
                environment_applicability=chunk.environment_applicability,
                source_document_title=chunk.source_document_title,
                source_document_version=chunk.source_document_version,
            ))
            idx += 1
            start = end - overlap if end < len(text) else end
        
        return sub_chunks
    
    def _store_chunks(
        self, 
        document: KnowledgeDocument,
        embeddings: List[Tuple[KnowledgeChunk, List[float]]]
    ) -> int:
        """Store chunks and embeddings in pgvector database."""
        stored_count = 0
        
        conn = self._get_db_connection()
        try:
            cur = conn.cursor()
            
            # Insert document metadata row (P0 fix: now stored on ingest)
            cur.execute("""
                INSERT INTO knowledge_documents (
                    document_id, title, version, status,
                    effective_date, expiry_date,
                    postgresql_versions, environment_applicability,
                    policy_owner, classification, source_url, superseded_by,
                    document_hash, approved_by, approved_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (document_id) DO UPDATE
                SET title = EXCLUDED.title,
                    version = EXCLUDED.version,
                    status = EXCLUDED.status,
                    effective_date = EXCLUDED.effective_date,
                    expiry_date = EXCLUDED.expiry_date,
                    postgresql_versions = EXCLUDED.postgresql_versions,
                    environment_applicability = EXCLUDED.environment_applicability,
                    policy_owner = EXCLUDED.policy_owner,
                    classification = EXCLUDED.classification,
                    source_url = EXCLUDED.source_url,
                    superseded_by = EXCLUDED.superseded_by,
                    document_hash = EXCLUDED.document_hash,
                    approved_by = EXCLUDED.approved_by,
                    approved_at = EXCLUDED.approved_at,
                    updated_at = NOW()
            """, (
                document.document_id,
                document.title,
                document.version,
                document.status,
                document.effective_date,
                document.expiry_date,
                document.postgresql_versions,
                document.environment_applicability,
                document.policy_owner,
                document.classification,
                document.source_url,
                document.superseded_by,
                document.document_hash,
                document.approved_by,
                datetime.utcnow() if document.status == "active" else None,
            ))

            # Re-ingestion replaces a document's previous chunks atomically.
            # Cascading foreign keys remove the corresponding embeddings.
            cur.execute(
                "DELETE FROM knowledge_chunks WHERE document_id = %s",
                (document.document_id,),
            )

            for chunk, embedding in embeddings:
                # Store chunk metadata
                cur.execute("""
                    INSERT INTO knowledge_chunks (
                        document_id, section, content, chunk_hash,
                        chunk_index, postgresql_versions,
                        environment_applicability, source_document_title,
                        source_document_version
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    chunk.document_id,
                    chunk.section,
                    chunk.content,
                    chunk.chunk_hash,
                    chunk.chunk_index,
                    chunk.postgresql_versions,
                    chunk.environment_applicability,
                    chunk.source_document_title,
                    chunk.source_document_version,
                ))
                
                chunk_id = cur.fetchone()[0]
                
                # Store embedding with chunk ID
                # Convert embedding to array format for pgvector
                embedding_array = f"[{','.join(str(x) for x in embedding)}]"
                
                cur.execute("""
                    INSERT INTO knowledge_embeddings (
                        chunk_id, embedding, embedding_model
                    ) VALUES (%s, %s::vector, %s)
                """, (chunk_id, embedding_array, self.embedding_model))
                
                stored_count += 1
            
            conn.commit()
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to store chunks: {e}")
            raise
        finally:
            conn.close()
        
        return stored_count
    
    def search(
        self,
        query: str,
        pg_version: Optional[str] = None,
        environment: str = "all",
        top_k: int = 5,
        min_score: float = 0.5,
    ) -> List[RetrievalResult]:
        """
        Search for relevant knowledge chunks using semantic similarity.
        
        Filters by PostgreSQL version and environment applicability.
        Returns chunks ranked by cosine similarity with source citations.
        
        Args:
            query: Search query text
            pg_version: Filter by PostgreSQL version (e.g., "16")
            environment: Deployment environment (for example prod, dev, all)
            top_k: Maximum number of results to return
            min_score: Minimum similarity score threshold
            
        Returns:
            List of RetrievalResult with chunk content, metadata, and score
        """
        conn = self._get_db_connection()
        results = []
        
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Build WHERE clause for filters (P0 fix: enforce document lifecycle)
            where_clauses = [
                "kd.status = 'active'",  # Only active docs
                "kd.effective_date <= NOW()",  # Already in force
                "(kd.expiry_date IS NULL OR kd.expiry_date > NOW())",  # Not expired
                "(kc.environment_applicability @> %s OR kc.environment_applicability @> ARRAY['all']::varchar[])",
            ]
            filter_params = [[environment]]
            
            if pg_version:
                where_clauses.append("kc.postgresql_versions && %s")
                filter_params.append([pg_version])
            
            where_clause = " AND ".join(where_clauses)
            
            # Execute semantic search with pgvector (P0 fix: joined with documents table for lifecycle filtering)
            query_embedding = self._generate_embedding(query)
            embedding_array = f"[{','.join(str(x) for x in query_embedding)}]"
            
            sql = f"""
                SELECT 
                    kc.id,
                    kc.document_id,
                    kc.section,
                    kc.content,
                    kc.chunk_hash,
                    kc.chunk_index,
                    kc.postgresql_versions,
                    kc.environment_applicability,
                    kc.source_document_title,
                    kc.source_document_version,
                    kd.postgresql_versions AS doc_pg_versions,
                    kd.environment_applicability AS doc_env_applicability,
                    kd.effective_date,
                    kd.expiry_date,
                    kd.status AS doc_status,
                    kd.source_url,
                    ke.embedding,
                    (ke.embedding <=> %s::vector) AS similarity
                FROM knowledge_chunks kc
                JOIN knowledge_embeddings ke ON kc.id = ke.chunk_id
                JOIN knowledge_documents kd ON kc.document_id = kd.document_id
                WHERE {where_clause}
                ORDER BY similarity ASC  -- pgvector: lower = more similar
                LIMIT %s
            """
            
            cur.execute(sql, [embedding_array, *filter_params, top_k])
            rows = cur.fetchall()
            
            for row in rows:
                score = 1.0 - row['similarity']  # Convert distance to similarity
                
                if score < min_score:
                    continue
                
                result = RetrievalResult(
                    chunk_id=row['id'],
                    document_id=row['document_id'],
                    section=row['section'],
                    content=row['content'],
                    chunk_hash=row['chunk_hash'],
                    postgresql_versions=row['postgresql_versions'],
                    environment_applicability=row['environment_applicability'],
                    source_document_title=row['source_document_title'],
                    source_document_version=row['source_document_version'],
                    source_url=row['source_url'],
                    similarity_score=score,
                    retrieval_timestamp=datetime.utcnow(),
                )
                results.append(result)
            
            # Sort by score descending
            results.sort(key=lambda r: r.similarity_score, reverse=True)
            
        except Exception as e:
            logger.error(f"RAG search failed: {e}")
            raise
        finally:
            conn.close()
        
        return results
    
    def search_with_context(
        self,
        query: str,
        pg_version: Optional[str] = None,
        environment: str = "all",
        top_k: int = 5,
        min_score: float = 0.5,
    ) -> str:
        """
        Search and return formatted context for HERMES to use.
        
        Returns a string with all relevant chunks and citations,
        ready to be included in HERMES's prompt context.
        """
        results = self.search(query, pg_version, environment, top_k, min_score)
        
        if not results:
            return "MANUAL_REVIEW_REQUIRED: No approved evidence found for this query."
        
        context_parts = [f"# Retrieved Evidence ({len(results)} chunks)\n"]
        
        for i, result in enumerate(results, 1):
            context_parts.append(
                f"## Chunk {i} (similarity: {result.similarity_score:.2f})\n"
                f"**Document:** {result.source_document_title} v{result.source_document_version}\n"
                f"**Section:** {result.section}\n"
                f"**PostgreSQL Versions:** {', '.join(result.postgresql_versions)}\n"
                f"**Source:** {result.source_url or result.document_id}\n"
                f"\n{result.content}\n"
                f"\n---\n"
            )
        
        return "\n".join(context_parts)
    
    def get_document_metadata(
        self, 
        document_id: str,
    ) -> Optional[DocumentMetadata]:
        """Get metadata for a specific document."""
        conn = self._get_db_connection()
        
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT document_id, title, version, status,
                       effective_date, expiry_date, postgresql_versions,
                       environment_applicability, policy_owner, classification, source_url,
                       created_at, updated_at, approved_by, approved_at
                FROM knowledge_documents
                WHERE document_id = %s
            """, (document_id,))
            
            row = cur.fetchone()
            if row:
                return DocumentMetadata(
                    document_id=row[0],
                    title=row[1],
                    version=row[2],
                    status=row[3],
                    effective_date=row[4],
                    expiry_date=row[5],
                    postgresql_versions=row[6] or [],
                    environment_applicability=row[7] or ['all'],
                    policy_owner=row[8] or '',
                    classification=row[9],
                    source_url=row[10],
                    created_at=row[11],
                    updated_at=row[12],
                    approved_by=row[13],
                    approved_at=row[14],
                )
            return None
            
        except Exception as e:
            logger.error(f"Failed to get document metadata: {e}")
            return None
        finally:
            conn.close()
    
    def supersede_document(self, document_id: str, new_version: str) -> bool:
        """
        Mark a document as superseded by a new version.
        
        The old document becomes read-only, new version takes precedence.
        """
        conn = self._get_db_connection()
        
        try:
            cur = conn.cursor()
            
            # Update old document
            cur.execute("""
                UPDATE knowledge_documents
                SET status = 'superseded',
                    superseded_by = %s,
                    updated_at = %s
                WHERE document_id = %s
            """, (new_version, datetime.utcnow(), document_id))
            
            success = cur.rowcount > 0
            
            if success:
                conn.commit()
                logger.info(f"Document superseded: {document_id} -> {new_version}")
            else:
                logger.warning(f"Document not found for supersede: {document_id}")
            
            return success
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to supersede document: {e}")
            return False
        finally:
            conn.close()

    def approve_document(self, document_id: str, approved_by: str) -> bool:
        """Activate a human-reviewed draft so it can appear in retrieval."""
        conn = self._get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("""
                UPDATE knowledge_documents
                SET status = 'active', approved_by = %s,
                    approved_at = NOW(), updated_at = NOW()
                WHERE document_id = %s AND status = 'draft'
            """, (approved_by, document_id))
            success = cur.rowcount == 1
            conn.commit()
            return success
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def get_applicable_documents(
        self,
        pg_version: str,
        environment: str = "all",
    ) -> List[DocumentMetadata]:
        """Get all documents applicable to a specific PostgreSQL version and environment."""
        conn = self._get_db_connection()
        
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT document_id, title, version, status,
                       effective_date, expiry_date, postgresql_versions,
                       environment_applicability, policy_owner, classification, source_url,
                       created_at, updated_at, approved_by, approved_at
                FROM knowledge_documents
                WHERE status = 'active'
                  AND postgresql_versions && %s
                  AND (environment_applicability @> %s OR environment_applicability @> '{all}')
                  AND effective_date <= NOW()
                  AND (expiry_date IS NULL OR expiry_date > NOW())
            """, ([pg_version], [environment]))
            
            rows = cur.fetchall()
            docs = []
            
            for row in rows:
                docs.append(DocumentMetadata(
                    document_id=row[0],
                    title=row[1],
                    version=row[2],
                    status=row[3],
                    effective_date=row[4],
                    expiry_date=row[5],
                    postgresql_versions=row[6],
                    environment_applicability=row[7] or ['all'],
                    policy_owner=row[8] or '',
                    classification=row[9],
                    source_url=row[10],
                    created_at=row[11],
                    updated_at=row[12],
                    approved_by=row[13],
                    approved_at=row[14],
                ))
            
            return docs
            
        except Exception as e:
            logger.error(f"Failed to get applicable documents: {e}")
            return []
        finally:
            conn.close()
    
    def ingest_knowledge_pack(self, pack_path: str) -> Dict[str, Any]:
        """
        Ingest a knowledge pack from a directory or YAML file.
        
        Expected structure:
        knowledge/
        ├── manifests/
        │   └── cis-pg-benchmark-1.0.0.yaml
        └── public_seed/
            └── cis-postgresql-benchmark.md
        
        The manifest defines document metadata, the content files contain text.
        """
        results = {
            "pack_name": Path(pack_path).name,
            "documents_ingested": 0,
            "chunks_created": 0,
            "errors": [],
        }
        
        pack_path = Path(pack_path)
        
        # Try to ingest as a single YAML manifest
        if pack_path.suffix in (".yaml", ".yml"):
            try:
                with open(pack_path, "r") as f:
                    manifest = yaml.safe_load(f)
                
                doc = KnowledgeDocument(
                    document_id=manifest.get("document_id", pack_path.stem),
                    title=manifest.get("title", "Unknown"),
                    version=manifest.get("version", "1.0.0"),
                    content=manifest.get("content", ""),
                    effective_date=datetime.fromisoformat(
                        manifest.get("effective_date", datetime.utcnow().isoformat())
                    ),
                    expiry_date=datetime.fromisoformat(manifest.get("expiry_date")) if manifest.get("expiry_date") else None,
                    postgresql_versions=manifest.get("postgresql_versions", ["15", "16", "17"]),
                    environment_applicability=manifest.get("environment_applicability", ["all"]),
                    policy_owner=manifest.get("policy_owner", ""),
                    classification=manifest.get("classification", "internal"),
                    source_url=manifest.get("source_url"),
                    superseded_by=manifest.get("superseded_by"),
                )
                
                ingestion = self.ingest_document(doc)
                results["documents_ingested"] += 1
                results["chunks_created"] += ingestion.chunks_created
                results["errors"].extend(ingestion.errors)
                
            except Exception as e:
                results["errors"].append(f"Failed to ingest pack: {str(e)}")
        
        # Try to ingest as a directory
        elif pack_path.is_dir():
            for yaml_file in pack_path.glob("*.yaml"):
                try:
                    with open(yaml_file, "r") as f:
                        manifest = yaml.safe_load(f)
                    
                    # Find corresponding content file
                    content_file = yaml_file.with_suffix(".md")
                    if not content_file.exists():
                        content_file = yaml_file.with_suffix(".txt")
                    
                    if content_file.exists():
                        with open(content_file, "r") as f:
                            manifest["content"] = f.read()
                        
                        doc = KnowledgeDocument(**manifest)
                        ingestion = self.ingest_document(doc)
                        results["documents_ingested"] += 1
                        results["chunks_created"] += ingestion.chunks_created
                        results["errors"].extend(ingestion.errors)
                
                except Exception as e:
                    results["errors"].append(f"Failed to ingest {yaml_file.name}: {str(e)}")
        
        return results
    
    def health_check(self) -> Dict[str, Any]:
        """Check the health of the RAG service."""
        try:
            conn = self._get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM knowledge_documents WHERE status = 'active'")
            active_docs = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM knowledge_embeddings")
            total_embeddings = cur.fetchone()[0]
            
            conn.close()
            
            return {
                "status": "healthy",
                "service": "dbguard-rag",
                "active_documents": active_docs,
                "total_embeddings": total_embeddings,
                "embedding_model": self.embedding_model,
                "provider": self.provider.value,
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
            }


# ─── Singleton Instance ──────────────────────────────────────────────

rag_service = RAGService()
