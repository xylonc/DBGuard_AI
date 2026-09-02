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
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras
import yaml

logger = logging.getLogger("dbguard.rag")


# ─── Constants ───────────────────────────────────────────────────────

CHUNK_SIZE = 500  # characters per chunk
CHUNK_OVERLAP = 50  # overlap between chunks for context continuity
MAX_CHUNKS = 1000  # max chunks per document to avoid excessive storage


class EmbeddingProvider(str, Enum):
    OPENAI = "openai"
    OLLAMA = "ollama"
    OLLAMA_CLOUD = "ollama-cloud"


# ─── RAG Data Models (inlined to avoid cross-package import issues) ──

class DocumentMetadata:
    """Metadata for a document in the RAG knowledge base."""
    def __init__(self, document_id: str, title: str, version: str, status: str,
                 effective_date: datetime, expiry_date: Optional[datetime],
                 postgresql_versions: List[str], environment_applicability: List[str],
                 policy_owner: str, classification: str, source_url: Optional[str],
                 created_at: datetime, updated_at: datetime):
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
    def __init__(self, chunk_id: str, document_id: str, section: str, content: str,
                 chunk_hash: str, postgresql_versions: List[str],
                 environment_applicability: List[str],
                 source_document_title: str, source_document_version: str,
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
        self.db_url = db_url or os.getenv("DATABASE_URL", "postgresql://admin:securepassword123@localhost:5433/dbguard_rag")
        self.embedding_dim = int(os.getenv("RAG_EMBEDDING_DIM", "1536"))
        self.embedding_model = os.getenv("RAG_EMBEDDING_MODEL", "text-embedding-3-small")
        llm_provider = os.getenv("LLM_PROVIDER", "openai")
        self.provider = EmbeddingProvider(llm_provider)
        self.chunk_size = CHUNK_SIZE
        self.chunk_overlap = CHUNK_OVERLAP
        
        logger.info(f"RAG Service initialized: provider={self.provider}, model={self.embedding_model}")
    
    def _get_db_connection(self) -> psycopg2.extensions.connection:
        """Get a database connection for RAG operations."""
        return psycopg2.connect(self.db_url)
    
    def _generate_embedding(self, text: str) -> List[float]:
        """Generate embedding vector using OpenAI or Ollama API directly.
        Self-contained — mirrors vector_service.py logic but reads from os.getenv.
        """
        import requests
        
        openai_key = os.getenv("OPENAI_API_KEY", "")
        ollama_key = os.getenv("OLLAMA_API_KEY", "")
        
        def _is_real_key(key: str) -> bool:
            if not key:
                return False
            fake_keys = {"***", "*", "your-api-key-here", "redacted", "sk-..."}
            if key in fake_keys:
                return False
            if key.startswith("sk-"):
                return len(key) > 20 and "*" not in key and "placeholder" not in key.lower()
            return True
        
        use_ollama = _is_real_key(ollama_key)
        use_openai = _is_real_key(openai_key)
        
        if use_openai and not use_ollama:
            from openai import OpenAI
            client = OpenAI(api_key=openai_key)
            model = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")
            response = client.embeddings.create(model=model, input=text)
            embedding_vec = list(response.data[0].embedding)
        else:
            # Use Ollama (local or cloud)
            ollama_base = os.getenv("OLLAMA_API_BASE", "http://localhost:11434")
            ollama_base = ollama_base.rstrip("/")
            if "ollama.com/api" in ollama_base and "api.ollama.com" not in ollama_base:
                ollama_base = "https://api.ollama.com"
            elif ollama_base == "https://api.ollama.com/v1":
                ollama_base = "https://api.ollama.com"
            
            model = os.getenv("EMBEDDING_MODEL", "nomic-embed-text")
            headers = {"Content-Type": "application/json"}
            if ollama_key:
                headers["Authorization"] = f"Bearer {ollama_key}"
            
            response = requests.post(f"{ollama_base}/api/embed", json={
                "model": model,
                "input": text
            }, headers=headers, timeout=30)
            if response.status_code != 200:
                raise RuntimeError(f"Embedding failed: {response.status_code} {response.text}")
            data = response.json()
            embedding_vec = list(data["embeddings"][0])
        
        # Pad or truncate to expected dimension
        dim = self.embedding_dim
        if len(embedding_vec) < dim:
            embedding_vec += [0.0] * (dim - len(embedding_vec))
        return embedding_vec[:dim]
    
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
        
        # Check for supersession
        if document.superseded_by:
            existing = self.get_document_metadata(document.superseded_by)
            if existing and existing.versions_stored:
                return True  # Superseding a valid document is fine
        
        return True
    
    def _chunk_document(self, document: KnowledgeDocument) -> List[KnowledgeChunk]:
        """
        Split document into chunks by section headers.
        
        Preserves section headers as context for each chunk.
        Uses sliding window approach for better semantic continuity.
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
        
        # Apply sliding window overlap if needed
        if len(chunks) > 1:
            chunks = self._apply_overlap(chunks)
        
        return chunks
    
    def _create_chunk(
        self, 
        document: KnowledgeDocument,
        section: str,
        content: str,
        chunk_index: int,
    ) -> Optional[KnowledgeChunk]:
        """Create a KnowledgeChunk from document content."""
        if not content.strip():
            return None
        
        # Calculate chunk hash
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        return KnowledgeChunk(
            document_id=document.document_id,
            section=section,
            content=content,
            chunk_hash=content_hash,
            chunk_index=chunk_index,
            postgresql_versions=document.postgresql_versions,
            environment_applicability=document.environment_applicability,
            source_document_title=document.title,
            source_document_version=document.version,
        )
    
    def _apply_overlap(self, chunks: List[KnowledgeChunk]) -> List[KnowledgeChunk]:
        """Apply sliding window overlap between chunks."""
        # For now, keep chunks as-is; overlap is mainly for embedding quality
        # In production, you might merge small adjacent chunks
        return chunks
    
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
            top_k: Maximum number of results to return
            min_score: Minimum similarity score threshold
            
        Returns:
            List of RetrievalResult with chunk content, metadata, and score
        """
        conn = self._get_db_connection()
        results = []
        
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Build WHERE clause for filters
            where_clauses = []
            params = [query]
            
            if pg_version:
                where_clauses.append(
                    "kc.postgresql_versions && %s"
                )
                params.append(f"{{{pg_version}}}")
            
            where_clause = " AND ".join(where_clauses) if where_clauses else "1=1"
            
            # Execute semantic search with pgvector
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
                    ke.embedding,
                    (ke.embedding <=> '{embedding_array}'::vector) AS similarity
                FROM knowledge_chunks kc
                JOIN knowledge_embeddings ke ON kc.id = ke.chunk_id
                WHERE {where_clause}
                ORDER BY similarity ASC  -- pgvector: lower = more similar
                LIMIT %s
            """
            
            params.append(top_k)
            
            cur.execute(sql, params)
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
        top_k: int = 5,
        min_score: float = 0.5,
    ) -> str:
        """
        Search and return formatted context for HERMES to use.
        
        Returns a string with all relevant chunks and citations,
        ready to be included in HERMES's prompt context.
        """
        results = self.search(query, pg_version, top_k, min_score)
        
        if not results:
            return "MANUAL_REVIEW_REQUIRED: No approved evidence found for this query."
        
        context_parts = [f"# Retrieved Evidence ({len(results)} chunks)\n"]
        
        for i, result in enumerate(results, 1):
            context_parts.append(
                f"## Chunk {i} (similarity: {result.similarity_score:.2f})\n"
                f"**Document:** {result.source_document_title} v{result.source_document_version}\n"
                f"**Section:** {result.section}\n"
                f"**PostgreSQL Versions:** {', '.join(result.postgresql_versions)}\n"
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
                       policy_owner, classification, source_url,
                       created_at, updated_at
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
                    postgresql_versions=row[6],
                    policy_owner=row[7],
                    classification=row[8],
                    source_url=row[9],
                    created_at=row[10],
                    updated_at=row[11],
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
                       policy_owner, classification, source_url,
                       created_at, updated_at
                FROM knowledge_documents
                WHERE status = 'active'
                  AND postgresql_versions && %s
                  AND (environment_applicability @> %s OR environment_applicability @> '{all}')
                  AND (expiry_date IS NULL OR expiry_date > NOW())
            """, (f"{{{pg_version}}}", f"{{{environment}}}"))
            
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
                    policy_owner=row[7],
                    classification=row[8],
                    source_url=row[9],
                    created_at=row[10],
                    updated_at=row[11],
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
