"""Tier C tests for Lifecycle - End-to-end with known bugs marked with xfail.

Known Bug - Partial Chunk Ingestion:
The RAGService.ingest_document() method incorrectly reports status as 'ingested'
when only partial chunks are successfully ingested. The bug causes the method
to return success even when some chunks fail to embed or store.

This is documented in the code at services/rag/rag_service.py line 237:
    result.status = "ingested" if stored_count > 0 else "failed"

The fix should be:
    result.status = "partial" if stored_count > 0 and stored_count < len(embeddings)
    result.status = "ingested" if stored_count == len(embeddings)
    result.status = "failed" if stored_count == 0
"""
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from services.rag.rag_service import IngestionResult, KnowledgeDocument, RAGService

pytestmark = pytest.mark.tier_c


class TestPartialChunkIngestionBug:
    """Tests for the Partial Chunk Ingestion bug.

    BUG: Partial chunk ingestion incorrectly reports status as 'ingested'
    instead of 'partial' or 'failed'.

    The bug occurs when some chunks are successfully ingested but others fail.
    The current implementation returns 'ingested' if stored_count > 0,
    regardless of how many chunks actually failed.

    Expected behavior:
    - All chunks succeed → status = "ingested"
    - Some chunks fail → status = "partial"
    - All chunks fail → status = "failed"
    """

    @pytest.mark.xfail(reason="Bug: Partial chunk ingestion incorrectly reports status as 'ingested' instead of 'partial' or 'failed'")
    def test_partial_chunk_ingestion_reports_correct_status(self, mock_embedding_provider):
        """Test that partial chunk ingestion reports 'partial' status.

        This test simulates a scenario where some chunks fail to embed but others succeed.
        The expected behavior is to report status as 'partial' in this case.

        The test will FAIL with the current buggy implementation because it reports
        'ingested' even when chunks are missing.
        """
        with patch("services.rag.rag_service.RAGService._get_db_connection") as mock_get_conn:
            # Setup mock database connection
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_get_conn.return_value = mock_conn

            # Mock document metadata check
            mock_cursor.fetchone.return_value = [None]

            # Track chunk insertion calls
            inserted_chunks = []

            def mock_execute(sql, params=None):
                if "INSERT INTO knowledge_chunks" in sql:
                    # Simulate success for first 2 chunks, failure for third
                    chunk_index = params[4] if params else 0
                    if chunk_index < 2:
                        mock_cursor.fetchone.return_value = [1]  # chunk_id
                        inserted_chunks.append(chunk_index)
                    else:
                        # Third chunk fails
                        raise Exception("Embedding generation failed for chunk 2")

            mock_cursor.execute.side_effect = mock_execute
            mock_cursor.fetchall.return_value = []
            mock_cursor.rowcount = 0

            doc = KnowledgeDocument(
                document_id="partial_test_doc",
                title="Partial Ingestion Test",
                version="1.0.0",
                content="# Test\n" + ("Content line\n" * 500),
                effective_date=datetime.utcnow(),
                status="draft",
            )

            rag_service = RAGService()
            # Mock _generate_embedding to fail for some chunks
            original_generate = rag_service._generate_embedding

            def mock_generate(text):
                if len(inserted_chunks) >= 2:
                    raise Exception("Embedding provider unavailable")
                return original_generate(text)

            with patch.object(rag_service, "_generate_embedding", side_effect=mock_generate):
                result = rag_service.ingest_document(doc)

            # With the bug, this returns 'ingested' when it should be 'partial'
            assert result.status == "partial", (
                f"Expected status 'partial' for partial ingestion, got '{result.status}'"
            )
            assert result.chunks_created == 2, (
                f"Expected 2 chunks created, got {result.chunks_created}"
            )
            assert len(result.errors) > 0, (
                "Expected errors to be reported for failed chunks"
            )

    @pytest.mark.xfail(reason="Bug: Partial chunk ingestion incorrectly reports status as 'ingested' instead of 'partial' or 'failed'")
    def test_all_chunks_fail_reports_failed_status(self, mock_embedding_provider):
        """Test that when all chunks fail, status is 'failed'.

        This test simulates a scenario where all chunks fail to embed.
        The expected behavior is to report status as 'failed'.

        The test will FAIL with the current buggy implementation.
        """
        with patch("services.rag.rag_service.RAGService._get_db_connection") as mock_get_conn:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_get_conn.return_value = mock_conn

            mock_cursor.fetchone.return_value = [None]

            # Mock all chunk insertions to fail
            def mock_execute_fail(sql, params=None):
                raise Exception("Database connection lost")

            mock_cursor.execute.side_effect = mock_execute_fail
            mock_cursor.fetchall.return_value = []
            mock_cursor.rowcount = 0

            doc = KnowledgeDocument(
                document_id="all_fail_doc",
                title="All Fail Test",
                version="1.0.0",
                content="# Test\n" + ("Content line\n" * 1000),
                effective_date=datetime.utcnow(),
                status="draft",
            )

            rag_service = RAGService()

            with patch.object(rag_service, "_generate_embedding", side_effect=Exception("Embedding failed")):
                result = rag_service.ingest_document(doc)

            # With the bug, this might return 'ingested' when it should be 'failed'
            assert result.status == "failed", (
                f"Expected status 'failed' when all chunks fail, got '{result.status}'"
            )
            assert result.chunks_created == 0, (
                f"Expected 0 chunks created when all fail, got {result.chunks_created}"
            )
            assert len(result.errors) > 0, (
                "Expected errors to be reported when all chunks fail"
            )

    def test_all_chunks_succeed_reports_ingested_status(self, mock_embedding_provider):
        """Test that when all chunks succeed, status is 'ingested'.

        This is the happy path and should pass with both buggy and fixed implementations.
        """
        with patch("services.rag.rag_service.RAGService._get_db_connection") as mock_get_conn, \
             patch("services.rag.rag_service.generate_embedding") as mock_gen_embed:
            mock_get_conn.return_value = mock_get_conn
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_get_conn.__enter__ = lambda self: mock_conn
            mock_get_conn.__exit__ = lambda self, *args: None
            mock_get_conn.cursor.return_value = mock_cursor
            
            mock_cursor.fetchone.return_value = [1, "test_doc", "1.0.0", "active", None]
            
            call_count = [0]
            
            def mock_execute(sql, params=None):
                if "INSERT INTO knowledge_chunks" in sql:
                    call_count[0] += 1
                    mock_cursor.fetchone.return_value = [call_count[0]]
            
            mock_cursor.execute.side_effect = mock_execute
            mock_cursor.fetchall.return_value = []
            mock_gen_embed.return_value = [0.1] * 768
            
            doc = KnowledgeDocument(
                document_id="full_success_doc",
                title="Full Success Test",
                version="1.0.0",
                content="# Test\n" + ("Content line\n" * 100),
                effective_date=datetime.utcnow(),
                status="draft",
            )
            
            rag_service = RAGService()
            result = rag_service.ingest_document(doc)

            # This should pass with both implementations
            assert result.status == "ingested", (
                f"Expected status 'ingested' when all chunks succeed, got '{result.status}'"
            )
            assert result.chunks_created > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
