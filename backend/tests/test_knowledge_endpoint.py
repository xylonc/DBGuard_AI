"""Tests for POST /api/v1/knowledge/upload — XLSX ingestion POC.

Tests:
  1. Valid XLSX workbook uploads successfully.
  2. Spreadsheet values are converted to meaningful normalized text.
  3. The existing KnowledgeIngestRequest Pydantic model validates correctly.
  4. The upload endpoint reaches the existing RAG ingestion path (mocked).
  5. A non-XLSX file is rejected with 400.
  6. An empty workbook is rejected with 400.
"""

import io
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure the backend package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from openpyxl import Workbook  # type: ignore

from tests.test_app import app as flask_app  # noqa: E402

client = TestClient(flask_app)


# ── helpers ──────────────────────────────────────────────────────────────


def make_xlsx(
    sheet_name: str = "Security Controls",
    header: list[str] | None = None,
    rows: list[list[str]] | None = None,
) -> bytes:
    """Create a tiny XLSX workbook in memory and return its bytes."""
    wb = Workbook()
    ws = wb.active
    ws.title = sheet_name

    if header:
        ws.append(header)
    if rows:
        for row in rows:
            ws.append(row)

    buf = io.BytesIO()
    wb.save(buf)
    wb.close()
    buf.seek(0)
    return buf.read()


def make_empty_xlsx(sheet_name: str = "Empty Sheet") -> bytes:
    """Create an XLSX with a sheet name but no cells at all."""
    wb = Workbook()
    ws = wb.active
    ws.title = sheet_name
    buf = io.BytesIO()
    wb.save(buf)
    wb.close()
    buf.seek(0)
    return buf.read()


# ── tests ────────────────────────────────────────────────────────────────


class TestXlsxExtraction:
    """Direct tests on the XLSX extractor module."""

    def test_valid_xlsx_produces_meaningful_text(self):
        """Test 2 — spreadsheet values are converted to meaningful text."""
        from app.xlsx_extractor import extract_xlsx_to_text

        xlsx_bytes = make_xlsx(
            sheet_name="Security Controls",
            header=["Control", "Requirement", "Severity"],
            rows=[
                ["DB-001", "TLS required", "High"],
                ["DB-002", "Logging enabled", "Medium"],
            ],
        )

        text = extract_xlsx_to_text(xlsx_bytes)

        assert "Security Controls" in text
        assert "DB-001" in text
        assert "TLS required" in text
        assert "DB-002" in text
        assert "Logging enabled" in text
        assert "Control: DB-001" in text

    def test_valid_xlsx_content_length(self):
        """Ensure extracted text is long enough for RAG chunking (>100 chars)."""
        from app.xlsx_extractor import extract_xlsx_to_text

        xlsx_bytes = make_xlsx(
            sheet_name="Security Controls",
            header=["Control", "Requirement", "Severity"],
            rows=[
                ["DB-001", "TLS required", "High"],
                ["DB-002", "Logging enabled", "Medium"],
            ],
        )

        text = extract_xlsx_to_text(xlsx_bytes)
        assert len(text) >= 100


class TestXlsxUploadEndpoint:
    """Tests for the POST /api/v1/knowledge/upload endpoint."""

    def test_valid_xlsx_upload_succeeds(self, mocker):
        """Test 1 & 4 — valid XLSX uploads and reaches existing RAG ingestion path."""
        mock_result = mocker.MagicMock()
        mock_result.status = "ingested"
        mock_result.chunks_created = 5
        mock_result.errors = []

        mocker.patch(
            "app.knowledge_endpoint.rag_service.ingest_document",
            return_value=mock_result,
        )

        xlsx_bytes = make_xlsx(
            sheet_name="Security Controls",
            header=["Control", "Requirement"],
            rows=[
                ["DB-001", "TLS required"],
                ["DB-002", "Logging enabled"],
            ],
        )

        response = client.post(
            "/api/v1/knowledge/upload",
            files={"file": ("security-controls.xlsx", io.BytesIO(xlsx_bytes), "application/octet-stream")},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ingested"
        assert data["chunks_created"] == 5
        assert "document_id" in data
        assert "title" in data

    def test_non_xlsx_file_rejected(self):
        """Test 5 — a non-XLSX file is rejected with 400."""
        response = client.post(
            "/api/v1/knowledge/upload",
            files={"file": ("readme.txt", io.BytesIO(b"not an xlsx"), "text/plain")},
        )

        assert response.status_code == 400
        assert ".xlsx" in response.json()["detail"].lower()

    def test_empty_xlsx_rejected(self):
        """Test 6 — an empty workbook (no cells) is rejected with 400."""
        xlsx_bytes = make_empty_xlsx()

        response = client.post(
            "/api/v1/knowledge/upload",
            files={"file": ("empty.xlsx", io.BytesIO(xlsx_bytes), "application/octet-stream")},
        )

        assert response.status_code == 400
        detail = response.json()["detail"].lower()
        assert "empty" in detail or "short" in detail

    def test_empty_file_rejected(self):
        """Bonus: an uploaded file with zero bytes is rejected."""
        response = client.post(
            "/api/v1/knowledge/upload",
            files={"file": ("empty.xlsx", io.BytesIO(b""), "application/octet-stream")},
        )

        assert response.status_code == 400


class TestPydanticContract:
    """Test 3 — the existing KnowledgeIngestRequest validates correctly."""

    def test_knowledge_ingest_request_validates(self):
        """Ensure the Pydantic contract accepts text built from XLSX extraction."""
        from app.models import KnowledgeIngestRequest

        from app.xlsx_extractor import extract_xlsx_to_text

        xlsx_bytes = make_xlsx(
            sheet_name="Security Controls",
            header=["Control", "Requirement"],
            rows=[
                ["DB-001", "TLS required"],
                ["DB-002", "Logging enabled"],
            ],
        )

        text = extract_xlsx_to_text(xlsx_bytes)

        request = KnowledgeIngestRequest(
            document_id="test-xlsx-001",
            title="Security Controls",
            version="1.0.0",
            content=text,
            effective_date=datetime.now(timezone.utc),
        )

        assert request.document_id == "test-xlsx-001"
        assert request.title == "Security Controls"
        assert len(request.content) >= 100
        assert "DB-001" in request.content

# ── Section-length regression ─────────────────────────────────────────


def make_long_header_xlsx() -> bytes:
    """Build an XLSX whose first data row starts with ``# `` and has a long body.

    This reproduces the bug where a worksheet header cell like
    ``# PostgreSQL CIS Benchmark v1.0.0`` causes the extractor to produce
    lines such as::

        # PostgreSQL CIS Benchmark v1.0.0: Enable detailed query logging …

    The chunker then treats the entire rest of the line as a section header,
    producing section values that exceed ``VARCHAR(255)`` and fail the INSERT.
    """
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = "Benchmarks"
    ws.append(["# PostgreSQL CIS Benchmark v1.0.0"])
    ws.append(["Section 1: Installation and Configuration"])
    ws.append([
        "Enable detailed query logging for audit trail purposes on the "
        "PostgreSQL database server instance configured to capture all "
        "connection attempts and SQL queries executed by user roles across "
        "all databases in the production environment with strict compliance "
        "requirements for financial institutions operating in multi-tenant "
        "cloud environments with shared infrastructure and regulatory "
        "oversight bodies requiring comprehensive audit capabilities"
    ])
    buf = io.BytesIO()
    wb.save(buf)
    wb.close()
    buf.seek(0)
    return buf.getvalue()


class TestChunkSectionBounded:
    """Regression tests: chunk section values must never exceed 255 chars."""

    def test_xlsx_with_long_hash_header_section_is_bounded(self):
        """XLSX containing a long ``# `` header line must not produce a
        ``section`` value longer than 255 characters.

        This is a regression test for the ``VARCHAR(255)`` insertion failure
        where pasted CIS-benchmark-style content in an XLSX header cell
        produced lines like::

            # PostgreSQL CIS Benchmark v1.0.0: Enable detailed query logging …

        and the chunker used the entire rest of the line as ``section``.
        """
        from app.xlsx_extractor import extract_xlsx_to_text
        from services.rag.rag_service import RAGService, KnowledgeDocument

        xlsx_bytes = make_long_header_xlsx()
        text = extract_xlsx_to_text(xlsx_bytes)

        # Verify the extracted text does contain a ``#``-prefixed line
        # that would trigger the old bug.
        lines = text.split("\n")
        assert any(
            line.startswith("# ") and len(line) > 260 for line in lines
        ), "Test setup: extracted text must contain a >260-char # line"

        doc = KnowledgeDocument(
            document_id="regression-xlsx-long-header",
            title="Benchmarks",
            version="1.0.0",
            content=text,
            effective_date=datetime.now(timezone.utc),
            status="draft",
        )

        chunks = RAGService()._chunk_document(doc)

        assert len(chunks) > 0, "Expected at least one chunk"

        for i, chunk in enumerate(chunks):
            assert len(chunk.section) <= 255, (
                f"Chunk {i} section is {len(chunk.section)} chars "
                f"(exceeds VARCHAR(255)): {chunk.section[:60]}..."
            )

    def test_direct_300_char_section_header_is_clamped(self):
        """A document with a direct 300-char ``#`` header must clamp to 255."""
        from services.rag.rag_service import RAGService, KnowledgeDocument

        content = f"{'#' + 'X' * 300}\\nBody text\\n"
        doc = KnowledgeDocument(
            document_id="regression-300-char-header",
            title="Test",
            version="1.0.0",
            content=content,
            effective_date=datetime.now(timezone.utc),
            status="draft",
        )

        chunks = RAGService()._chunk_document(doc)
        assert len(chunks) > 0

        for i, chunk in enumerate(chunks):
            assert len(chunk.section) <= 255, (
                f"Chunk {i} section is {len(chunk.section)} chars (should be clamped)"
            )

    def test_split_oversized_chunk_section_stays_within_255(self):
        """When an oversized chunk is split, the ``(cont.)`` suffix must
        not push the section beyond 255 characters."""
        from services.rag.rag_service import RAGService, KnowledgeChunk

        long_section = "Y" * 255
        long_content = "Z" * 5000

        chunk = KnowledgeChunk(
            document_id="regression-split",
            section=long_section,
            content=long_content,
            chunk_hash="abc",
            chunk_index=0,
            postgresql_versions=["15"],
            environment_applicability=["all"],
            source_document_title="Test",
            source_document_version="1.0",
        )

        sub_chunks = RAGService()._split_oversized_chunk(chunk)

        assert len(sub_chunks) > 1, "Expected at least 2 sub-chunks from 5000-char content"

        for i, sc in enumerate(sub_chunks):
            assert len(sc.section) <= 255, (
                f"Split chunk {i} section is {len(sc.section)} chars (with '(cont.)')"
            )
            if i > 0:
                assert sc.section.endswith(" (cont.)"), (
                    f"Split chunk {i} section should end with '(cont.)'"
                )

    def test_long_xlsx_content_preserved_in_chunk_text(self):
        """The full long spreadsheet text must remain in the chunk ``content``
        (``TEXT`` column) even though ``section`` is bounded."""
        from app.xlsx_extractor import extract_xlsx_to_text
        from services.rag.rag_service import RAGService, KnowledgeDocument

        xlsx_bytes = make_long_header_xlsx()
        text = extract_xlsx_to_text(xlsx_bytes)

        doc = KnowledgeDocument(
            document_id="regression-preserve-content",
            title="Benchmarks",
            version="1.0.0",
            content=text,
            effective_date=datetime.now(timezone.utc),
            status="draft",
        )

        chunks = RAGService()._chunk_document(doc)
        combined_content = "".join(c.content for c in chunks)

        # The long description line should still be fully present
        assert "Enable detailed query logging for audit trail purposes" in combined_content
        assert "shared infrastructure" in combined_content
        assert "regulatory oversight bodies" in combined_content

    def test_large_xlsx_stays_under_max_chunks(self):
        """A representative 800-row CIS-style workbook (with pruned columns
        omitted) must produce fewer than MAX_CHUNKS so no content is
        silently truncated.

        This is a regression test for the ``value too long`` /
        ``exceeds MAX_CHUNKS`` errors that occurred when the XLSX
        extractor produced ~1680-char tab-joined lines, inflating the
        chunk count past 1000.

        The test deliberately omits CIS-safeguards/IG/control-reference
        columns that would be pruned by the extractor, matching the
        real CIS workbook shape.
        """
        from app.xlsx_extractor import extract_xlsx_to_text
        from services.rag.rag_service import RAGService, KnowledgeDocument

        # Build an 800-row workbook — only the columns the extractor keeps
        wb = Workbook()
        ws = wb.active
        ws.title = "Controls"
        ws.append([
            "Section #", "Recommendation #", "Title", "Severity",
            "Description", "Rationale Statement", "Remediation Procedure",
            "Audit Procedure", "Impact Statement",
        ])
        for i in range(2, 602):
            ws.append([
                str(i - 1),
                f"4.{i-1:03d}",
                f"Ensure security control {i-1} is enabled",
                "High" if i % 3 == 0 else "Medium" if i % 2 == 0 else "Low",
                f"This control ensures measure {i-1} is configured. " * 2,
                f"Without this control the system may be vulnerable. " * 2,
                f"Execute:\n```\n# echo 'setting={i-1}' >> /etc/config\n# systemctl restart app\n```\nApply and verify.",
                f"Run: ```\n# whoami\n# psql -c 'SELECT * FROM controls WHERE id={i-1}'\n```\nVerify output.",
                f"Performance impact: negligible for control {i-1}",
            ])

        buf = io.BytesIO()
        wb.save(buf)
        xlsx_bytes = buf.getvalue()

        text = extract_xlsx_to_text(xlsx_bytes)
        doc = KnowledgeDocument(
            document_id="regression-large-xlsx",
            title="Synthetic CIS Controls",
            version="1.0",
            content=text,
            effective_date=datetime.now(timezone.utc),
            status="draft",
        )

        chunks = RAGService()._chunk_document(doc)

        assert len(chunks) < 1000, (
            f"Chunk count {len(chunks)} exceeds MAX_CHUNKS (1000); "
            f"content was silently truncated"
        )
        # All fields should be represented in the chunks
        all_text = " ".join(c.content for c in chunks)
        assert "Section #" in all_text
        assert "Remediation Procedure" in all_text
        assert "Audit Procedure" in all_text
