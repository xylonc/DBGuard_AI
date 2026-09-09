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
