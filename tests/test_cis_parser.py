"""Tests for CIS workbook parser.

Tests:
  A. Section rows are skipped
  B. Duplicate recommendation raises error
  C. Missing header raises error
  D. Columns found by name when order is shuffled
  E. Backticks, newlines, and surrounding spaces preserved exactly
  F. Two runs produce identical output
  G. Workbook order preserved (non-sorted recommendations)
  H. Rows with Audit Procedure but no Recommendation # raise error
  I. Section row with Section #, Title, Description only -> skipped
  J. Assessment Status "automated" (lowercase) -> rejected
  K. Missing Title on a recommendation row -> rejected

Plus one test on the real workbook (skipped if absent) checking:
  L. IDs are unique, every record has a source_sha256, and source_row is strictly increasing
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from openpyxl import Workbook

# Add scripts to path
SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))
from parse_cis_workbook import WorkbookFormatError, parse_workbook


# ============================================================================
# Helpers
# ============================================================================


def make_test_xlsx(sheet_name: str = "Combined Profiles", headers: list[str] | None = None, rows: list[list[str]] | None = None) -> Path:
    """Create a small XLSX file for testing."""
    wb = Workbook()
    ws = wb.active
    ws.title = sheet_name
    
    # Write headers
    if headers:
        for col, header in enumerate(headers, start=1):
            ws.cell(row=1, column=col, value=header)
    
    # Write data rows
    if rows:
        for row_idx, row_values in enumerate(rows, start=2):
            for col_idx, value in enumerate(row_values, start=1):
                ws.cell(row=row_idx, column=col_idx, value=value)
    
    # Save to temp file
    tmp = Path(TemporaryDirectory().name)
    tmp.mkdir(parents=True, exist_ok=True)
    output = tmp / "test.xlsx"
    wb.save(output)
    return output


def get_records_from_json(json_path: str | Path) -> list[dict]:
    """Load records from a parser output JSON."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["records"]


# ============================================================================
# Tests
# ============================================================================


def test_section_rows_skipped():
    """Section rows (empty Recommendation #) should be skipped.
    
    Uses a synthetic workbook with exactly ONE section row and asserts:
    - No record has a null recommendation
    - record_count is correct (only non-section rows)
    
    Section row has only Section #, Title, Description (no other content).
    """
    headers = ["Recommendation #", "Section #", "Profile", "Title", "Assessment Status", "Description", "Rationale Statement", "Impact Statement", "Remediation Procedure", "Audit Procedure", "Additional Information", "References", "Default Value"]
    # Section row: only Section #, Title, Description are non-empty (all others must be empty)
    rows = [
        ["", "1", None, "General Section", None, None, None, None, None, None, None, None, None],  # section row - skipped (all outside {Section #, Title, Description} are empty)
        ["1.1.1", "1.1", "Level 1 - PostgreSQL", "Test", "Automated", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],  # real row
    ]
    
    xlsx_path = make_test_xlsx(headers=headers, rows=rows)
    with TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "output.json"
        parse_workbook(str(xlsx_path), str(output))
        records = get_records_from_json(output)
        
        # Only 1 real record (section row skipped)
        assert len(records) == 1
        # No null recommendations
        for r in records:
            assert r["recommendation"] is not None
            assert r["recommendation"] != ""
        # Source rows should match input order
        assert records[0]["source_row"] == 3  # Row 3 in the sheet (after header and section row)


def test_duplicate_recommendation_raises():
    """Duplicate recommendation should raise WorkbookFormatError with specific message."""
    headers = ["Recommendation #", "Section #", "Profile", "Title", "Assessment Status", "Description", "Rationale Statement", "Impact Statement", "Remediation Procedure", "Audit Procedure", "Additional Information", "References", "Default Value"]
    rows = [
        ["1.1.1", "1.1", "Level 1 - PostgreSQL", "Test", "Automated", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],
        ["1.1.1", "1.1", "Level 1 - PostgreSQL", "Duplicate", "Automated", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],  # duplicate
    ]
    
    xlsx_path = make_test_xlsx(headers=headers, rows=rows)
    with TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "output.json"
        with pytest.raises(WorkbookFormatError) as exc_info:
            parse_workbook(str(xlsx_path), str(output))
        assert "Duplicate recommendation: 1.1.1" in str(exc_info.value)


def test_missing_header_raises():
    """Missing required header should raise WorkbookFormatError with specific message."""
    # Missing "Recommendation #" header (but has others)
    headers = ["Section #", "Profile", "Title", "Assessment Status", "Description", "Rationale Statement", "Impact Statement", "Remediation Procedure", "Audit Procedure", "Additional Information", "References", "Default Value"]
    rows = [["1.1", "Level 1 - PostgreSQL", "Test", "Automated", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"]]
    
    xlsx_path = make_test_xlsx(headers=headers, rows=rows)
    with TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "output.json"
        with pytest.raises(WorkbookFormatError) as exc_info:
            parse_workbook(str(xlsx_path), str(output))
        assert "Missing required header" in str(exc_info.value)


def test_columns_found_by_name_when_shuffled():
    """Columns should be found by name even when order is shuffled."""
    # Shuffled headers (all 13 required columns)
    headers = ["Title", "Default Value", "Recommendation #", "Assessment Status", "Profile", "Description", "Rationale Statement", "Impact Statement", "Remediation Procedure", "Audit Procedure", "Additional Information", "References", "Section #"]
    rows = [
        ["Test Title", "off", "1.1.1", "Automated", "Level 1 - PostgreSQL", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "1.1"],
    ]
    
    xlsx_path = make_test_xlsx(headers=headers, rows=rows)
    with TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "output.json"
        parse_workbook(str(xlsx_path), str(output))
        records = get_records_from_json(output)
        
        assert len(records) == 1
        assert records[0]["title"] == "Test Title"
        assert records[0]["pg_default_value"] == "off"
        assert records[0]["recommendation"] == "1.1.1"
        assert records[0]["assessment_status"] == "Automated"
        assert records[0]["profile"] == "Level 1 - PostgreSQL"


def test_special_characters_preserved():
    """Backticks, newlines, and surrounding spaces should be preserved exactly."""
    headers = ["Recommendation #", "Section #", "Profile", "Title", "Assessment Status", "Description", "Rationale Statement", "Impact Statement", "Remediation Procedure", "Audit Procedure", "Additional Information", "References", "Default Value"]
    rows = [
        ["1.1.1", "1.1", "Level 1 - PostgreSQL on Linux", "  Title with spaces  ", "Manual", "Description with `backticks` and\nnewlines", "Rat", "Imp", "Rem", "Audit line 1\nAudit line 2", "Add", "Ref", "Def"],
    ]
    
    xlsx_path = make_test_xlsx(headers=headers, rows=rows)
    with TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "output.json"
        parse_workbook(str(xlsx_path), str(output))
        records = get_records_from_json(output)
        
        assert records[0]["title"] == "  Title with spaces  "
        assert records[0]["description"] == "Description with `backticks` and\nnewlines"
        assert records[0]["audit_procedure"] == "Audit line 1\nAudit line 2"
        assert records[0]["recommendation"] == "1.1.1"
        assert records[0]["section"] == "1.1"
        assert records[0]["profile"] == "Level 1 - PostgreSQL on Linux"
        assert records[0]["assessment_status"] == "Manual"


def test_two_runs_identical():
    """Running the parser twice should produce byte-identical output."""
    headers = ["Recommendation #", "Section #", "Profile", "Title", "Assessment Status", "Description", "Rationale Statement", "Impact Statement", "Remediation Procedure", "Audit Procedure", "Additional Information", "References", "Default Value"]
    rows = [
        ["1.1.1", "1.1", "Level 1 - PostgreSQL", "Test", "Automated", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],
        ["1.1.2", "1.1", "Level 1 - PostgreSQL on Linux", "Test2", "Manual", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],
    ]
    
    xlsx_path = make_test_xlsx(headers=headers, rows=rows)
    with TemporaryDirectory() as tmpdir:
        output1 = Path(tmpdir) / "output1.json"
        output2 = Path(tmpdir) / "output2.json"
        
        parse_workbook(str(xlsx_path), str(output1))
        parse_workbook(str(xlsx_path), str(output2))
        
        with open(output1, "rb") as f1, open(output2, "rb") as f2:
            assert f1.read() == f2.read()


def test_workbook_order_preserved():
    """Workbook order is preserved in output - output order must equal workbook order, not numeric order."""
    headers = ["Recommendation #", "Section #", "Profile", "Title", "Assessment Status", "Description", "Rationale Statement", "Impact Statement", "Remediation Procedure", "Audit Procedure", "Additional Information", "References", "Default Value"]
    # Non-sorted order: 2.1, 1.10, 1.2
    rows = [
        ["2.1", "2", "Level 1 - PostgreSQL", "Second", "Automated", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],
        ["1.10", "1", "Level 1 - PostgreSQL on Linux", "Eleventh", "Manual", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],
        ["1.2", "1", "Level 1 - PostgreSQL", "Second", "Automated", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],
    ]
    
    xlsx_path = make_test_xlsx(headers=headers, rows=rows)
    with TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "output.json"
        parse_workbook(str(xlsx_path), str(output))
        records = get_records_from_json(output)
        
        # Output order should match input order (2.1, 1.10, 1.2) - preserved
        assert len(records) == 3
        assert records[0]["recommendation"] == "2.1"
        assert records[0]["source_row"] == 2
        assert records[1]["recommendation"] == "1.10"
        assert records[1]["source_row"] == 3
        assert records[2]["recommendation"] == "1.2"
        assert records[2]["source_row"] == 4


def test_audit_procedure_no_recommendation_raises():
    """Row with Audit Procedure but no Recommendation # should raise WorkbookFormatError."""
    headers = ["Recommendation #", "Section #", "Profile", "Title", "Assessment Status", "Description", "Rationale Statement", "Impact Statement", "Remediation Procedure", "Audit Procedure", "Additional Information", "References", "Default Value"]
    # Section row with Audit Procedure content - should raise error
    rows = [
        ["", "1", "Level 1 - PostgreSQL", "Section Title", "Automated", "Section Desc", "Rat", "Imp", "Rem", "Audit content", "Add", "Ref", "Def"],  # section row with Audit Procedure -> error
        ["1.1.1", "1.1", "Level 1 - PostgreSQL", "Test", "Automated", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],
    ]
    
    xlsx_path = make_test_xlsx(headers=headers, rows=rows)
    with TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "output.json"
        with pytest.raises(WorkbookFormatError) as exc_info:
            parse_workbook(str(xlsx_path), str(output))
        assert "Row 2: recommendation content but no Recommendation #" in str(exc_info.value)


def test_section_row_valid():
    """Section row with only Section #, Title, Description should be skipped."""
    headers = ["Recommendation #", "Section #", "Profile", "Title", "Assessment Status", "Description", "Rationale Statement", "Impact Statement", "Remediation Procedure", "Audit Procedure", "Additional Information", "References", "Default Value"]
    # Valid section row: only Section #, Title, Description are non-empty
    rows = [
        ["", "1", None, "Section Title", None, "Section Desc", None, None, None, None, None, None, None],
        ["1.1.1", "1.1", "Level 1 - PostgreSQL", "Test", "Automated", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],
    ]
    
    xlsx_path = make_test_xlsx(headers=headers, rows=rows)
    with TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "output.json"
        parse_workbook(str(xlsx_path), str(output))
        records = get_records_from_json(output)
        
        # Only 1 real record (section row skipped)
        assert len(records) == 1
        assert records[0]["recommendation"] == "1.1.1"


def test_assessment_status_lowercase_raises():
    """Assessment Status 'automated' (lowercase) should raise WorkbookFormatError."""
    headers = ["Recommendation #", "Section #", "Profile", "Title", "Assessment Status", "Description", "Rationale Statement", "Impact Statement", "Remediation Procedure", "Audit Procedure", "Additional Information", "References", "Default Value"]
    rows = [
        ["1.1.1", "1.1", "Level 1 - PostgreSQL", "Test", "automated", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],  # lowercase -> error
    ]
    
    xlsx_path = make_test_xlsx(headers=headers, rows=rows)
    with TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "output.json"
        with pytest.raises(WorkbookFormatError) as exc_info:
            parse_workbook(str(xlsx_path), str(output))
        assert "Row 2: Assessment Status must be 'Automated' or 'Manual', got 'automated'" in str(exc_info.value)


def test_missing_title_raises():
    """Missing Title on a recommendation row should raise WorkbookFormatError."""
    headers = ["Recommendation #", "Section #", "Profile", "Title", "Assessment Status", "Description", "Rationale Statement", "Impact Statement", "Remediation Procedure", "Audit Procedure", "Additional Information", "References", "Default Value"]
    rows = [
        ["1.1.1", "1.1", "Level 1 - PostgreSQL", None, "Automated", "Desc", "Rat", "Imp", "Rem", "Aud", "Add", "Ref", "Def"],  # missing Title -> error
    ]
    
    xlsx_path = make_test_xlsx(headers=headers, rows=rows)
    with TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "output.json"
        with pytest.raises(WorkbookFormatError) as exc_info:
            parse_workbook(str(xlsx_path), str(output))
        assert "Row 2: missing Title on recommendation row" in str(exc_info.value)


@pytest.mark.skipif(
    not Path(__file__).resolve().parent.parent / "local docs" / "CIS_PostgreSQL_17_Benchmark_v1.1.0.xlsx",
    reason="Real workbook not present",
)
def test_real_workbook():
    """Test on the real workbook: IDs are unique, every record has a source_sha256, source_row is strictly increasing."""
    workbook_path = Path(__file__).resolve().parent.parent / "local docs" / "CIS_PostgreSQL_17_Benchmark_v1.1.0.xlsx"
    
    if not workbook_path.exists():
        pytest.skip("Real workbook not present")
    
    with TemporaryDirectory() as tmpdir:
        output = Path(tmpdir) / "output.json"
        parse_workbook(str(workbook_path), str(output))
        records = get_records_from_json(output)
        
        # Check all recommendations are unique
        recommendations = [r["recommendation"] for r in records]
        assert len(recommendations) == len(set(recommendations)), "Duplicate recommendations found"
        
        # Check every record has source_sha256
        for record in records:
            assert "source_sha256" in record, f"Missing source_sha256 for {record['recommendation']}"
            # Verify SHA-256 format
            sha = record["source_sha256"]
            assert len(sha) == 64, f"Invalid SHA-256 length: {len(sha)}"
            int(sha, 16)  # Verify it's a valid hex string
        
        # Check source_row is strictly increasing
        source_rows = [r["source_row"] for r in records]
        assert source_rows == sorted(source_rows), "source_row values are not in ascending order"
        for i in range(1, len(source_rows)):
            assert source_rows[i] > source_rows[i-1], f"source_row not strictly increasing: {source_rows[i-1]} -> {source_rows[i]}"


def test_script_runs_twice_with_identical_output():
    """Test that running the CLI script twice produces identical output."""
    workbook_path = Path(__file__).resolve().parent.parent / "local docs" / "CIS_PostgreSQL_17_Benchmark_v1.1.0.xlsx"
    
    if not workbook_path.exists():
        pytest.skip("Real workbook not present")
    
    with TemporaryDirectory() as tmpdir:
        output1 = Path(tmpdir) / "output1.json"
        output2 = Path(tmpdir) / "output2.json"
        
        # Run first time
        result1 = subprocess.run(
            [sys.executable, "scripts/parse_cis_workbook.py", "--output", str(output1)],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True,
            text=True,
        )
        assert result1.returncode == 0, f"First run failed: {result1.stderr}"
        
        # Run second time
        result2 = subprocess.run(
            [sys.executable, "scripts/parse_cis_workbook.py", "--output", str(output2)],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True,
            text=True,
        )
        assert result2.returncode == 0, f"Second run failed: {result2.stderr}"
        
        # Compare outputs
        with open(output1, "rb") as f1, open(output2, "rb") as f2:
            content1 = f1.read()
            content2 = f2.read()
            assert content1 == content2, "Two runs produced different output"
