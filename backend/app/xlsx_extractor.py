"""XLSX file extractor — converts spreadsheet content into normalized text.

This module is deliberately minimal and stateless. It loads a workbook,
iterates worksheets, and produces a single readable text block that the
existing RAG chunker can ingest.

Supported
---------
* Multiple worksheets (each becomes a "section")
* Header-row detection (first non-empty row becomes column names)
* Plain string / numeric / datetime cell values
* Empty-cell skipping

Not supported (out of scope for the POC)
-----------------------------------------
* Charts, macros, images, complex formatting
* Formula evaluation
* Merged-cell semantics
* Business-meaning inference
"""

from __future__ import annotations

import io
from datetime import date, datetime
from typing import List, Optional

try:
    from openpyxl import load_workbook  # type: ignore
except ImportError:
    raise ImportError(
        "openpyxl is required for XLSX ingestion. Install it with: pip install openpyxl"
    )


# ── Public API ──────────────────────────────────────────────────────────


def extract_xlsx_to_text(
    file_bytes: bytes,
) -> str:
    """Load an ``.xlsx`` workbook and convert its content to normalized text.

    Returns a single string where each worksheet is separated by a blank
    line and each row is rendered as ``Header: Value`` pairs.

    Raises
    ------
    ValueError
        If the workbook contains no usable content.
    """
    wb = load_workbook(filename=io.BytesIO(file_bytes), read_only=True, data_only=True)

    parts: List[str] = []

    for ws in wb.worksheets:
        section_lines: List[str] = [f"Sheet: {ws.title}"]

        # Collect all rows as a list so we can peek at the header.
        # Iterating row_iter directly is memory-efficient.
        rows_as_list: List[List] = list(ws.iter_rows())

        if not rows_as_list:
            continue  # empty sheet

        # Find the header row: first row that has at least one non-empty cell.
        header_row_idx: Optional[int] = None
        header_names: List[str] = []

        for idx, row in enumerate(rows_as_list):
            non_empty = [cell.value for cell in row if cell.value is not None]
            if non_empty:
                header_row_idx = idx
                header_names = [str(cell.value or "") for cell in row]
                break

        if header_row_idx is None:
            continue  # all cells empty

        # Render data rows (starting after the header).
        for row in rows_as_list[header_row_idx + 1 :]:
            values = [cell.value for cell in row]
            if all(v is None for v in values):
                continue  # skip blank rows

            row_parts: List[str] = []
            for col_idx, val in enumerate(values):
                if val is None:
                    continue
                # Determine header for this column.
                if col_idx < len(header_names):
                    header = header_names[col_idx]
                else:
                    # Column index beyond header length — use a generic name.
                    header = f"column_{col_idx}"

                # Format the value nicely.
                if isinstance(val, datetime):
                    formatted = val.strftime("%Y-%m-%d %H:%M:%S")
                elif isinstance(val, date):
                    formatted = val.strftime("%Y-%m-%d")
                else:
                    formatted = str(val)

                row_parts.append(f"{header}: {formatted}")

            if row_parts:
                section_lines.append("\t".join(row_parts))

        if len(section_lines) > 1:  # more than just the sheet name line
            parts.append("\n".join(section_lines))

    wb.close()

    text = "\n\n".join(parts)

    if not text or len(text.strip()) < 100:
        raise ValueError(
            "Extracted content too short (<100 chars); workbook may be empty"
        )

    return text
