"""XLSX file extractor — converts spreadsheet content into normalized text.

This module is deliberately minimal and stateless. It loads a workbook,
iterates worksheets, and produces a single readable text output. It does NOT:

* Merge cells
* Follow cross-sheet references
* Evaluate formulas
* Handle charts, macros, images, or complex formatting
* Infer business meaning

Requirements
------------
* ``openpyxl`` (for reading ``.xlsx`` files)
"""

from __future__ import annotations

import io
import re
from datetime import date, datetime
from textwrap import wrap
from typing import Dict, List, Optional

try:
    from openpyxl import load_workbook  # type: ignore
except ImportError:
    raise ImportError(
        "openpyxl is required for XLSX ingestion. Install it with: pip install openpyxl"
    )

# The RAG chunker splits on CHUNK_SIZE (500 chars). Each output line
# should ideally stay well under this to avoid unnecessary splits.
# We use 450 to leave room for the "Header: " prefix.
_MAX_LINE_LEN = 450

# Columns deemed low-value for retrieval and high-volume for text
# (they bloat the normalized output without adding semantic content).
# Matched case-insensitively via startswith against header names.
_LOW_VALUE_COLUMNS = {
    # CIS-specific columns that are structured metadata, not prose
    "cis controls",
    "cis safeguards",
    "cis safeguards 1",
    "cis safeguards 2",
    "cis safeguards 3",
    "cis profile",
    # IG1/IG2/IG3 level groupings — single letters
    "ig1",
    "ig2",
    "ig3",
    # Metadata that is not useful for retrieval
    "profile",
    "references",
    "default value",
}


def extract_xlsx_to_text(
    file_bytes: bytes,
) -> str:
    """Load an ``.xlsx`` workbook and convert its content to normalized text.

    Returns a single string where each worksheet is separated by a blank
    line and each data row is rendered as one field-per-line block:

        Sheet: Name
        Control ID: 4.001
        Requirement: Ensure PostgreSQL is configured ...
        Rationale: PostgreSQL must enforce authorized ...

    Only semantically meaningful columns are emitted. Columns whose names
    match known metadata patterns (CIS safeguards, profile mappings,
    CIS Controls references, IG groupings, etc.) are pruned.

    Long cell values are wrapped so that the RAG chunker can group
    several lines into one chunk without splitting mid-line.  Lines
    that start with ``# `` (bash commands inside code blocks, etc.)
    are indented with a leading space so the RAG chunker's section-
    header regex ``^(#{1,3})\\s+(.+)$`` does not mistake them for
    Markdown/YAML section headers.
    """

    wb = load_workbook(filename=io.BytesIO(file_bytes), read_only=True, data_only=True)

    parts: List[str] = []

    for ws in wb.worksheets:
        section_lines: List[str] = [f"Sheet: {ws.title}"]

        rows_as_list: List[List] = list(ws.iter_rows())

        if not rows_as_list:
            continue

        # Find the header row.
        header_row_idx: Optional[int] = None
        header_names: List[str] = []

        for idx, row in enumerate(rows_as_list):
            non_empty = [cell.value for cell in row if cell.value is not None]
            if non_empty:
                header_row_idx = idx
                header_names = [str(cell.value or "") for cell in row]
                break

        if header_row_idx is None:
            continue

        # Determine which columns to prune (heuristic patterns from config).
        low_value_set = _LOW_VALUE_COLUMNS

        # Render data rows.
        for row in rows_as_list[header_row_idx + 1 :]:
            values = [cell.value for cell in row]
            if all(v is None for v in values):
                continue

            row_parts: List[str] = []

            for col_idx, val in enumerate(values):
                if val is None:
                    continue
                if col_idx < len(header_names):
                    header = header_names[col_idx]
                else:
                    header = f"column_{col_idx}"

                header_lower = header.lower()
                # Prune low-value columns (prefix match).
                if any(header_lower.startswith(prefix) for prefix in low_value_set):
                    continue
                # Prune IG level groupings like "v8 IG1", "v7 IG2", etc.
                if "ig" in header_lower:
                    continue

                # Format the value.
                if isinstance(val, datetime):
                    formatted = val.strftime("%Y-%m-%d %H:%M:%S")
                elif isinstance(val, date):
                    formatted = val.strftime("%Y-%m-%d")
                else:
                    formatted = str(val)

                prefix = f"{header}: "
                value_text = formatted

                # Escape ``# `` lines inside the value to prevent the
                # RAG chunker from treating bash comments as section headers.
                if "\n#" in value_text or value_text.startswith("# "):
                    value_text = re.sub(r"^\n# ", "\n #", value_text)
                    value_text = re.sub(r"\n#", "\n #", value_text)

                # Wrap long values.
                if len(prefix) + len(value_text) > _MAX_LINE_LEN:
                    wrapped = wrap(value_text, width=_MAX_LINE_LEN - len(prefix))
                    # Guard any wrapped line that starts with ``# ``.
                    for w in wrapped:
                        if w.startswith("# "):
                            w = " " + w
                        row_parts.append(f"{prefix}{w}")
                else:
                    row_parts.append(f"{prefix}{value_text}")

            if row_parts:
                section_lines.append("\n".join(row_parts))

        if len(section_lines) > 1:
            parts.append("\n".join(section_lines))

    wb.close()

    text = "\n\n".join(parts)

    if not text or len(text.strip()) < 100:
        raise ValueError(
            "Extracted content too short (<100 chars); workbook may be empty"
        )

    return text
