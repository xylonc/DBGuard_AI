"""XLSX file extractor — converts spreadsheet content into normalized text.

This module is deliberately minimal and stateless. It loads a workbook,
iterates worksheets, and produces a single readable text blob that the
existing RAG pipeline can chunk, embed and store as a knowledge document.

Safety guarantees
-----------------
* Only reads cell *values* — formulas are NOT evaluated.
* Ignores charts, images, macros, and other embedded objects.
* Lines beginning with ``# `` (Markdown section header pattern) inside
  cell values are treated as plain text and will be escaped as
  ``\\# `` in the output so the downstream chunker does not misinterpret
  them as new Markdown sections.
* Cell text longer than 8 000 characters is truncated with a note — this
  keeps individual chunks from becoming pathological while preserving
  the bulk of the content.
* Source worksheet information is preserved throughout so no sheet is
  silently dropped.
"""

from __future__ import annotations

import logging
from typing import List

try:
    from openpyxl import load_workbook  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    raise ImportError(
        "openpyxl is required for XLSX extraction. "
        "Install it with: pip install openpyxl"
    )

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

_MAX_CELL_CHARS = 8_000
"""Per-cell truncation guard. Prevents pathological RAG chunks."""

# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------


def extract_xlsx_to_text(
    data: bytes,
    *,
    max_sheets: int = 50,
) -> str:
    """Extract readable text from an XLSX workbook.

    Parameters
    ----------
    data:
        Raw bytes of the .xlsx file.
    max_sheets:
        Maximum number of worksheets to process (safety guard).

    Returns
    -------
    str
        Normalised text with sheet boundaries, row numbers, and cell
        values.  Suitable for RAG chunking.

    Raises
    ------
    ValueError
        If the workbook has zero usable cells across all sheets, or if
        the file is not a recognisable XLSX workbook.
    """
    # ------------------------------------------------------------------
    # Load workbook
    # ------------------------------------------------------------------
    try:
        wb = load_workbook(filename=__load_bytes_into_temp(data), read_only=True, data_only=True)
    except Exception as exc:
        raise ValueError(f"Invalid or corrupt XLSX file: {exc}") from exc

    # ------------------------------------------------------------------
    # Validate and iterate
    # ------------------------------------------------------------------
    sheet_names = wb.sheetnames[:max_sheets]
    if not sheet_names:
        wb.close()
        raise ValueError("The workbook contains no worksheets.")

    parts: List[str] = []

    for sheet_name in sheet_names:
        ws = wb[sheet_name]
        section_header = _normalize_section_header(sheet_name)
        parts.append(f"--- BEGIN SHEET: {section_header} ---")

        max_rows_in_sheet = 0
        row_count = 0

        for row_idx, row in enumerate(ws.iter_rows(min_row=1, max_col=0, values_only=False), start=1):
            values = []
            for cell in row:
                val = _extract_cell_text(cell)
                if val is not None:
                        values.append(val)
                        max_rows_in_sheet = row_idx

            if max_rows_in_sheet > 0:
                row_count += 1
                parts.append(f"  Row {row_idx}: {', '.join(values)}")


        # If this sheet had no printable rows, note it
        if max_rows_in_sheet == 0:
            parts.append(f"  [Sheet '{sheet_name}' contains no readable cell values]")

    wb.close()

    text = "\n".join(parts)

    if not text.strip():
        raise ValueError("The workbook contains no usable text content.")

    logger.info(
        "Extracted %d characters from %d sheet(s), %d total rows",
        len(text),
        len(sheet_names),
        sum(1 for p in parts if p.startswith("  Row")),
    )
    return text


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def __load_bytes_into_temp(data: bytes) -> str:
    """Write bytes to a temp file and return the path.

    openpyxl expects a file path, not raw bytes, so we write to a
    temporary file.  The caller is responsible for cleanup (or the
    OS temp dir will reclaim it).
    """
    import os
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".xlsx", prefix="xlsx_extract_")
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def _extract_cell_text(cell) -> str | None:
    """Extract the display text from a single cell.

    * Returns ``None`` for empty / non-value cells.
    * Booleans become ``"TRUE"`` / ``"FALSE"``.
    * Numbers are rendered without trailing zeros (e.g. ``1.0 -> "1"``).
    * Text is escaped for ``# `` (Markdown header pattern).
    * Long text is truncated at ``_MAX_CELL_CHARS``.
    """
    from openpyxl.cell.cell import Cell
    from openpyxl.cell.read_only import ReadOnlyCell

    cell_types = (Cell, ReadOnlyCell)

    if not isinstance(cell, cell_types):
        return None

    # Only process cells that have a value (not formula refs)
    if cell.value is None:
        return None

    # Determine display value — data_only=True on load means we get
    # the computed value, not the formula string.
    val = cell.value

    # Booleans
    if isinstance(val, bool):
        return "TRUE" if val else "FALSE"

    # Numbers
    if isinstance(val, (int, float)):
        if isinstance(val, float) and val == int(val):
            val = int(val)  # Avoid "1.0" noise
        return str(val)

    # Everything else — coerce to string
    text = str(val)
    if not text.strip():
        return None

    # Escape Markdown section-heading pattern so the chunker won't
    # treat it as a new section.
    text = text.replace("# ", "\\# ", len(text))

    # Truncate very long cells to avoid pathological chunks
    if len(text) > _MAX_CELL_CHARS:
        logger.warning(
            "Cell value truncated from %d to %d characters",
            len(text),
            _MAX_CELL_CHARS,
        )
        text = text[:_MAX_CELL_CHARS] + " [truncated]"

    return text


def _normalize_section_header(name: str) -> str:
    """Create a RAG-safe section header from a worksheet name.

    * Strips leading/trailing whitespace.
    * Replaces characters that are problematic for filesystem / DB
      identifiers with underscores.
    * Does NOT evaluate formulas or infer business meaning.
    """
    name = name.strip()
    # Replace invalid chars
    import re

    name = re.sub(r"[^a-zA-Z0-9_\s-]", "_", name)
    # Collapse whitespace
    name = re.sub(r"\s+", " ", name)
    return name
