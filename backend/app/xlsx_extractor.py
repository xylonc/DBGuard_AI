"""XLSX file extractor — converts spreadsheet content into normalized text.

This module is deliberately minimal and stateless. It loads a workbook,
iterates worksheets, and produces a single readable text output. It does NOT:

* Merge cells
* Follow cross-sheet references
* Evaluate formulas
* Handle charts, macros, images, or complex formatting
* Infer business meaning
* Discard or prune source columns

Requirements
------------
* ``openpyxl`` (for reading ``.xlsx`` files)
"""

from __future__ import annotations

import io
import re
from datetime import date, datetime
from typing import List, Optional

try:
    from openpyxl import load_workbook  # type: ignore
except ImportError:
    raise ImportError(
        "openpyxl is required for XLSX ingestion. Install it with: pip install openpyxl"
    )

# RAG chunker uses CHUNK_SIZE=500, CHUNK_OVERLAP=50 → effective 450 chars/chunk.
_LINE_LIMIT = 400
_SEP = "\t"

_SHORT: dict[str, str] = {}

# Columns with short values — emit raw (no prefix).
# Text fields where prefixes add overhead relative to value size.
_SHORT_COLS = frozenset({
    "Section #", "Recommendation #", "Title", "Assessment Status",
    "Default Value", "Profile", "License",
    "CIS Controls",
    "CIS Safeguards 1 (v8)", "CIS Safeguards 2 (v8)", "CIS Safeguards 3 (v8)",
    "CIS Safeguards 1 (v7)", "CIS Safeguards 2 (v7)", "CIS Safeguards 3 (v7)",
    "v8 IG1", "v8 IG2", "v8 IG3",
    "v7 IG1", "v7 IG2", "v7 IG3",
    "References", "Description", "Rationale Statement",
    "Impact Statement", "Additional Information",
})


def _make_short(headers: List[str]) -> None:
    _SHORT.clear()
    for h in headers:
        low = h.lower()
        if low.startswith("cis safeguards 1 (v8)"):
            _SHORT[h] = "S8.1"
        elif low.startswith("cis safeguards 2 (v8)"):
            _SHORT[h] = "S8.2"
        elif low.startswith("cis safeguards 3 (v8)"):
            _SHORT[h] = "S8.3"
        elif low.startswith("cis safeguards 1 (v7)"):
            _SHORT[h] = "S7.1"
        elif low.startswith("cis safeguards 2 (v7)"):
            _SHORT[h] = "S7.2"
        elif low.startswith("cis safeguards 3 (v7)"):
            _SHORT[h] = "S7.3"
        elif low.startswith("cis controls"):
            _SHORT[h] = "CC"
        elif low.startswith("v8 ig1"):
            _SHORT[h] = "IG8.1"
        elif low.startswith("v8 ig2"):
            _SHORT[h] = "IG8.2"
        elif low.startswith("v8 ig3"):
            _SHORT[h] = "IG8.3"
        elif low.startswith("v7 ig1"):
            _SHORT[h] = "IG7.1"
        elif low.startswith("v7 ig2"):
            _SHORT[h] = "IG7.2"
        elif low.startswith("v7 ig3"):
            _SHORT[h] = "IG7.3"
        elif low.startswith("default"):
            _SHORT[h] = "Def"
        elif low.startswith("references"):
            _SHORT[h] = "Refs"
        elif low.startswith("section"):
            _SHORT[h] = "Sec"
        elif low.startswith("recommendation"):
            _SHORT[h] = "Rec"
        elif low.startswith("title"):
            _SHORT[h] = "Title"
        elif low.startswith("assessment"):
            _SHORT[h] = "Status"
        elif low.startswith("description"):
            _SHORT[h] = "Desc"
        elif low.startswith("rationale"):
            _SHORT[h] = "Ration"
        elif low.startswith("impact"):
            _SHORT[h] = "Impact"
        elif low.startswith("remediation"):
            _SHORT[h] = "Remed"
        elif low.startswith("audit"):
            _SHORT[h] = "Audit"
        elif low.startswith("additional"):
            _SHORT[h] = "Info"
        else:
            _SHORT[h] = h[:14] if h else "c"


def _guard_cell(val: str) -> str:
    """Prepend a space to ``# `` lines so the RAG chunker does not
    treat them as Markdown section headers (``^(#{1,3})\\s+(.+)$``).

    Example: ``# psql`` → `` # psql`` (space inserted before #,
    the space after # is preserved).
    """
    return re.sub(r"(^|\n)# ", r"\1 # ", val)


def extract_xlsx_to_text(file_bytes: bytes) -> str:
    """Load an ``.xlsx`` workbook and convert to normalized text.

    Output format per sheet::

        -- Sheet: Level 1 - PostgreSQL
        -- Cols: Section #, Recommendation #, Title, ...
        1\t1.1\tEnsure login password ... \tManual\tHIGH\tControl 7.1\tN/A
        \tRemed\tExamine the installed packages ...
        \tAudit\tOn Debian one can use ...

    Short columns (IDs, statuses, CIS mappings, refs, description)
    are raw. Long columns (procedures) get ``Col:`` prefixes.
    All non-empty source cells preserved. No columns pruned.
    """
    global _SHORT

    wb = load_workbook(
        filename=io.BytesIO(file_bytes), read_only=True, data_only=True
    )
    parts: List[str] = []

    for ws in wb.worksheets:
        rows: List[List] = list(ws.iter_rows())
        if not rows:
            continue

        hdr_idx: Optional[int] = None
        hdr_names: List[str] = []
        for i, row in enumerate(rows):
            if any(cell.value is not None for cell in row):
                hdr_idx = i
                hdr_names = [str(cell.value or "") for cell in row]
                break

        if hdr_idx is None:
            continue

        _make_short(hdr_names)
        s_hdrs = [_SHORT.get(h, h[:14]) for h in hdr_names]

        sheet_line = f"-- Sheet: {ws.title}"
        col_line = f"-- Cols: {', '.join(hdr_names)}"

        row_parts: List[str] = [sheet_line, col_line]

        for row in rows[hdr_idx + 1 :]:
            values = [cell.value for cell in row]
            if all(v is None for v in values):
                continue

            segments: List[str] = []
            for ci, val in enumerate(values):
                if val is None:
                    continue
                raw = str(val)
                if isinstance(val, datetime):
                    raw = val.strftime("%Y-%m-%d %H:%M:%S")
                elif isinstance(val, date):
                    raw = val.strftime("%Y-%m-%d")
                raw = _guard_cell(raw)
                col = hdr_names[ci] if ci < len(hdr_names) else f"col_{ci}"
                is_short_col = col in _SHORT_COLS

                if is_short_col or len(raw) <= 20:
                    segments.append(raw)
                else:
                    s_hdr = s_hdrs[ci] if ci < len(s_hdrs) else f"c{ci}"
                    segments.append(f"{s_hdr}: {raw}")

            row_line = _SEP.join(segments)

            if len(row_line) > _LINE_LIMIT:
                row_parts.extend(_wrap_tab(row_line, _LINE_LIMIT))
            else:
                row_parts.append(row_line)

        if row_parts:
            parts.append("\n".join(row_parts))

    wb.close()
    text = "\n\n".join(parts)
    if not text or len(text.strip()) < 100:
        raise ValueError(
            "Extracted content too short (<100 chars); workbook may be empty"
        )
    return text


def _wrap_tab(line: str, limit: int) -> List[str]:
    """Wrap at tab boundaries."""
    segs = line.split("\t")
    if not segs:
        return []
    parts: List[str] = []
    current = segs[0]
    for seg in segs[1:]:
        test = current + "\t" + seg
        if len(test) <= limit:
            current = test
        else:
            parts.append(current)
            if len(seg) > limit:
                words = seg.split()
                acc = words[0]
                for w in words[1:]:
                    if len(acc + " " + w) > limit:
                        parts.append(acc)
                        acc = w
                    else:
                        acc += " " + w
                parts.append(acc)
                current = ""
            else:
                current = seg
    if current:
        parts.append(current)
    return parts
