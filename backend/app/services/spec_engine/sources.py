"""Where a collected setting value comes from (pg_settings.source).

Checks read SHOW / current_setting() in the collector's own session. A value set
per role, per database or for the session (ALTER ROLE ... SET, ALTER DATABASE ...
SET, ALTER ROLE ... IN DATABASE ... SET, ALTER ROLE ALL SET, connection options,
SET) is what the collector's session sees, not necessarily what the server and
other sessions use, and a server-wide fix would not change it. Such a reading is
never PASS or FAIL: the finding is NOT_COLLECTED (sandbox: GAPPED) with the
explanation code ``session_override``.

PostgreSQL 17 source names (guc.c GucSource_Names) and how they are treated:
- server-wide, evaluated normally: default, environment variable,
  configuration file, command line, override (set internally by the server,
  e.g. data_directory or config_file);
- per role/database/session, GAPPED: global (ALTER ROLE ALL SET), database,
  user, database user, client, session; and interactive or test, which should
  never appear in pg_settings;
- anything else, including an empty or non-string source, is unknown and GAPPED.

A settings row without a ``source`` key, a missing row and a missing settings
section keep the existing behaviour (the caller's own evidence rules decide).
"""
from __future__ import annotations

from typing import Any

SERVER_WIDE_SOURCES = frozenset({
    "default", "environment variable", "configuration file", "command line", "override",
})

# Settings the collector sets in its own session (collector/collect.sql: SET search_path,
# SET standard_conforming_strings). Their collected value is the collector's own, so no
# spec may check them or use them as an applies_when condition (validate.py).
COLLECTOR_PINNED_SETTINGS = frozenset({"search_path", "standard_conforming_strings"})


def session_override(settings: Any, name: str) -> dict[str, Any] | None:
    """{setting_name, source} if the row for ``name`` has a non-server-wide source, else None."""
    if not isinstance(settings, list):
        return None
    row = next((r for r in settings if isinstance(r, dict) and r.get("name") == name), None)
    if row is None or "source" not in row:
        return None
    source = row["source"]
    if isinstance(source, str) and source in SERVER_WIDE_SOURCES:
        return None
    return {"setting_name": name, "source": source if isinstance(source, str) else None}
