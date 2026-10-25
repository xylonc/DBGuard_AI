"""Screenshot a local evidence viewer of actual database query output.

No model-generated values and no screenshot of a dashboard status badge.
The accompanying JSON is the source; this is not proof of operator authenticity.
"""

import base64
from datetime import datetime, timezone
import hashlib
from html import escape
import json
import subprocess
import sys


def render_html(evidence):
    body = "".join(
        "<section><h2>"
        + escape(check["title"])
        + "</h2><pre>"
        + escape(check["query"])
        + "</pre><pre>"
        + escape(
            json.dumps(check["output"], indent=2, default=str)
            if isinstance(check["output"], (dict, list))
            else str(check["output"])
        )
        + "</pre></section>"
        for check in evidence["queries"]
    )
    metadata = "".join(
        "<dt>"
        + escape(key.replace("_", " ").title())
        + "</dt><dd>"
        + escape(
            json.dumps(value, ensure_ascii=False)
            if isinstance(value, (dict, list))
            else str(value)
        )
        + "</dd>"
        for key, value in evidence.items()
        if key not in ("queries", "scope")
    )
    return (
        '<!doctype html><html><head><meta charset="utf-8"><style>body{font:16px system-ui;padding:32px;color:#152f36;background:#fff}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#edf4f3;padding:16px;font:14px monospace}section{border-top:1px solid #aaa;margin-top:24px}p,dd{overflow-wrap:anywhere}dl{display:grid;grid-template-columns:170px 1fr;gap:8px}dt{font-weight:600}dd{margin:0}</style></head><body><h1>DBGuardAI · Actual database query results</h1><p>'
        + escape(evidence["scope"])
        + "</p><dl>"
        + metadata
        + "</dl>"
        + body
        + "</body></html>"
    )


def capture(evidence):
    # A subprocess is also safe when called from FastAPI's async event loop.
    process = subprocess.run(
        [sys.executable, __file__, "--render"],
        input=json.dumps(evidence),
        text=True,
        capture_output=True,
        timeout=60,
    )
    if process.returncode:
        raise RuntimeError("Evidence browser unavailable; install playwright chromium")
    png = base64.b64decode(process.stdout.strip(), validate=True)
    return {
        "status": "CAPTURED",
        "format": "png",
        "sha256": hashlib.sha256(png).hexdigest(),
        "png_base64": process.stdout.strip(),
        "query_evidence": evidence,
    }


if __name__ == "__main__":
    from playwright.sync_api import sync_playwright

    evidence = json.load(sys.stdin)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(
            viewport={"width": 1100, "height": 800}, device_scale_factor=1
        )
        page.route("**/*", lambda route: route.abort())
        page.set_content(render_html(evidence), wait_until="load")
        print(base64.b64encode(page.screenshot(full_page=True)).decode())
        browser.close()
