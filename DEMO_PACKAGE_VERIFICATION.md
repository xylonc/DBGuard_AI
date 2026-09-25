# Packaged demo verification — 25 September 2026

Base: reviewed integration commit `ad36874078538cd66ef68bebc69a996c609b2b05`.
Host tested: macOS, Python 3.14, Node 24, Docker Desktop. Linux/WSL2 are documented but not tested here.

## Completed checks

- A new isolated checkout installed a fresh `.venv-demo` from `requirements-demo.lock`, ran `npm ci`, type-checked and built the UI. No existing Python environment or frontend node_modules was copied into it.
- `python3 scripts/demo.py up` started the demo API, MCP, newly built HERMES container, separate embedding service/model, Main API with disposable Library registry, and UI gateway on an unused port group.
- Readiness completed only after the real embedding request and all API health checks succeeded.
- `python3 scripts/verify_demo.py` called the new HERMES instance through the UI gateway. It produced run `d15a2f79-0f80-448d-9da1-8877bc1ab5a4`, status VERIFIED. Checks passed for exact rollback, post-apply/post-rollback health, no regressions, sandbox cleanup, unchanged source/registry, a matching chat run ID, and ZIP integrity/required files.
- `python3 scripts/demo.py down` completed. No containers remained with that launch's `dbguard.demo.owner` label or Compose project label. Downloaded-model and HERMES conversation volumes were intentionally retained as documented caches.
- The original UI on port 8443 and its Main API, demo and HERMES services stayed available after this isolated shutdown.
- A second startup reached READY using retained caches. Its shutdown completed with no owned or Compose containers remaining.
- 8 launcher/HERMES configuration checks passed, including occupied-port rejection, exact-owner cleanup, refusal of wildcard cleanup, and environment isolation.
- 59 existing sandbox/demo/API/adaptive unit checks passed after the ownership-label and image-selection changes.
- 6 frontend contract/gateway checks passed.

## Boundaries

This is local POC packaging, not production deployment. The real model call used the configured account. No live adaptive failure/revision occurred because the sandbox passed on its first attempt. No production database was changed. No team approval was fabricated. Automatic workbook-to-spec generation and Main API chat routing are still outside this demo path.

Private configuration, logs, runtime state, Python environments, node_modules and generated builds are excluded from Git and the source archive. Runtime IDs expire across new disposable sessions.
