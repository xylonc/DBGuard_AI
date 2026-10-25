# Unified DBGuardAI frontend

For the complete live demo, follow [the repository demo guide](../docs/LOCAL_DEMO.md) and use `python3 scripts/demo.py up` from the repository root. Do not start this frontend alone when testing the full workflow.

For frontend-only development with already-running services:

```sh
npm ci
npm run typecheck
npm test
npm run build
npm start
```

`server.mjs` serves the build and proxies the existing API endpoints; HERMES authentication stays on the server. Set `DBGUARD_API_URL`, `DBGUARD_DEMO_URL`, `HERMES_API_URL`, and `HERMES_API_SERVER_KEY` in the server environment. Never put credentials in `VITE_` variables.

- `src/store/liveStore.tsx`: shared live workflow/chat state and result retrieval.
- `src/live/LiveUI.tsx`: guided workflow and live chat.
- `src/live/EndpointPanel.tsx`: advanced forms for all supplied OpenAPI operations.
- `src/adapters/live.ts`: response normalization and identity/freshness checks.
- `tests/`: transport and contract checks.

Prototype mode remains explicitly separate from live execution. `VERIFICATION.md` documents the original UI integration checks; the repository's `DEMO_PACKAGE_VERIFICATION.md` documents the packaged startup.
