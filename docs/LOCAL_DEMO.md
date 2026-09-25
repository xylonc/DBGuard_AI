# Launch the unified live demo

Supported hosts: macOS and Linux. Windows users can use WSL2 with Docker integration; native Windows is not supported by the host launcher. The fresh-start verification was performed on macOS with Python 3.14 and Node 24. Cross-platform instructions are not a claim that Linux/WSL2 were tested.

Install **Python 3.12+**, **Node.js 24+ with npm**, and **Docker with Docker Compose**. Start Docker before proceeding. Reserve enough Docker memory for HERMES, three PostgreSQL instances during a test, and CPU embeddings (8 GB is a reasonable starting allocation). First launch downloads dependencies, images and the embedding model.

From the repository root:

```sh
cp .env.demo.example .env.demo
```

Edit `.env.demo` and set **your own** `OLLAMA_API_KEY`. It is ignored by Git. Do not use another teammate's credentials or put them in frontend files.

```sh
python3 scripts/demo.py up
```

Keep that terminal open. When it prints **READY**, open **http://127.0.0.1:8443**. No separate frontend, backend, MCP or HERMES launch commands are required. The launcher creates its own Python environment, installs locked dependencies, builds the UI, and starts the services in order.

If a port is already in use, set another `DEMO_BASE_PORT` in `.env.demo`. The launcher reserves that port and the next six; it never stops an existing service to take its port.

## Demo sequence

1. **Home → Load live demo** loads a real snapshot collected from a disposable PostgreSQL 17 source.
2. Review the six installed controls. The sample is intentionally not fully compliant.
3. Open **HERMES** and click **Run disposable sandbox through HERMES**. Alternatively use the guided Sandbox test button.
4. Wait for the recorded result, then open **DBA review**. Match its run ID to chat. Inspect the before/after controls, rollback and cleanup evidence.
5. Download the ZIP containing `harden.sh`, `report.html`, and evidence.
6. **Verify target → Recollect unchanged demo source** confirms that sandbox testing did not change the source.
7. **Library** connects to a separate disposable registry with real local embeddings. Documents/templates are drafts until deliberately reviewed and approved. An empty approved-content search on a fresh installation is expected.

The UI never applies the bundle to a real target. Do not use DBGuard's pgvector knowledge store as a sandbox target.

## Optional end-to-end check

With the package running, `python3 scripts/verify_demo.py` requests a **new** disposable test through live HERMES and validates the recorded run, rollback, cleanup and ZIP. This uses the configured model account. Results stay in ignored `.demo/verification.json`.

## Stop and inspect

Use Ctrl+C in the launch terminal, or from another terminal in the same checkout:

```sh
python3 scripts/demo.py status
python3 scripts/demo.py down
```

Shutdown stops only this launcher's host processes and Compose project. It removes its run-labelled source, registry and sandbox containers. Normal shutdown retains this checkout's Compose volumes for the downloaded embedding model and HERMES conversations, so the next launch need not download the model again. These caches can contain conversation data and runtime credentials. They are not copied into Git or a source ZIP.

The Library registry, snapshots and prepared handoff IDs are disposable. On a fresh launch, load the new demo rather than reusing an old snapshot ID or bundle link. If startup fails, the same cleanup runs automatically. Logs and non-secret status are in `.demo/`, which is ignored by Git and created with private directory permissions.

A forced operating-system kill or unavailable Docker daemon can prevent graceful cleanup. The launcher reports cleanup failure; inspect `.demo/state.json` rather than running global Docker prune commands. Normal stop never signals a PID read from a stale file or removes another demo's containers.

## How services connect

| Offset from DEMO_BASE_PORT | Service | Binding |
| --- | --- | --- |
| +0 | Unified UI and server-side gateway | localhost |
| +1 | Disposable demo API | localhost |
| +2 | Main API and separate Library registry | localhost |
| +3 | HERMES API | localhost |
| +4 | Optional HERMES dashboard | localhost |
| +5 | Restricted MCP bridge | DEMO_MCP_BIND; default all interfaces for Docker host-gateway access |
| +6 | Local embedding service | localhost |

HERMES receives no Docker socket. Only host-side sandbox services can create the labelled disposable containers. The MCP bridge exposes the existing restricted tools and needs to be reachable from the HERMES container. This is a local POC: do not expose its ports to public networks. Browser calls go through the local gateway; the HERMES API key stays server-side. The packaged UI does not require a separate HERMES dashboard login.

## Scope and honest limits

- The demo uses **DEMO_FIXTURE_ONLY** approval records, not team approval or genuine approved-content RAG retrieval.
- The sandbox milestone fixes `log_connections`; it does not fix every failed control.
- An attempt can pass without invoking the LLM reviewer. Adaptive review only follows failure and remains restricted to eligible approved candidates.
- XLSX knowledge upload is connected. Automatic workbook-to-spec generation still needs its upstream endpoint.
- The running HERMES agent is connected to the **demo** backend. Main API snapshot intake/assessment and Library forms work separately. Switching the UI backend alone does not reconfigure the agent's MCP target.
- There is no automatic real-target application, production deployment, durable multi-user history or live per-stage progress stream.
- Local Library approval/bulk routes are available but are not automatically exercised by startup.

See `DEMO_PACKAGE_VERIFICATION.md` for checks actually run, including startup/shutdown results.
