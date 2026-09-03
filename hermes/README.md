# DBGuardAI HERMES package

This directory packages DBGuardAI on top of the official HERMES Agent image.
It provides the natural-language chat experience while keeping all database
and SQL decisions behind DBGuardAI's trusted API.

## Packaging contract

The Dockerfile pins `nousresearch/hermes-agent:v2026.8.31` (HERMES v0.21.0)
by immutable SHA-256 digest. It adds:

- `config/config.yaml`: model, MCP allowlist and disabled toolsets;
- `context/HERMES.md`: non-negotiable DBGuard operating rules;
- `context/SOUL.md`: plain-language assistant identity;
- `skills/dbguard-hardening/SKILL.md`: the complete proposal workflow;
- `configure.py`: creates runtime config and hashes the dashboard password;
- `docker-entrypoint.sh`: seeds the persistent HERMES home, then delegates to
  the official image entrypoint.

HERMES state lives in the `hermes-data` Docker volume at `/opt/data`. Rebuilding
the image therefore preserves conversations, while managed DBGuard config,
context and skill files are refreshed on each start.

## Install and launch

From the repository root:

```sh
docker compose --env-file .env -f deploy/compose.yaml up --build
```

The user does not install HERMES separately. Compose builds the thin DBGuard
wrapper from the pinned official image and starts its gateway plus built-in web
dashboard. Open `http://localhost:9119` and sign in using the dashboard
credentials in `.env`.

## Model requirement

The default config uses Ollama's OpenAI-compatible API at
`http://host.docker.internal:11434/v1` and model `llama3.1`. The dashboard and
gateway can start without Ollama, but chat replies cannot complete until that
model endpoint is available. To use another provider, update the `model`
section of `config/config.yaml` and provide its secret through runtime
environment configuration.

## Controlled tool surface

HERMES connects to `http://mcp:8001/mcp` and is restricted to four operations:

1. read one normalized snapshot;
2. search approved knowledge;
3. search approved SQL templates;
4. compile a proposal through the trusted API.

The MCP server publishes no resources and no prompts. General browser, shell,
file, process, code-execution, delegation, memory, scheduled-job and web
toolsets are disabled. The terminal backend is set to Docker as a second safety
layer, and no Docker socket is mounted.

The model may see HERMES's three deferred-tool facade functions
(`tool_search`, `tool_describe`, `tool_call`) instead of four raw schemas. The
facade's underlying registry contains only the four allowlisted DBGuard tools;
it does not expand the agent's authority.

## User workflow

1. Upload a collector bundle to DBGuardAI and copy its `snapshot_id`.
2. Open the HERMES dashboard and start a chat.
3. Provide the snapshot ID, environment, and requirement in natural language.
4. HERMES reads the snapshot, searches approved evidence and templates, then
   asks the backend to compile the selected template.
5. Review the returned SQL, citations, risks, gaps, verification guidance and
   rollback considerations.
6. A DBA or engineer decides whether to approve and apply it outside DBGuardAI.

HERMES never claims that proposed SQL was tested or executed.

## Local endpoints

- Dashboard: `http://localhost:9119`
- HERMES OpenAI-compatible API: `http://localhost:8642`
- HERMES health: `http://localhost:8642/health`
- DBGuard API docs: `http://localhost:8000/docs`

Both HERMES ports are bound to host loopback by Compose. The API requires
`HERMES_API_SERVER_KEY`; the dashboard requires its own username and password.
