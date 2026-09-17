# Twin Runner Service

> **Status (Sept 2026)**: This service is deferred to **Phase 2**. It is retained
> here for documentation purposes only; no runnable implementation is included in
> the current Phase 0 POC.

The twin runner is a **restricted Docker container lifecycle manager** for PostgreSQL
configuration verification. It is the ONLY DBGuard component permitted to communicate
with the Docker daemon.

## Architecture Boundary

```
HERMES / AI
    │
    │ proposes template + parameters + reasoning
    ▼
Trusted DBGuard API
    │
    │ validates template, parameters, evidence
    │ renders exact approved Jinja SQL
    ▼
Sandbox Validation Service
    │
    │ orchestrates lifecycle, calls restricted methods
    ▼
Twin Runner
    │
    │ ONLY this component contacts Docker
    ▼
Restricted Twin Runner (ephemeral container)
```

## Security Constraints

- No arbitrary Docker commands
- No host networking (`--net none`)
- No host filesystem mounts
- No production credentials
- Resource limits enforced (CPU, memory, process limits)
- No new privileges (`--no-new-privileges`)
- Capabilities dropped (`--cap-drop ALL`)
- Automatic cleanup via TTL

## Permitted Operations

The twin runner exposes only these methods (no generic `exec` or `run`):

- `create_twin(spec)` - Create a twin container from an approved image
- `stop_twin(run_id)` - Stop a twin container
- `destroy_twin(run_id)` - Remove a twin container and volumes
- `verify_twin(run_id)` - Verify twin identity and security config
- `execute_sql(run_id, sql, description)` - Execute SQL in twin (restricted interface)
- `replay_metadata(run_id, settings)` - Replay security-relevant settings (restricted interface)
- `cleanup_expired_twins()` - Remove expired containers
- `health_check()` - Service health status

## Approved Image Catalog

Images must come from `catalog/images/catalog.py` and be marked as approved.
Unapproved images are rejected during twin creation.

## Integration with Sandbox Validation

The twin runner is called by `SandboxValidationService` to:
1. Create an ephemeral PostgreSQL container
2. Replay security-relevant metadata (settings only)
3. Execute the approved proposal artifact (rendered SQL)
4. Collect snapshots for assessment
5. Execute rollback SQL
6. Verify restoration
7. Cleanup

The sandbox does NOT contain an autonomous agent. It only executes approved artifacts
and returns structured evidence.
