# Control catalog status

> **Status (Sept 2026)**: Assessment/control records are deferred to **Phase 1**.
> The current proposal phase uses reviewed knowledge documents and SQL templates.
> `examples/` preserves the earlier contract shape for that future phase without
> presenting it as implemented.

The current proposal phase uses reviewed knowledge documents and SQL templates.
Assessment/control records are not active yet. `examples/` preserves the earlier
contract shape for that future phase without presenting it as implemented.

## Assessment rulebook (Oct 2026)

There is one rulebook. `assess/registry.py` builds its CIS controls from the
reviewed spec YAML in `catalog/specs/<benchmark>/` (via `assess/spec_controls.py`),
so `/api/v1/snapshots/{id}/assessment`, HERMES `get_snapshot_assessment`, the
legacy sandbox and the spec-driven sandbox all apply the same spec, operator
and expected value. Adding a spec file adds the control everywhere.

The registry also keeps two DBGuard supplementary checks that are not CIS
PostgreSQL 17 recommendations: `DBGUARD-PUBLIC-SCHEMA-CREATE` and
`DBGUARD-MD5-PASSWORDS`. The old IDs `CIS-3.1.2` (log_connections, really CIS
3.1.20), `CIS-4.1.1` and `CIS-2.1` are accepted as aliases by `get_control()`
but are never reported.
