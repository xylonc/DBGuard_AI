# Twin runner status: deferred

`twin_runner.py` contains useful container lifecycle, replay, fidelity, cleanup,
and health-check logic. It is intentionally excluded from the current Compose
stack because it does not yet have an HTTP boundary, a verified image catalog,
or integration tests. It must not be described as a runnable service yet.

The next phase should add a narrow authenticated API, real approved image
records, Docker isolation tests, and proposal-to-twin contracts before enabling
it in deployment.
