# HERMES packaging status

This directory contains the implemented DBGuard-specific HERMES package:

- proposal-phase system instructions;
- a strict MCP allow-list;
- typed proposal output contracts;
- a Dockerfile that layers them onto a HERMES runtime.

It is not part of the default Compose stack because this repository does not
contain or publish the upstream HERMES runtime. Supply a real, immutable base
image reference (preferably `registry/image@sha256:digest`) when building:

```sh
docker build --build-arg HERMES_BASE_IMAGE=registry/hermes@sha256:... \
  -f hermes/Dockerfile .
```

The package is therefore ready for integration, but the repository does not
claim that the external HERMES runtime is locally runnable.
