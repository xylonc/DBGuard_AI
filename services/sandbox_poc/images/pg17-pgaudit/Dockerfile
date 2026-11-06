# DBGuard sandbox image: stock PostgreSQL 17 plus the pgaudit package (CIS 3.2 rehearsal).
#
# Built only by scripts/build_sandbox_image.py; the resulting image ID is pinned in
# catalog/images/sandbox/pg17-pgaudit.json and verified by services/sandbox_poc/runtime.py
# before any container starts. Network is used at BUILD time only (apt); every sandbox
# still runs with --network none, a read-only root, no mounts and dropped capabilities.
#
# Nothing is preloaded: shared_preload_libraries keeps its empty default, so the image
# behaves like the stock one until a rehearsed fix adds pgaudit and restarts.

# Base pinned by digest (local postgres:17-bookworm, PostgreSQL 17.11-1.pgdg12+2).
FROM postgres:17-bookworm@sha256:3645570cccdfa447589da9f57dd740faa29b30938e861289a5574b6ca6b03826

# Exact package version from the PGDG apt repository already configured in the base.
ARG PGAUDIT_VERSION=17.1-2.pgdg12+1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends "postgresql-17-pgaudit=${PGAUDIT_VERSION}"; \
    rm -rf /var/lib/apt/lists/*; \
    # The server package must not have been upgraded by the dependency resolver.
    test "$(dpkg-query -W -f='${Version}' postgresql-17)" = "${PG_VERSION}"; \
    test "$(dpkg-query -W -f='${Version}' postgresql-17-pgaudit)" = "${PGAUDIT_VERSION}"; \
    test -f /usr/lib/postgresql/17/lib/pgaudit.so; \
    test -f /usr/share/postgresql/17/extension/pgaudit.control

LABEL org.dbguard.sandbox="pg17-pgaudit" \
      org.dbguard.pgaudit.version="${PGAUDIT_VERSION}"
