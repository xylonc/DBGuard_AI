ARG HERMES_BASE_IMAGE=nousresearch/hermes-agent@sha256:64923faeae267792bf9bf87fe3b4c4869e35004e360c7df01730ad801b74d524
FROM ${HERMES_BASE_IMAGE}

LABEL org.dbguardai.version="1.0.0"
LABEL org.dbguardai.hermes-release="v2026.8.31"
LABEL org.dbguardai.description="DBGuardAI controlled PostgreSQL hardening proposal agent"

# Managed configuration is copied into the persistent HERMES_HOME at startup.
# Secrets and conversation state remain in the /opt/data runtime volume.
COPY hermes/config/config.yaml /opt/dbguard/config.yaml
COPY hermes/configure.py /opt/dbguard/configure.py
COPY hermes/context/SOUL.md /opt/dbguard/SOUL.md
COPY hermes/context/HERMES.md /opt/dbguard/HERMES.md
COPY hermes/skills/dbguard-hardening/SKILL.md /opt/dbguard/SKILL.md
COPY hermes/docker-entrypoint.sh /usr/local/bin/dbguard-hermes-entrypoint
RUN chmod 0555 /usr/local/bin/dbguard-hermes-entrypoint

EXPOSE 8642 9119
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
  CMD curl -fsS http://localhost:8642/health || exit 1

ENTRYPOINT ["/usr/local/bin/dbguard-hermes-entrypoint"]
CMD ["gateway", "run"]
