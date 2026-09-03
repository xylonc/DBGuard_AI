# DBGuardAI HERMES Agent Dockerfile
# This image packages HERMES with DBGuard-specific configuration.
# Sensitive data (API keys, secrets) are mounted at runtime, not baked in.

# ---- Base Image ----
# Pass a complete immutable image reference, for example
# registry.example/hermes@sha256:<real digest>.
ARG HERMES_BASE_IMAGE

FROM ${HERMES_BASE_IMAGE}

# ---- Build-time Labels ----
LABEL org.dbguardai.version="1.0.0"
LABEL org.dbguardai.build-date="%BUILD_DATE%"
LABEL org.dbguardai.hermes-version="external"
LABEL org.dbguardai.description="DBGuardAI — Controlled Database Security Hardening Assistant"

# ---- Environment Variables ----
# These are defaults — override at runtime via docker-compose or .env
ENV HERMES_APP_NAME=DBGuardAI
ENV HERMES_MCP_RESTRICTED=true
ENV HERMES_APPROVAL_POLICY=high-risk
ENV HERMES_LOG_LEVEL=INFO
ENV HERMES_MODEL_PROVIDER=openai
ENV HERMES_MODEL=gpt-4o-mini

# ---- Copy DBGuard-Specific Files ----
# These are static, non-secret files that define DBGuard behavior.

# DBGuard skill
COPY hermes/skills/dbguard-skill.py /hermes/skills/dbguard-skill/

# MCP restrictions (defines allowed/prohibited tools)
COPY hermes/config/mcp-restrictions.yaml /hermes/config/mcp-restrictions.yaml

# Gateway configuration (defines tool routing)
COPY hermes/config/gateway.py /hermes/config/gateway.py

# DBGuard agent instructions (system prompts)
COPY hermes/prompts/agent-instructions.md /hermes/prompts/agent-instructions.md

# ---- Health Check ----
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# ---- Runtime Volumes ----
# These directories are mounted at deploy time with runtime secrets/knowledge.
# Nothing sensitive is baked into the image.
VOLUME ["/hermes/secrets"]
VOLUME ["/hermes/knowledge"]
VOLUME ["/hermes/logs"]

# ---- Expose Ports ----
# Gateway API port (MCP tool routing)
EXPOSE 8080

# ---- Entry Point ----
# Starts the DBGuardAI gateway with HERMES agent
# Runtime secrets are loaded from mounted volumes / env vars.
ENTRYPOINT ["hermes", "gateway", "--config", "/hermes/config/mcp-restrictions.yaml"]
CMD []

# ---- Image Provenance ----
# This image is built from:
# - Pinned HERMES base image (immutable digest)
# - DBGuard AI configuration files (static, non-secret)
# - NOT from: API keys, secrets, business data, or model weights
