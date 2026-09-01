# DBGuardAI POC

**Database Security Hardening & Decision Support Platform**

## Overview
DBGuardAI collects security metadata from PostgreSQL without copying business data, creates an isolated configuration twin, tests hardening changes, and generates an itemised hardening package for human review and implementation.

## Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    DBGuardAI POC                            │
│                                                             │
│  PHASE 1: SNAPSHOT                                          │
│  ┌─────────────┐     ┌──────────────┐                      │
│  │ Metadata    │────→│ Container    │                       │
│  │ Snapshotter │     │ Simulator    │                       │
│  │ (PostgreSQL)│     │ (isolated DB)│                       │
│  └─────────────┘     └──────────────┘                      │
│                                ↓                            │
│  PHASE 2: RAG + PLANNING                                    │
│  ┌─────────────┐     ┌──────────────┐     ┌─────────────┐  │
│  │ RAG Engine  │←────│ Agent Planner│→────│ Rule        │  │
│  │ (CIS, etc.) │     │ (LLM)        │     │ Executor    │  │
│  └─────────────┘     └──────────────┘     └─────────────┘  │
│                                ↓                            │
│  PHASE 3: VERIFY + ASSESS                                   │
│  ┌─────────────┐     ┌──────────────┐     ┌─────────────┐  │
│  │ CIS Score   │←────│ Risk Assessor│←────│ Verification│  │
│  │ Reporter    │     │ (App checks) │     │ Engine      │  │
│  └─────────────┘     └──────────────┘     └─────────────┘  │
│                                ↓                            │
│  OUTPUT: Hardening Script + Report (with review flags)      │
└─────────────────────────────────────────────────────────────┘
```

## Repository Structure
```
dbguard-ai/
├── apps/
│   └── api/                    # FastAPI services
│       └── app/
│           ├── config.py       # Environment settings
│           ├── models.py       # Pydantic contracts
│           └── main.py         # API entrypoint
├── services/
│   ├── snapshot_collector/     # Metadata extraction
│   │   └── collect.py
│   ├── twin_runner/            # Container lifecycle
│   │   └── runner.py
│   └── rag/                    # Vector search
│       └── rag_service.py
├── catalog/
│   ├── controls/               # YAML hardening controls
│   │   └── pg-auth-001.yaml
│   └── images/                 # Approved PostgreSQL images
│       └── postgres-16.yaml
├── deploy/
│   └── compose.yaml            # Docker Compose stack
├── tests/
│   └── unit/
│       └── test_collector.py
├── hermes/
│   ├── skills/                 # DBGuard-specific skills
│   └── prompts/                # Agent prompts
└── contracts/
    └── schemas/                # JSON schemas for validation
```

## Quick Start
```bash
# 1. Clone repo
git clone <repo-url>
cd dbguard-ai

# 2. Configure environment
cp .env.example .env
# Edit .env with your settings

# 3. Start infrastructure
docker compose -f deploy/compose.yaml up -d

# 4. Collect snapshot
python3 services/snapshot_collector/collect.py \
  --dsn "postgresql://user:pass@localhost:5432/db" \
  --output snapshot.json

# 5. Run assessment
python3 services/assessment/run.py --snapshot snapshot.json

# 6. Generate hardening package
python3 services/reporting/generate.py --run-id <run-id>
```

## POC Scope
- **PostgreSQL versions:** 15, 16, 17
- **Initial controls:** ~10 representative controls
- **Container isolation:** Docker-based twin
- **LLM:** Online (OpenAI/Ollama)
- **RAG:** PostgreSQL + pgvector

## Non-Goals (POC)
- No direct production modification
- No autonomous decision-making
- No full CIS-CAT integration (simulated scoring)
- No multi-user authentication

## Security Principles
1. HERMES never touches Docker or production DBs
2. Only approved images execute
3. Every action has rollback
4. Three-attempt limit on remediations
5. Human approval required for all changes

## License
Internal Use Only - Confidential
