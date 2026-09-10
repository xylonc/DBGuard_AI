# RAG Knowledge Data Management
# These commands help export/import your RAG data with your team

.PHONY: export import templates all help

help:
	@echo "RAG Data Management - Export/Import for Team Sharing"
	@echo "===================================================="
	@echo ""
	@echo "Commands:"
	@echo "  make export       - Export RAG knowledge data to ./export/"
	@echo "  make import       - Import RAG knowledge data from ./export/"
	@echo "  make templates    - Export/import templates only"
	@echo "  make all          - Export everything (knowledge + templates + more)"
	@echo "  make help         - Show this help"
	@echo ""
	@echo "Environment variables:"
	@echo "  DATABASE_URL - PostgreSQL connection string"
	@echo "  (default: postgresql://dbguard:***@localhost:5433/dbguard)"
	@echo ""

export:
	@echo "Exporting RAG knowledge data..."
	python scripts/export_rag_data.py "$(DATABASE_URL)" export
	@echo ""
	@echo "Exported files:"
	@ls -la export/

import:
	@echo "Importing RAG knowledge data..."
	python scripts/import_rag_data.py export "$(DATABASE_URL)"
	@echo ""
	@echo "Import complete!"

# Export/import everything in one command
all:
	@echo "Exporting all RAG data..."
	python scripts/export_all.py "$(DATABASE_URL)" export
	@echo ""
	@echo "Exported files:"
	@ls -la export/

import-all:
	@echo "Importing all RAG data..."
	python scripts/import_all.py export "$(DATABASE_URL)"
	@echo ""
	@echo "Import complete!"

# Templates (separate)
export-templates:
	@echo "Exporting templates..."
	python scripts/export_templates.py "postgresql://dbguard:***@localhost:5433/dbguard" export

import-templates:
	@echo "Importing templates..."
	python scripts/import_templates.py export "postgresql://dbguard:***@localhost:5433/dbguard"

# Docker Compose variants
export-docker:
	@echo "Exporting from Docker Compose stack..."
	python scripts/export_rag_data.py "postgresql://dbguard:***@localhost:5433/dbguard" export

import-docker:
	@echo "Importing to Docker Compose stack..."
	python scripts/import_rag_data.py export "postgresql://dbguard:***@localhost:5433/dbguard"

all-docker:
	@echo "Exporting everything from Docker Compose stack..."
	python scripts/export_all.py "postgresql://dbguard:***@localhost:5433/dbguard" export

import-all-docker:
	@echo "Importing everything to Docker Compose stack..."
	python scripts/import_all.py export "postgresql://dbguard:***@localhost:5433/dbguard"
