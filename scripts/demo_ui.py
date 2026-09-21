#!/usr/bin/env python3
"""Launch live workflow UI with disposable PostgreSQL fixtures; Ctrl+C cleans up."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]


def main():
    import uvicorn
    from services.sandbox_poc.demo import create_app
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8010)
    args = parser.parse_args()
    print(f"Preparing isolated demo fixtures. Open http://127.0.0.1:{args.port} after startup completes.", flush=True)
    print("Approvals are DEMO_FIXTURE_ONLY. No existing database is accessed. Ctrl+C removes demo resources.", flush=True)
    uvicorn.run(create_app(), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
