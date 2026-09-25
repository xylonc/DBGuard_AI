#!/usr/bin/env python3
"""Launch live workflow UI with disposable PostgreSQL fixtures; Ctrl+C cleans up."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]


def main():
    import uvicorn
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8010)
    parser.add_argument("--env-file", type=Path, help="Local private model settings")
    args = parser.parse_args()
    if args.env_file:
        from dotenv import load_dotenv
        load_dotenv(args.env_file, override=False)
    from services.sandbox_poc.demo import create_app
    print(f"Preparing isolated demo fixtures. Open http://127.0.0.1:{args.port} after startup completes.", flush=True)
    print("Approvals are DEMO_FIXTURE_ONLY. No existing database is accessed. Ctrl+C removes demo resources.", flush=True)
    uvicorn.run(create_app(public_url=f"http://127.0.0.1:{args.port}"), host="127.0.0.1", port=args.port)


if __name__ == "__main__":
    main()
