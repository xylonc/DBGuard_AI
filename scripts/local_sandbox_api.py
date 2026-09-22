#!/usr/bin/env python3
"""Serve the existing API plus exact-spec sandbox integration on the Docker host."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'backend')]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8011)
    parser.add_argument('--host', default='127.0.0.1', help='Use an explicit host binding reachable from Docker for HERMES')
    parser.add_argument('--env-file', type=Path, help='Optional local settings file; credentials are never printed')
    args = parser.parse_args()
    if args.env_file:
        from dotenv import load_dotenv
        load_dotenv(args.env_file, override=False)
    from app.config import settings
    if not settings.sandbox_poc_enabled:
        parser.error('Set SANDBOX_POC_ENABLED=true before starting the local runner')
    import uvicorn
    uvicorn.run('app.main:app', host=args.host, port=args.port)


if __name__ == '__main__':
    main()
