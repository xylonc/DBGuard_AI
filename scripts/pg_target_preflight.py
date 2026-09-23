#!/usr/bin/env python3
"""Preflight check for pg-target connection.

Exit codes:
  0  ok
  1  unexpected error (Python's own uncaught-exception exit)
  2  connection failed
  3  dbguard_canary missing
  4  dbguard_canary empty
  5  PG_TARGET_URL unset
"""

import os
import sys

import psycopg2
from psycopg2 import OperationalError
from psycopg2.errors import UndefinedTable


def main():
    # Check PG_TARGET_URL is set
    pg_url = os.environ.get("PG_TARGET_URL")
    if not pg_url:
        print("Error: PG_TARGET_URL is not set in environment", file=sys.stderr)
        sys.exit(5)

    # Connect to pg-target - wrap only this call in try/except OperationalError
    try:
        conn = psycopg2.connect(pg_url)
    except OperationalError as e:
        print(f"Error: connection failed - {str(e).replace(pg_url, '[REDACTED]')}", file=sys.stderr)
        sys.exit(2)

    cur = conn.cursor()

    # Fetch server version
    cur.execute("SHOW server_version")
    server_version = cur.fetchone()[0]

    # Fetch current user
    cur.execute("SELECT current_user")
    current_user = cur.fetchone()[0]

    # Fetch is_superuser
    cur.execute("SELECT current_setting('is_superuser')")
    is_superuser = cur.fetchone()[0]

    # Fetch pg_postmaster_start_time
    cur.execute("SELECT pg_postmaster_start_time()")
    pg_postmaster_start_time = cur.fetchone()[0]

    # Fetch log_connections setting
    cur.execute("""
        SELECT setting, source, sourcefile
        FROM pg_settings
        WHERE name = 'log_connections'
    """)
    log_connections = cur.fetchone()

    # Fetch dbguard_canary table - check by exception TYPE only
    try:
        cur.execute("SELECT * FROM dbguard_canary")
        canary_rows = cur.fetchall()
    except UndefinedTable:
        print("Error: dbguard_canary table does not exist", file=sys.stderr)
        sys.exit(3)

    # Check if canary table is empty
    if not canary_rows:
        print("Error: dbguard_canary table exists but is empty", file=sys.stderr)
        sys.exit(4)

    # Print results
    print(f"server_version: {server_version}")
    print(f"current_user: {current_user}")
    print(f"is_superuser: {is_superuser}")
    print(f"pg_postmaster_start_time: {pg_postmaster_start_time}")
    if log_connections:
        print(f"log_connections: {log_connections[0]} (source: {log_connections[1]}, sourcefile: {log_connections[2]})")
    else:
        print("log_connections: (not found)")

    print("dbguard_canary rows:")
    for row in canary_rows:
        print(f"  {row}")

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
