"""Materialize HERMES runtime configuration without baking secrets into images."""

import os
from pathlib import Path

import yaml
from plugins.dashboard_auth.basic import hash_password


SOURCE = Path("/opt/dbguard/config.yaml")
DESTINATION = Path("/opt/data/config.yaml")


def main() -> None:
    username = os.environ.get("HERMES_DASHBOARD_USERNAME", "dbguard")
    password = os.environ.get("HERMES_DASHBOARD_PASSWORD")
    if not password:
        raise SystemExit("HERMES_DASHBOARD_PASSWORD must be set")

    config = yaml.safe_load(SOURCE.read_text(encoding="utf-8"))
    config["dashboard"]["basic_auth"] = {
        "username": username,
        "password_hash": hash_password(password),
    }
    DESTINATION.write_text(
        yaml.safe_dump(config, sort_keys=False),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
