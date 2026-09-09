#!/bin/sh
set -eu

mkdir -p /opt/data/skills/dbguard-hardening /opt/data/workspace
python /opt/dbguard/configure.py
cp /opt/dbguard/SOUL.md /opt/data/SOUL.md
cp /opt/dbguard/HERMES.md /opt/data/workspace/HERMES.md
cp /opt/dbguard/SKILL.md /opt/data/skills/dbguard-hardening/SKILL.md
chown -R 10000:10000 /opt/data

exec /opt/hermes/docker/entrypoint-dispatch.sh "$@"
