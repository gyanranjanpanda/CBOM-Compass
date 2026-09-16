#!/usr/bin/env bash
# Render build step.
#
# The store is SQLite on the instance filesystem, which Render resets to its
# post-build state on every deploy and every free-plan spin-up. So the estate is
# built here rather than at startup: the dashboard is never empty on a cold open,
# and waking a spun-down instance costs nothing beyond the process start.
#
# What it scans is four real open-source projects, not a synthetic sample app.
# Every location the dashboard shows is a real file and line in code the viewer
# can go read, which is the whole claim the tool makes about itself.
set -euo pipefail

ESTATE=estate
PROJECTS=(
  "paramiko           https://github.com/paramiko/paramiko.git"
  "node-jsonwebtoken  https://github.com/auth0/node-jsonwebtoken.git"
  "golang-crypto      https://github.com/golang/crypto.git"
  "jjwt               https://github.com/jwtk/jjwt.git"
)

pip install --upgrade pip
pip install -e .

# A cached store from an earlier build would stack duplicate scans into the
# history and make the drift view compare the wrong two runs.
rm -f cbom-compass.db cbom-compass.db-wal cbom-compass.db-shm
rm -rf "$ESTATE"
mkdir -p "$ESTATE"

for entry in "${PROJECTS[@]}"; do
  read -r name url <<<"$entry"
  echo "==> cloning $name"
  git clone --depth 1 --single-branch --no-tags --quiet "$url" "$ESTATE/$name"
done

# Two scans, so the drift view opens on a real diff rather than an empty state:
# one project onboarded, then the rest of the estate added.
echo "==> scan 1 of 2 — first project onboarded"
cbom-compass scan "$ESTATE/paramiko" --limit 8

echo "==> scan 2 of 2 — full estate"
cbom-compass scan "$ESTATE"/* --limit 12
