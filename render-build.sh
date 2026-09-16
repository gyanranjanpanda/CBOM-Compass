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
POLICY=crypto-policy.yaml
FIRST=paramiko
REST=(
  "node-jsonwebtoken  https://github.com/auth0/node-jsonwebtoken.git"
  "golang-crypto      https://github.com/golang/crypto.git"
  "jjwt               https://github.com/jwtk/jjwt.git"
)

clone() {
  echo "==> cloning $1"
  git clone --depth 1 --single-branch --no-tags --quiet "$2" "$ESTATE/$1"
}

pip install --upgrade pip
pip install -e .

# A cached store from an earlier build would stack duplicate scans into the
# history and make the drift view compare the wrong two runs.
rm -f cbom-compass.db cbom-compass.db-wal cbom-compass.db-shm
rm -rf "$ESTATE"
mkdir -p "$ESTATE"

# Both scans take `estate` itself as the single scan root, never the project
# directories individually. Locations are recorded relative to the root, so
# scanning the projects separately would strip the project name off every
# finding — `acme/acme_test.go` rather than `golang-crypto/acme/acme_test.go` —
# and the `paths:` globs in the policy would match nothing, leaving every asset
# on the default criticality and the heat map collapsed into a single row.
clone "$FIRST" https://github.com/paramiko/paramiko.git
echo "==> scan 1 of 2 — first project onboarded"
cbom-compass scan "$ESTATE" --policy "$POLICY" --limit 8

# Two scans rather than one, so the drift view opens on a real diff. Growing the
# estate between them keeps every path stable across both, which is what makes
# the diff read as "these assets are new" instead of "everything moved".
for entry in "${REST[@]}"; do
  read -r name url <<<"$entry"
  clone "$name" "$url"
done
echo "==> scan 2 of 2 — full estate"
cbom-compass scan "$ESTATE" --policy "$POLICY" --limit 12
