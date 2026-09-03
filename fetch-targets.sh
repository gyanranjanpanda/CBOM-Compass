#!/usr/bin/env bash
# Fetch real open-source projects to scan.
#
# The demo deliberately scans real third-party code rather than fixtures we
# wrote: a scanner that only finds what its authors planted proves nothing.
# These four were chosen because they use cryptography genuinely and differently
# — an SSH implementation, two JWT libraries in different languages, and Go's
# own crypto tree — and because paramiko is mid-migration to ML-KEM, so the
# inventory shows post-quantum cryptography already in production use.

set -euo pipefail
cd "$(dirname "$0")"
mkdir -p targets

clone() {   # clone <repo> <dir> <why>
  if [[ -d "targets/$2/.git" ]]; then
    printf "  \033[2mhave\033[0m   %-22s %s\n" "$2" "$3"
    return
  fi
  printf "  fetch  %-22s %s\n" "$2" "$3"
  git clone --depth 1 --quiet "https://github.com/$1.git" "targets/$2"
}

echo "Fetching real scan targets…"
clone paramiko/paramiko        paramiko           "SSH — RSA, ECDSA, x25519, and ML-KEM"
clone auth0/node-jsonwebtoken  node-jsonwebtoken  "JWT in JavaScript — RS256, ES256, HS256"
clone jwtk/jjwt                jjwt               "JWT in Java — JCA algorithm names"
clone golang/crypto            golang-crypto      "Go's extended crypto library"

echo
echo "Fetched into targets/ — $(du -sh targets 2>/dev/null | cut -f1) total."
echo "These are unmodified upstream repositories. Nothing here was written for the demo."
