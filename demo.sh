#!/usr/bin/env bash
# CBOM Compass — demo against real code.
#
#   ./demo.sh                 scan real open-source projects, open the dashboard
#   ./demo.sh --no-serve      scan only
#   ./demo.sh /path/to/repo   scan something of yours instead
#
# Everything scanned here is real: unmodified upstream repositories, the real
# binaries installed on this machine, and a real TLS handshake. Nothing is
# fixture data written to make the tool look good. The one thing that is *not*
# discovered is the business tagging in crypto-policy.yaml — X (data lifetime)
# and criticality are facts about your organisation, not about the code, and
# anything untagged is badged "assumed" in the dashboard and in the CBOM.

set -euo pipefail
cd "$(dirname "$0")"

PY=.venv/bin/python
DB=demo.db
POLICY=crypto-policy.yaml
PORT=${PORT:-8000}
TLS_PORT=8443
SERVE=1
CUSTOM=""

for arg in "$@"; do
  case "$arg" in
    --no-serve) SERVE=0 ;;
    *) CUSTOM="$arg" ;;
  esac
done

bold() { printf "\033[1m%s\033[0m\n" "$1"; }
dim()  { printf "\033[2m%s\033[0m\n" "$1"; }

TLS_PID=""
cleanup() { [[ -n "$TLS_PID" ]] && kill "$TLS_PID" 2>/dev/null || true; }
trap cleanup EXIT

# --- 1. environment -------------------------------------------------------
if [[ ! -x "$PY" ]]; then
  bold "Creating virtualenv…"
  python3 -m venv .venv
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -e ".[dev]"
fi

# --- 2. real targets ------------------------------------------------------
if [[ -n "$CUSTOM" ]]; then
  SCAN_PATHS=("$CUSTOM")
  bold "Scanning $CUSTOM"
else
  [[ -d targets ]] || ./fetch-targets.sh
  SCAN_PATHS=(targets)
fi

# Real binaries on this machine: dynamically linked, with real import tables.
SYSTEM_BINARIES=()
for candidate in /usr/bin/ssh /usr/bin/curl /usr/bin/git; do
  [[ -f "$candidate" ]] && SYSTEM_BINARIES+=("$candidate")
done

# --- 3. real TLS endpoint -------------------------------------------------
TLS_TARGET=""
if lsof -ti :$TLS_PORT >/dev/null 2>&1; then
  TLS_TARGET="127.0.0.1:$TLS_PORT"
elif command -v openssl >/dev/null 2>&1; then
  $PY samples/tls_demo_server.py >/tmp/cbom-tls.log 2>&1 &
  TLS_PID=$!
  sleep 2
  kill -0 "$TLS_PID" 2>/dev/null && TLS_TARGET="127.0.0.1:$TLS_PORT"
fi

# --- 4. two scans, so drift is a real diff --------------------------------
rm -f "$DB"
bold "Scan 1 of 2 — source and dependencies"
$PY -m cbom_compass.cli --db "$DB" --user demo scan "${SCAN_PATHS[@]}" \
    --policy "$POLICY" --limit 0 >/dev/null
dim "  done"

echo
bold "Scan 2 of 2 — adding binaries, a live TLS endpoint and two key stores"
TLS_ARGS=()
[[ -n "$TLS_TARGET" ]] && TLS_ARGS=(--tls "$TLS_TARGET")
# Both key stores are file exports: a demo must not need cloud credentials or a
# physical token, and the export path exercises the same mapping code the live
# aws:// / azure:// / gcp:// / pkcs11:// connectors use.
$PY -m cbom_compass.cli --db "$DB" --user demo scan \
    "${SCAN_PATHS[@]}" "${SYSTEM_BINARIES[@]}" "${TLS_ARGS[@]}" \
    --cloud file://samples/keystore-export.json \
    --cloud file://samples/hsm-export.json \
    --policy "$POLICY" --limit 12 -o demo-cbom.json --format cbom

# --- 5. the other deliverables -------------------------------------------
echo
bold "Standard conformance"
$PY -m cbom_compass.cli validate demo-cbom.json

echo
bold "Proof: re-reading findings from disk"
dim "  Nothing below uses the scan result except the location it claimed."
$PY -m cbom_compass.cli --db "$DB" verify --sample 8 --seed 7 | tail -n +3

echo
bold "Measured scanner accuracy"
$PY -m cbom_compass.cli eval | sed -n '4,16p'

$PY - <<'PYEOF'
import pathlib
from cbom_compass import report_pdf
from cbom_compass.store import Store
document = Store("demo.db").latest()
pathlib.Path("demo-risk-summary.pdf").write_bytes(report_pdf.build(document, limit=40))
print("\nPDF risk summary -> demo-risk-summary.pdf")
PYEOF

if [[ $SERVE -eq 0 ]]; then
  echo; bold "Artefacts: demo-cbom.json · demo-risk-summary.pdf · $DB"
  exit 0
fi

# --- 6. dashboard ---------------------------------------------------------
echo
bold "Dashboard → http://127.0.0.1:$PORT"
cat <<'TXT'

  Proving it is real
    ./demo.sh printed a verification pass above: for a sample of findings it
    re-opened the file on disk and quoted the line. Run it against everything
    with

        .venv/bin/python -m cbom_compass.cli --db demo.db verify --sample 0

    and check any line by hand. The verifier is not a rubber stamp — plant an
    algorithm that is not there and it reports UNCONFIRMED
    (tests/test_verify.py::test_fabricated_findings_are_rejected).

    The exception is the business tagging in crypto-policy.yaml. X and
    criticality are not discoverable; untagged assets fall back to a default
    and are badged "assumed". The tool never hides that.

  Suggested demo path
    1. Overview        "raw · de-duplicated" — the same library found by three
                       scanners collapses to one row
    2. Inventory       search "mlkem" — paramiko is already migrating to ML-KEM,
                       and it scores as adequate, not as something to fix
    3. Z slider        drag it. Total risk moves; RSA does not, and the score
                       explainer says why (the NIST 2035 date is fixed)
    4. Any score       click it — X, Y, Z, the arithmetic, and which inputs
                       were assumed rather than tagged
    5. Asset graph     library hubs and their dependents: the blast radius
    6. Reports         export CycloneDX 1.7, PDF, or CSV — filters carry through

  Ctrl-C to stop.

TXT
exec $PY -m cbom_compass.cli --db "$DB" serve --policy "$POLICY" --port "$PORT"
