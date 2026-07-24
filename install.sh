#!/bin/bash
# Riptide — install script for Ubuntu 22.04 / 24.04
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "╔══════════════════════════════════════════════════╗"
echo "║   Riptide C2 Framework — Installer              ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── OS check ──────────────────────────────────────────────────────

if [ ! -f /etc/os-release ]; then
    echo -e "${RED}[!] Cannot detect OS. /etc/os-release not found.${NC}"
    echo "    Please follow the manual build instructions in README.md."
    exit 1
fi

. /etc/os-release

if [ "$ID" != "ubuntu" ] || { [ "$VERSION_ID" != "22.04" ] && [ "$VERSION_ID" != "24.04" ]; }; then
    echo -e "${RED}[!] This installer only supports Ubuntu 22.04 and 24.04.${NC}"
    echo "    Detected: $NAME $VERSION_ID"
    echo ""
    echo "    For manual installation, see README.md:"
    echo "    1. Install Rust:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "    2. Add musl target: rustup target add x86_64-unknown-linux-musl"
    echo "    3. Build:          cargo build --release"
    echo "    4. Install service: cp riptide.service /etc/systemd/system/"
    echo "    5. Start:          systemctl enable --now riptide"
    exit 1
fi

echo -e "${GREEN}[+] Ubuntu $VERSION_ID detected${NC}"

# ── Install dependencies ──────────────────────────────────────────

echo "[*] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential pkg-config libssl-dev musl-tools curl 2>/dev/null

# ── Install Rust ──────────────────────────────────────────────────

if command -v rustc &>/dev/null; then
    echo -e "${GREEN}[+] Rust already installed: $(rustc --version)${NC}"
else
    echo "[*] Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    . "$HOME/.cargo/env"
fi

# ── Add musl target ───────────────────────────────────────────────

if rustup target list --installed | grep -q x86_64-unknown-linux-musl; then
    echo -e "${GREEN}[+] musl target already installed${NC}"
else
    echo "[*] Adding x86_64-unknown-linux-musl target..."
    rustup target add x86_64-unknown-linux-musl
fi

# ── Build ─────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Building Riptide (release)..."
cargo build --release 2>&1 | tail -3

# ── Install binaries ──────────────────────────────────────────────

INSTALL_DIR="/opt/riptide"
sudo mkdir -p "$INSTALL_DIR"

echo "[*] Installing binaries to $INSTALL_DIR..."

# Install server binary
sudo cp target/release/c2-server "$INSTALL_DIR/riptide-server"
sudo chmod 755 "$INSTALL_DIR/riptide-server"

# Install console, payload-gen, and Python client
sudo cp target/release/console "$INSTALL_DIR/riptide-console" 2>/dev/null || true
sudo cp target/release/payload-gen "$INSTALL_DIR/riptide-payload" 2>/dev/null || true
sudo cp "$SCRIPT_DIR/c2client.py" "$INSTALL_DIR/" 2>/dev/null || true

# ── Install systemd service ───────────────────────────────────────

SERVICE_FILE="/etc/systemd/system/riptide.service"

echo "[*] Installing systemd service..."

sudo tee "$SERVICE_FILE" > /dev/null << 'SERVICEEOF'
[Unit]
Description=Riptide C2 Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/riptide/riptide-server --api-port 10337
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICEEOF

sudo systemctl daemon-reload
sudo systemctl enable riptide
sudo systemctl start riptide

sleep 2

if systemctl is-active --quiet riptide; then
    echo -e "${GREEN}[+] Riptide service started successfully${NC}"
else
    echo -e "${YELLOW}[!] Service may not have started. Check: systemctl status riptide${NC}"
fi

# ── Done ──────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   Riptide installed successfully                ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Server binary:  /opt/riptide/riptide-server    ║"
echo "║  Console:        /opt/riptide/riptide-console   ║"
echo "║  Payload gen:    /opt/riptide/riptide-payload   ║"
echo "║  Python client:  /opt/riptide/c2client.py       ║"
echo "║  Service:        systemctl status riptide       ║"
echo "║  API port:       10337 (default)                ║"
echo "║  Logs:           journalctl -u riptide -f       ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Next steps:                                     ║"
echo "║    1. Start a beacon listener from the console:  ║"
echo "║       riptide-console --server http://localhost:10337 ║"
echo "║       > listeners add http 8080                  ║"
echo "║    2. Build an implant:                          ║"
echo "║       riptide-payload --host <IP> --port 8080    ║"
echo "║    3. Deploy and control                         ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Installation complete.${NC}"
