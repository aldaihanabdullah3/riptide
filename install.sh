#!/bin/bash
# Riptide — install script for Ubuntu 22.04 / 24.04
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FORCE=0
if [ "${1:-}" = "--force" ]; then
    FORCE=1
    shift
fi

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
    echo "    For manual installation, see README.md"
    exit 1
fi

echo -e "${GREEN}[+] Ubuntu $VERSION_ID detected${NC}"

# ── Already installed? ────────────────────────────────────────────

INSTALL_DIR="/opt/riptide"
ALREADY_INSTALLED=0

if [ -x "$INSTALL_DIR/riptide-server" ] && [ "$FORCE" != "1" ]; then
    ALREADY_INSTALLED=1
    echo -e "${YELLOW}[!] Riptide is already installed at $INSTALL_DIR${NC}"
    echo "    Run with --force to rebuild and reinstall."
    echo ""
    echo "    To update:  $0 --force"
    echo "    To check:   systemctl status riptide"
    echo "    To stop:    systemctl stop riptide"
    echo ""
fi

# ── Install dependencies ──────────────────────────────────────────

echo "[*] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq build-essential pkg-config libssl-dev musl-tools curl 2>/dev/null

# ── Install Rust ──────────────────────────────────────────────────

# Ensure ~/.cargo/bin is in PATH for this script and persist it
CARGO_ENV="$HOME/.cargo/env"
if [ -f "$CARGO_ENV" ]; then
    . "$CARGO_ENV"
fi

if command -v rustc &>/dev/null; then
    echo -e "${GREEN}[+] Rust: $(rustc --version)${NC}"
else
    echo "[*] Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    . "$CARGO_ENV"
fi

# Put cargo/rustc on system PATH (works for non-login shells too)
for BIN in cargo rustc rustup; do
    if [ -x "$HOME/.cargo/bin/$BIN" ] && [ ! -L "/usr/local/bin/$BIN" ]; then
        sudo ln -sf "$HOME/.cargo/bin/$BIN" "/usr/local/bin/$BIN"
    fi
done

# ── Add musl target ───────────────────────────────────────────────

if rustup target list --installed 2>/dev/null | grep -q x86_64-unknown-linux-musl; then
    echo -e "${GREEN}[+] musl target: installed${NC}"
else
    echo "[*] Adding x86_64-unknown-linux-musl target..."
    rustup target add x86_64-unknown-linux-musl
fi

# ── Build ─────────────────────────────────────────────────────────

if [ "$ALREADY_INSTALLED" = "1" ]; then
    echo -e "${YELLOW}[!] Skipping build (already installed). Use --force to rebuild.${NC}"
else
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    cd "$SCRIPT_DIR"

    echo "[*] Building Riptide (release)..."
    export RIPTIDE_SRC="$INSTALL_DIR/src"
    cargo build --release 2>&1 | tail -3

    sudo mkdir -p "$INSTALL_DIR"

    echo "[*] Installing binaries to $INSTALL_DIR..."
    sudo cp target/release/c2-server "$INSTALL_DIR/riptide-server"
    sudo chmod 755 "$INSTALL_DIR/riptide-server"
    sudo cp target/release/console "$INSTALL_DIR/riptide-console" 2>/dev/null || true
    sudo cp target/release/payload-gen "$INSTALL_DIR/riptide-payload" 2>/dev/null || true
    sudo cp "$SCRIPT_DIR/c2client.py" "$INSTALL_DIR/" 2>/dev/null || true

    # Copy source tree so payload-gen can build implants
    SRC_DIR="$INSTALL_DIR/src"
    echo "[*] Copying source to $SRC_DIR..."
    sudo rm -rf "$SRC_DIR"
    sudo mkdir -p "$SRC_DIR"
    for member in c2-server console payload-gen implant; do
        if [ -d "$SCRIPT_DIR/$member" ]; then
            sudo cp -r "$SCRIPT_DIR/$member" "$SRC_DIR/"
        fi
    done
    sudo cp "$SCRIPT_DIR/Cargo.toml" "$SCRIPT_DIR/Cargo.lock" "$SRC_DIR/" 2>/dev/null || true
    sudo cp "$SCRIPT_DIR/rust-toolchain.toml" "$SRC_DIR/" 2>/dev/null || true

    # Symlink into PATH
    echo "[*] Linking into /usr/local/bin..."
    sudo ln -sf "$INSTALL_DIR/riptide-server" /usr/local/bin/riptide-server
    sudo ln -sf "$INSTALL_DIR/riptide-console" /usr/local/bin/riptide-console 2>/dev/null || true
    sudo ln -sf "$INSTALL_DIR/riptide-payload" /usr/local/bin/riptide-payload 2>/dev/null || true
    sudo ln -sf "$INSTALL_DIR/c2client.py" /usr/local/bin/riptide-client 2>/dev/null || true

    # Set RIPTIDE_SRC for all shells
    if [ ! -f /etc/profile.d/riptide.sh ]; then
        echo "export RIPTIDE_SRC=$SRC_DIR" | sudo tee /etc/profile.d/riptide.sh > /dev/null
        sudo chmod 644 /etc/profile.d/riptide.sh
    fi

    # Clean up build artifacts
    echo "[*] Cleaning build cache..."
    rm -rf "$SCRIPT_DIR/target"
fi

# ── Install systemd service ───────────────────────────────────────

SERVICE_FILE="/etc/systemd/system/riptide.service"

if [ -f "$SERVICE_FILE" ]; then
    echo -e "${GREEN}[+] systemd service already installed${NC}"
else
    echo "[*] Installing systemd service..."
    sudo tee "$SERVICE_FILE" > /dev/null << 'SERVICEEOF'
[Unit]
Description=Riptide C2 Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/riptide/riptide-server --api-port 10337 --cert-dir /opt/riptide
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICEEOF

    sudo systemctl daemon-reload
    sudo systemctl enable riptide
fi

# Always restart to pick up any binary updates
sudo systemctl restart riptide 2>/dev/null || sudo systemctl start riptide
sleep 2

if systemctl is-active --quiet riptide; then
    echo -e "${GREEN}[+] Riptide service: running${NC}"
else
    echo -e "${YELLOW}[!] Service may not have started. Check: systemctl status riptide${NC}"
fi

# ── Done ──────────────────────────────────────────────────────────

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║   Riptide installed                              ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Server:   $INSTALL_DIR/riptide-server"
echo "║  Console:  $INSTALL_DIR/riptide-console"
echo "║  Payload:  $INSTALL_DIR/riptide-payload"
echo "║  Client:   $INSTALL_DIR/c2client.py"
echo "║  Service:  systemctl status riptide"
echo "║  API port: 10337"
echo "║  Logs:     journalctl -u riptide -f"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Console:  riptide-console --server http://localhost:10337"
echo "║            > listeners add http 8080"
echo "║  Implant:  riptide-payload --host <IP> --port 8080"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Done.${NC}"
