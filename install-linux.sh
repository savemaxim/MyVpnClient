#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Run as root: sudo ./install-linux.sh" >&2
  exit 1
fi

APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-/opt/myvpnclient}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/myvpnclient}"

install -d "$INSTALL_DIR"
install -d "$(dirname "$BIN_PATH")"

cp -a "$APP_DIR/backend" "$INSTALL_DIR/"
cp "$APP_DIR/myvpnclient_bridge.py" "$INSTALL_DIR/"
cp "$APP_DIR/config.example.json" "$INSTALL_DIR/"
cp "$APP_DIR/config.linux.example.json" "$INSTALL_DIR/"
cp "$APP_DIR/myvpnclient-linux" "$INSTALL_DIR/"
chmod 755 "$INSTALL_DIR/myvpnclient-linux"

ln -sf "$INSTALL_DIR/myvpnclient-linux" "$BIN_PATH"

echo "Installed MyVpnClient Linux CLI to $BIN_PATH"
echo "Install runtime dependencies if needed:"
echo "  sudo apt install python3 openconnect vpnc-scripts"
echo "Then run:"
echo "  myvpnclient preflight-json"
echo "  sudo MYVPNCLIENT_DATA_DIR=\$HOME/.config/myvpnclient myvpnclient connect"
