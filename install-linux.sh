#!/usr/bin/env bash
set -euo pipefail

REPO="${MYVPNCLIENT_REPO:-}"
VERSION="${MYVPNCLIENT_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/opt/myvpnclient}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/myvpnclient}"
FROM_RELEASE=0
INSTALL_API_SERVICE="${INSTALL_API_SERVICE:-0}"
API_BIND="${MYVPNCLIENT_API_BIND:-127.0.0.1}"
API_PORT="${MYVPNCLIENT_API_PORT:-17873}"
SERVICE_NAME="${MYVPNCLIENT_API_SERVICE_NAME:-myvpnclient-api.service}"

usage() {
  cat <<USAGE
Usage:
  sudo ./install-linux.sh
  ./install-linux.sh --from-release [version]
  ./install-linux.sh --install-api-service --api-bind <private-ip> --api-port 17873

Environment:
  MYVPNCLIENT_REPO=owner/repository
  MYVPNCLIENT_VERSION=latest
  INSTALL_DIR=/opt/myvpnclient
  BIN_PATH=/usr/local/bin/myvpnclient
  INSTALL_API_SERVICE=0
  MYVPNCLIENT_API_BIND=127.0.0.1
  MYVPNCLIENT_API_PORT=17873
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-release)
      FROM_RELEASE=1
      shift
      ;;
    --install-api-service)
      INSTALL_API_SERVICE=1
      shift
      ;;
    --no-install-api-service)
      INSTALL_API_SERVICE=0
      shift
      ;;
    --api-bind)
      API_BIND="${2:-}"
      if [[ -z "$API_BIND" ]]; then echo "--api-bind requires an address" >&2; exit 1; fi
      shift 2
      ;;
    --api-port)
      API_PORT="${2:-}"
      if [[ -z "$API_PORT" ]]; then echo "--api-port requires a port" >&2; exit 1; fi
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      VERSION="$1"
      shift
      ;;
  esac
done

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

download_release() {
  need unzip
  if [[ -z "$REPO" ]]; then
    echo "Set MYVPNCLIENT_REPO=owner/repository before using --from-release." >&2
    exit 1
  fi
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT INT TERM

  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    if [[ "$VERSION" == "latest" ]]; then
      gh release download --repo "$REPO" --pattern 'MyVpnClient-*-linux-x64.zip' --dir "$tmp_dir" --clobber
    else
      gh release download "v${VERSION#v}" --repo "$REPO" --pattern 'MyVpnClient-*-linux-x64.zip' --dir "$tmp_dir" --clobber
    fi
  else
    need curl
    if [[ "$VERSION" == "latest" ]]; then
      api_url="https://api.github.com/repos/$REPO/releases/latest"
      if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        json="$(curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" "$api_url")"
      else
        json="$(curl -fsSL "$api_url")"
      fi
      tag="$(printf '%s' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | head -n 1)"
    else
      tag="${VERSION#v}"
    fi

    if [[ -z "${tag:-}" ]]; then
      echo "Could not resolve release version. For private repos, install gh and run: gh auth login" >&2
      exit 1
    fi

    url="https://github.com/$REPO/releases/download/v$tag/MyVpnClient-$tag-linux-x64.zip"
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
      curl -fL -H "Authorization: Bearer $GITHUB_TOKEN" -o "$tmp_dir/MyVpnClient-$tag-linux-x64.zip" "$url"
    else
      curl -fL -o "$tmp_dir/MyVpnClient-$tag-linux-x64.zip" "$url"
    fi
  fi

  zip_path="$(find "$tmp_dir" -maxdepth 1 -name 'MyVpnClient-*-linux-x64.zip' -print | head -n 1)"
  if [[ -z "$zip_path" ]]; then
    echo "No MyVpnClient Linux release zip was downloaded." >&2
    exit 1
  fi

  app_dir="$tmp_dir/extract"
  mkdir -p "$app_dir"
  unzip -oq "$zip_path" -d "$app_dir"
  APP_DIR="$app_dir"
}

install_from_dir() {
  sudo_cmd=()
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    need sudo
    sudo_cmd=(sudo)
  fi

  "${sudo_cmd[@]}" install -d "$INSTALL_DIR"
  "${sudo_cmd[@]}" install -d "$(dirname "$BIN_PATH")"

  "${sudo_cmd[@]}" rm -rf "$INSTALL_DIR/backend"
  "${sudo_cmd[@]}" cp -a "$APP_DIR/backend" "$INSTALL_DIR/"
  "${sudo_cmd[@]}" cp "$APP_DIR/myvpnclient_bridge.py" "$INSTALL_DIR/"
  "${sudo_cmd[@]}" cp "$APP_DIR/config.example.json" "$INSTALL_DIR/"
  "${sudo_cmd[@]}" cp "$APP_DIR/config.linux.example.json" "$INSTALL_DIR/"
  "${sudo_cmd[@]}" cp "$APP_DIR/myvpnclient-linux" "$INSTALL_DIR/"
  "${sudo_cmd[@]}" sed -i 's/\r$//' "$INSTALL_DIR/myvpnclient-linux"
  "${sudo_cmd[@]}" chmod 755 "$INSTALL_DIR/myvpnclient-linux"

  "${sudo_cmd[@]}" ln -sf "$INSTALL_DIR/myvpnclient-linux" "$BIN_PATH"
}

install_api_service() {
  sudo_cmd=()
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    need sudo
    sudo_cmd=(sudo)
  fi
  need systemctl

  wait_for_bind_address=""
  case "$API_BIND" in
    ""|127.*|localhost|0.0.0.0|::|::1|"*")
      ;;
    *)
      wait_for_bind_address="ExecStartPre=/bin/sh -c 'i=0; while [ \$\$i -lt 60 ]; do ip addr show | grep -F \" $API_BIND/\" >/dev/null && exit 0; i=\$\$((i + 1)); sleep 1; done; echo \"Timed out waiting for API bind address $API_BIND\" >&2; exit 1'"
      ;;
  esac

  unit_tmp="$(mktemp)"
  cat > "$unit_tmp" <<SERVICE
[Unit]
Description=MyVpnClient API for App Control
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
Environment=HOME=/root
Environment=USER=root
$wait_for_bind_address
ExecStart=$BIN_PATH serve-api --bind $API_BIND --port $API_PORT
Restart=always
RestartSec=5
WorkingDirectory=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
SERVICE

  "${sudo_cmd[@]}" install -m 0644 "$unit_tmp" "/etc/systemd/system/$SERVICE_NAME"
  rm -f "$unit_tmp"
  "${sudo_cmd[@]}" systemctl daemon-reload
  "${sudo_cmd[@]}" systemctl enable "$SERVICE_NAME"
  "${sudo_cmd[@]}" systemctl restart "$SERVICE_NAME"
}
if [[ "$FROM_RELEASE" -eq 1 ]]; then
  download_release
else
  APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fi

install_from_dir

if [[ "$INSTALL_API_SERVICE" == "1" ]]; then
  install_api_service
fi

echo "Installed MyVpnClient Linux CLI to $BIN_PATH"
echo "Install runtime dependencies if needed:"
echo "  sudo apt install python3 openconnect vpnc-scripts"
echo "Then run:"
echo "  myvpnclient preflight-json"
echo "  sudo MYVPNCLIENT_DATA_DIR=\$HOME/.config/myvpnclient myvpnclient connect"
echo "Optional API service:"
echo "  sudo ./install-linux.sh --install-api-service --api-bind <private-ip> --api-port 17873"
