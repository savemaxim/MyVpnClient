#!/usr/bin/env bash
set -euo pipefail

REPO="${MYVPNCLIENT_REPO:-savemaxim/MyVpnClient}"
VERSION="${MYVPNCLIENT_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/opt/myvpnclient}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/myvpnclient}"
FROM_RELEASE=0

usage() {
  cat <<USAGE
Usage:
  sudo ./install-linux.sh
  ./install-linux.sh --from-release [version]

Environment:
  MYVPNCLIENT_REPO=savemaxim/MyVpnClient
  MYVPNCLIENT_VERSION=latest
  INSTALL_DIR=/opt/myvpnclient
  BIN_PATH=/usr/local/bin/myvpnclient
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-release)
      FROM_RELEASE=1
      shift
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
  "${sudo_cmd[@]}" chmod 755 "$INSTALL_DIR/myvpnclient-linux"

  "${sudo_cmd[@]}" ln -sf "$INSTALL_DIR/myvpnclient-linux" "$BIN_PATH"
}

if [[ "$FROM_RELEASE" -eq 1 ]]; then
  download_release
else
  APP_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fi

install_from_dir

echo "Installed MyVpnClient Linux CLI to $BIN_PATH"
echo "Install runtime dependencies if needed:"
echo "  sudo apt install python3 openconnect vpnc-scripts"
echo "Then run:"
echo "  myvpnclient preflight-json"
echo "  sudo MYVPNCLIENT_DATA_DIR=\$HOME/.config/myvpnclient myvpnclient connect"
