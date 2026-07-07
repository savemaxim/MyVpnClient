#!/bin/sh
set -eu

DEFAULT_REPO="savemaxim/MyVpnClient"
REPO_ENV="${MYVPNCLIENT_REPO:-}"
VERSION_ENV="${MYVPNCLIENT_VERSION:-}"
INSTALL_DIR="${INSTALL_DIR:-/opt/myvpnclient}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/myvpnclient}"
SERVICE_NAME="${MYVPNCLIENT_API_SERVICE_NAME:-myvpnclient-api.service}"
CONFIG_FILE="${MYVPNCLIENT_UPDATE_CONFIG:-/etc/myvpnclient/update.env}"
INSTALL_API_SERVICE_ENV="${INSTALL_API_SERVICE:-}"
API_BIND_ENV="${MYVPNCLIENT_API_BIND:-}"
API_PORT_ENV="${MYVPNCLIENT_API_PORT:-}"

if [ -r "$CONFIG_FILE" ]; then
  # shellcheck source=/dev/null
  . "$CONFIG_FILE"
fi

REPO="${REPO_ENV:-${MYVPNCLIENT_REPO:-$DEFAULT_REPO}}"
VERSION="${VERSION_ENV:-${MYVPNCLIENT_VERSION:-latest}}"
INSTALL_API_SERVICE="${INSTALL_API_SERVICE_ENV:-${INSTALL_API_SERVICE:-auto}}"
API_BIND="${API_BIND_ENV:-${MYVPNCLIENT_API_BIND:-auto}}"
API_PORT="${API_PORT_ENV:-${MYVPNCLIENT_API_PORT:-auto}}"

usage() {
  cat <<USAGE
Usage:
  sudo sh ./update-linux.sh
  sudo sh ./update-linux.sh 1.2.3
  sudo sh ./update-linux.sh --from-release [latest|1.2.3]

Options:
  --from-release [VERSION]      Compatibility alias. VERSION defaults to latest.
  --repo OWNER/REPOSITORY       GitHub repository. Default: $DEFAULT_REPO.
  --version VERSION             Release version, with or without leading v. Default: latest.
  --install-api-service         Install/reinstall the API systemd service.
  --no-install-api-service      Do not install/reinstall the API systemd service.
  --api-bind ADDRESS|auto       API bind address. "auto" preserves the existing service bind,
                                then uses tailscale ip -4 when available, then 127.0.0.1.
  --api-port PORT|auto          API port. "auto" preserves the existing service port, then 17873.
  --config PATH                 Persistent updater config. Default: /etc/myvpnclient/update.env.

Environment:
  MYVPNCLIENT_REPO=OWNER/REPOSITORY
  MYVPNCLIENT_VERSION=latest
  MYVPNCLIENT_API_BIND=auto
  MYVPNCLIENT_API_PORT=auto
  INSTALL_API_SERVICE=auto

The updater prefers GitHub CLI (gh) and falls back to curl for public releases
or when GITHUB_TOKEN is set.
USAGE
}

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

sudo_prefix() {
  if [ "$(id -u)" -eq 0 ]; then
    return 0
  fi
  need sudo
  printf '%s\n' sudo
}

service_exists() {
  command -v systemctl >/dev/null 2>&1 && systemctl cat "$SERVICE_NAME" >/dev/null 2>&1
}

service_exec_args() {
  if ! service_exists; then
    return 0
  fi
  systemctl cat "$SERVICE_NAME" 2>/dev/null | awk -F= '/^ExecStart=/{line=$0} END{sub(/^ExecStart=/, "", line); print line}'
}

arg_after() {
  flag="$1"
  shift
  previous=""
  for part in "$@"; do
    if [ "$previous" = "$flag" ]; then
      printf '%s\n' "$part"
      return 0
    fi
    previous="$part"
  done
  return 1
}

detect_service_value() {
  flag="$1"
  exec_line="$(service_exec_args)"
  if [ -z "$exec_line" ]; then
    return 1
  fi
  # Intentional word splitting: systemd ExecStart values written by this tool use simple argv.
  # shellcheck disable=SC2086
  set -- $exec_line
  arg_after "$flag" "$@"
}

detect_tailscale_ip() {
  if command -v tailscale >/dev/null 2>&1; then
    tailscale ip -4 2>/dev/null | head -n 1
  fi
}

resolve_api_options() {
  if [ "$INSTALL_API_SERVICE" = "auto" ]; then
    if service_exists; then
      INSTALL_API_SERVICE=1
    else
      INSTALL_API_SERVICE=0
    fi
  fi

  case "$INSTALL_API_SERVICE" in
    1|true|yes|on) INSTALL_API_SERVICE=1 ;;
    0|false|no|off) INSTALL_API_SERVICE=0 ;;
    *) echo "Invalid INSTALL_API_SERVICE value: $INSTALL_API_SERVICE" >&2; exit 1 ;;
  esac

  if [ "$API_BIND" = "auto" ]; then
    API_BIND="$(detect_service_value --bind || true)"
    if [ -z "$API_BIND" ]; then
      API_BIND="$(detect_tailscale_ip || true)"
    fi
    API_BIND="${API_BIND:-127.0.0.1}"
  fi

  if [ "$API_PORT" = "auto" ]; then
    API_PORT="$(detect_service_value --port || true)"
    API_PORT="${API_PORT:-17873}"
  fi
}

normalize_version() {
  value="$1"
  if [ "$value" = "latest" ]; then
    printf '%s\n' latest
  else
    printf '%s\n' "${value#v}"
  fi
}

gh_release_download() {
  repo="$1"
  version="$2"
  output_dir="$3"
  if [ "$version" = "latest" ]; then
    gh release download --repo "$repo" --pattern 'MyVpnClient-*-linux-x64.zip' --dir "$output_dir" --clobber
  else
    clean="${version#v}"
    gh release download "v$clean" --repo "$repo" --pattern "MyVpnClient-$clean-linux-x64.zip" --dir "$output_dir" --clobber
  fi
}

curl_with_optional_auth() {
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" "$@"
  else
    curl -fsSL "$@"
  fi
}

curl_file_with_optional_auth() {
  output="$1"
  url="$2"
  if [ -n "${GITHUB_TOKEN:-}" ]; then
    curl -fL -H "Authorization: Bearer $GITHUB_TOKEN" -o "$output" "$url"
  else
    curl -fL -o "$output" "$url"
  fi
}

curl_release_download() {
  repo="$1"
  version="$2"
  output_dir="$3"
  tag="$version"

  need curl
  if [ "$version" = "latest" ]; then
    json="$(curl_with_optional_auth "https://api.github.com/repos/$repo/releases/latest")"
    tag="$(printf '%s' "$json" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | head -n 1)"
  fi
  if [ -z "$tag" ]; then
    echo "Could not resolve latest release tag for $repo." >&2
    exit 1
  fi
  clean="${tag#v}"
  curl_file_with_optional_auth "$output_dir/MyVpnClient-$clean-linux-x64.zip" \
    "https://github.com/$repo/releases/download/v$clean/MyVpnClient-$clean-linux-x64.zip"
}

download_release() {
  repo="$1"
  version="$2"
  output_dir="$3"
  need unzip
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    gh_release_download "$repo" "$version" "$output_dir"
  else
    curl_release_download "$repo" "$version" "$output_dir"
  fi
}

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

write_update_config() {
  sudo_cmd="$(sudo_prefix || true)"
  tmp_file="$(mktemp)"
  {
    printf 'MYVPNCLIENT_REPO='
    shell_quote "$REPO"
    printf '\nMYVPNCLIENT_VERSION='
    shell_quote "$VERSION"
    printf '\nINSTALL_API_SERVICE='
    shell_quote "$INSTALL_API_SERVICE"
    printf '\nMYVPNCLIENT_API_BIND='
    shell_quote "$API_BIND"
    printf '\nMYVPNCLIENT_API_PORT='
    shell_quote "$API_PORT"
    printf '\nMYVPNCLIENT_API_SERVICE_NAME='
    shell_quote "$SERVICE_NAME"
    printf '\n'
  } > "$tmp_file"

  if [ -n "$sudo_cmd" ]; then
    "$sudo_cmd" install -d "$(dirname "$CONFIG_FILE")"
    "$sudo_cmd" install -m 0644 "$tmp_file" "$CONFIG_FILE"
  else
    install -d "$(dirname "$CONFIG_FILE")"
    install -m 0644 "$tmp_file" "$CONFIG_FILE"
  fi
  rm -f "$tmp_file"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --from-release)
      if [ "${2:-}" ] && [ "${2#-}" = "$2" ]; then
        VERSION="$2"
        shift 2
      else
        VERSION="${VERSION:-latest}"
        shift
      fi
      ;;
    --repo)
      REPO="${2:-}"
      if [ -z "$REPO" ]; then echo "--repo requires OWNER/REPOSITORY" >&2; exit 1; fi
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      if [ -z "$VERSION" ]; then echo "--version requires latest or a version" >&2; exit 1; fi
      shift 2
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
      if [ -z "$API_BIND" ]; then echo "--api-bind requires ADDRESS or auto" >&2; exit 1; fi
      shift 2
      ;;
    --api-port)
      API_PORT="${2:-}"
      if [ -z "$API_PORT" ]; then echo "--api-port requires PORT or auto" >&2; exit 1; fi
      shift 2
      ;;
    --config)
      CONFIG_FILE="${2:-}"
      if [ -z "$CONFIG_FILE" ]; then echo "--config requires PATH" >&2; exit 1; fi
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    [0-9]*|v[0-9]*|latest)
      VERSION="$1"
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

VERSION="$(normalize_version "$VERSION")"
resolve_api_options

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

echo "Downloading MyVpnClient ${VERSION} from $REPO..."
download_release "$REPO" "$VERSION" "$tmp_dir"

zip_path="$(find "$tmp_dir" -maxdepth 1 -name 'MyVpnClient-*-linux-x64.zip' -print | head -n 1)"
if [ -z "$zip_path" ]; then
  echo "No MyVpnClient Linux release zip was downloaded." >&2
  exit 1
fi

extract_dir="$tmp_dir/extract"
mkdir -p "$extract_dir"
unzip -oq "$zip_path" -d "$extract_dir"
chmod +x "$extract_dir/install-linux.sh"

if [ "$INSTALL_API_SERVICE" = "1" ]; then
  set -- --install-api-service --api-bind "$API_BIND" --api-port "$API_PORT"
else
  set -- --no-install-api-service
fi

echo "Installing $(basename "$zip_path")..."
INSTALL_DIR="$INSTALL_DIR" BIN_PATH="$BIN_PATH" bash "$extract_dir/install-linux.sh" "$@"
write_update_config

echo
echo "MyVpnClient update complete."
echo "Stored updater defaults in $CONFIG_FILE"
echo "Verify with:"
echo "  myvpnclient version"
echo "  myvpnclient status"
if [ "$INSTALL_API_SERVICE" = "1" ]; then
  echo "  systemctl status $SERVICE_NAME"
fi
