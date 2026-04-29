#!/usr/bin/env bash
set -euo pipefail

BIN_DIR="${HOME}/.local/bin"
CFG_DIR="${HOME}/.config/remote-askpass"

mkdir -p "$BIN_DIR" "$CFG_DIR"
chmod 700 "$BIN_DIR" "$CFG_DIR"

install -m 700 "$(dirname "$0")/remote-askpass" "$BIN_DIR/remote-askpass"
install -m 700 "$(dirname "$0")/rsudo" "$BIN_DIR/rsudo"

if [[ ! -f "$CFG_DIR/config.json" ]]; then
  cat > "$CFG_DIR/config.json" <<'JSON'
{
  "agent_url": "https://windows-host.tailnet-name.ts.net:7878/ask",
  "transport_mode": "tailscale",
  "tls_mode": "mtls",
  "client_cert_path": "~/.config/remote-askpass/client.crt",
  "client_key_path": "~/.config/remote-askpass/client.key",
  "server_ca_path": "~/.config/remote-askpass/server-ca.crt",
  "connect_timeout_seconds": 3,
  "request_timeout_seconds": 35,
  "send_host": true,
  "send_user": true,
  "send_cwd": true,
  "send_command_hint": false
}
JSON
  chmod 600 "$CFG_DIR/config.json"
fi

echo "Installed: $BIN_DIR/remote-askpass"
echo "Installed: $BIN_DIR/rsudo"
echo "Config: $CFG_DIR/config.json"
