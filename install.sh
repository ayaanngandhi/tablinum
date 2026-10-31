#!/usr/bin/env bash
# Install Tablinum as a systemd *user* service on :6320.
# User units + linger mean it survives logout and reboot, no root needed at runtime.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-6320}"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/tablinum.service"

mkdir -p "$UNIT_DIR"

cat > "$UNIT" <<EOF
[Unit]
Description=Tablinum — document shelf on :$PORT
Documentation=https://github.com/ayaanngandhi/tablinum
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=/usr/bin/env python3 $DIR/tablinum.py serve --port $PORT
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload
systemctl --user enable tablinum.service
systemctl --user restart tablinum.service

# linger: without it a user unit dies at logout
loginctl enable-linger "$USER" >/dev/null 2>&1 || true

sleep 1.5
printf '\n'
systemctl --user --no-pager --lines=0 status tablinum.service | head -6
printf '\nTablinum → http://127.0.0.1:%s/\n' "$PORT"
curl -fsS -o /dev/null -w 'health check: %{http_code}\n' "http://127.0.0.1:$PORT/healthz" || true
