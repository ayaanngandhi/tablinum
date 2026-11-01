#!/usr/bin/env bash
# Install Tablinum as a systemd *user* service on :6320.
# User units + linger mean it survives logout and reboot, no root needed at runtime.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-6320}"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/tablinum.service"

# The project venv is the unit's interpreter: the system python is externally
# managed on most distros, so a venv avoids fighting the OS. There are no
# third-party packages to install.
if [ ! -x "$DIR/.venv/bin/python" ]; then
  echo "creating .venv…"
  /usr/bin/python3 -m venv "$DIR/.venv"
fi
PY="$DIR/.venv/bin/python"

# A shelf with no profile password is not served at all, so make that a setup step.
if [ ! -f "$DIR/.env" ]; then
  echo
  echo "No .env yet. It needs one password per profile, for example:"
  echo "  TABLINUM_PASSWORD=…"
  echo "  TABLINUM_PASSWORD_SHARED=…"
  echo
  echo "Copy .env.example to .env and edit it:"
  echo "  cp $DIR/.env.example $DIR/.env"
  echo
  echo "The service will refuse to start until at least one profile has a password."
fi

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
ExecStart=$PY $DIR/tablinum.py serve --port $PORT
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
curl -fsS -o /dev/null -w 'health check: %{http_code} (open)\n' "http://127.0.0.1:$PORT/healthz" || true
curl -s -o /dev/null -w 'index without a session: %{http_code} (303 = locked)\n' "http://127.0.0.1:$PORT/"
