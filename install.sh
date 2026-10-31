#!/usr/bin/env bash
# Install Tablinum as a systemd *user* service on :6320.
# User units + linger mean it survives logout and reboot, no root needed at runtime.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-6320}"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT="$UNIT_DIR/tablinum.service"

# bcrypt lives in the project venv: the system python is externally managed on
# most distros, so a venv is the only install that does not fight the OS.
if [ ! -x "$DIR/.venv/bin/python" ]; then
  echo "creating .venv and installing bcrypt…"
  /usr/bin/python3 -m venv "$DIR/.venv"
  "$DIR/.venv/bin/pip" -q install --upgrade pip
  "$DIR/.venv/bin/pip" -q install bcrypt
fi
PY="$DIR/.venv/bin/python"

# A shelf with no password is not served at all, so make that a setup step.
if [ ! -f "$DIR/auth.json" ]; then
  echo
  echo "No password yet. Set one now:"
  echo "  $PY $DIR/tablinum.py passwd"
  echo
  read -r -p "Set it now? [Y/n] " yn
  case "${yn:-Y}" in
    [Yy]*) "$PY" "$DIR/tablinum.py" passwd ;;
    *) echo "Skipped — the service will refuse to start until a password exists." ;;
  esac
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
