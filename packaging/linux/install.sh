#!/bin/sh
# Installs NetScan as a systemd service. Run as root from the extracted tarball.
set -eu

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN=/usr/local/bin/netscan
UNIT=/etc/systemd/system/netscan.service

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must run as root (try: sudo ./install.sh)" >&2
  exit 1
fi
if [ ! -x "$DIR/netscan" ] || [ ! -f "$DIR/netscan.service" ]; then
  echo "netscan and netscan.service must sit next to install.sh" >&2
  exit 1
fi

if ! getent group netscan >/dev/null; then
  groupadd --system netscan
fi
if ! id -u netscan >/dev/null 2>&1; then
  useradd --system --gid netscan --home-dir /var/lib/netscan --no-create-home \
    --shell /usr/sbin/nologin netscan
fi

install -m 0755 "$DIR/netscan" "$BIN"
install -m 0644 "$DIR/netscan.service" "$UNIT"

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable --now netscan.service
  echo "NetScan installed and started. Dashboard: http://127.0.0.1:9095"
else
  echo "Installed $BIN and $UNIT. systemd is not running, so the service was not started."
fi
