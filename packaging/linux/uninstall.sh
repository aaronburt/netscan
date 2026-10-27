#!/bin/sh
# Removes the NetScan service and binary. History in /var/lib/netscan is kept
# unless --purge is given.
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "uninstall.sh must run as root (try: sudo ./uninstall.sh)" >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl disable --now netscan.service 2>/dev/null || true
fi

rm -f /etc/systemd/system/netscan.service /usr/local/bin/netscan
rm -rf /opt/netscan
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi

if [ "${1:-}" = "--purge" ]; then
  rm -rf /var/lib/netscan
  id -u netscan >/dev/null 2>&1 && userdel netscan || true
  getent group netscan >/dev/null && groupdel netscan || true
  echo "NetScan removed, including its history and service user."
else
  echo "NetScan removed. History in /var/lib/netscan was kept (run with --purge to delete it)."
fi
