#!/usr/bin/env bash
set -euo pipefail

MIN="${1:-70}"
PKGS="$(go list ./... | grep -vE '/cmd/|/internal/tray|/internal/platform|/internal/netenv|/internal/app$')"

go test -coverprofile=coverage.out $PKGS
TOTAL="$(go tool cover -func=coverage.out | awk '/^total:/ {gsub("%","",$3); print $3}')"
echo "core coverage: ${TOTAL}% (minimum ${MIN}%)"

awk -v t="$TOTAL" -v m="$MIN" 'BEGIN { exit !(t+0 >= m+0) }'
