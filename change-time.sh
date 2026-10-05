#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script with sudo or as root." >&2
    exit 1
fi

if [[ $# -ne 1 ]]; then
    echo "Usage: sudo $0 \"YYYY-MM-DD HH:MM:SS\"" >&2
    exit 1
fi

new_time=$1

if ! date -d "$new_time" >/dev/null 2>&1; then
    echo "Error: invalid date/time: $new_time" >&2
    echo "Example: sudo $0 \"2026-10-05 14:30:00\"" >&2
    exit 1
fi

if command -v timedatectl >/dev/null 2>&1; then
    timedatectl set-ntp false >/dev/null 2>&1 || true
    timedatectl set-time "$new_time"
else
    date -s "$new_time" >/dev/null
fi

echo "System time set to: $(date '+%Y-%m-%d %H:%M:%S %Z')"
