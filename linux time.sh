#!/usr/bin/env bash
# Set the system time on Ubuntu or Ubuntu running under WSL.
# Usage: ./set-time.sh "2025-01-31 14:30:00"

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 'YYYY-MM-DD HH:MM:SS'" >&2
	exit 1
fi

new_time="$1"
date -d "$new_time" >/dev/null 2>&1 || {
	echo "Invalid date: $new_time" >&2
	exit 1
}

if grep -qi microsoft /proc/version 2>/dev/null; then
	# WSL: change the Windows host clock using PowerShell.
	windows_time="$(date -d "$new_time" '+%m/%d/%Y %H:%M:%S')"
	powershell.exe -NoProfile -Command \
		"Set-Date -Date '$windows_time'" >/dev/null
else
	sudo timedatectl set-time "$new_time"
fi

echo "System time set to: $(date)"
