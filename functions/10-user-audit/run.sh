#!/usr/bin/env bash
# Read-only user audit placeholder. This script reports account information and does not change the system.

set -u

printf '=== User Audit ===\n\n'

printf 'Current user: %s\n' "$(id -un 2>/dev/null || echo unknown)"
printf 'Effective UID: %s\n' "$(id -u 2>/dev/null || echo unknown)"

printf '\n--- Local account list ---\n'
getent passwd | awk -F: '{ print $1 ": UID=" $3 ", HOME=" $6 ", SHELL=" $7 }'

printf '\n--- Sudo-capable users ---\n'
if getent group sudo >/dev/null 2>&1; then
    getent group sudo | cut -d: -f4 | sed 's/,/\n/g' | awk 'NF'
else
    printf 'No sudo group found.\n'
fi

printf '\n--- Accounts with UID 0 ---\n'
awk -F: '$3 == 0 { print $1 }' /etc/passwd 2>/dev/null || printf 'Unable to read /etc/passwd.\n'

printf '\n--- Password aging summary ---\n'
if command -v chage >/dev/null 2>&1; then
    for user in $(getent passwd | cut -d: -f1); do
        printf '\n[%s]\n' "$user"
        chage -l "$user" 2>/dev/null | sed -n '1,7p' || printf 'Password aging data unavailable.\n'
    done
else
    printf 'chage is unavailable on this system.\n'
fi

printf '\nThis audit is informational only. No files or settings were modified.\n'
