#!/usr/bin/env bash
# Read-only password policy review for Ubuntu-style systems.
# This reports password-related settings without changing anything.

set -u

printf '=== Password Policy Review ===\n\n'

printf '--- /etc/login.defs ---\n'
if [[ -r /etc/login.defs ]]; then
    grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|PASS_MIN_LEN|ENCRYPT_METHOD)' /etc/login.defs || printf 'No policy values found in /etc/login.defs.\n'
else
    printf '/etc/login.defs is not readable.\n'
fi

printf '\n--- PAM password policy files ---\n'
for pam_file in /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; do
    if [[ -f "$pam_file" ]]; then
        printf '\n[%s]\n' "$pam_file"
        grep -Ei 'pam_unix|pam_pwquality|pam_cracklib|minlen|ucredit|lcredit|dcredit|ocredit|difok|retry' "$pam_file" || printf 'No password policy directives found in this file.\n'
    fi
done

printf '\n--- Password-age values for local users ---\n'
if command -v chage >/dev/null 2>&1; then
    for user in $(getent passwd | cut -d: -f1); do
        printf '\n[%s]\n' "$user"
        chage -l "$user" 2>/dev/null | sed -n '1,7p' || printf 'Unable to read password aging data.\n'
    done
else
    printf 'The chage utility is not installed; password aging cannot be checked here.\n'
fi

printf '\nThis is a read-only review. No password or system settings were changed.\n'
