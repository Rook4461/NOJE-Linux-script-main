#!/usr/bin/env bash
# Configure the Debian/Ubuntu password-quality policy and optionally update one
# interactive human account selected by the operator.

set -u

PWQUALITY_FILE='/etc/security/pwquality.conf'
PAM_FILE='/etc/pam.d/common-password'

fail() {
    printf 'Error: %s\n' "$1" >&2
    exit 1
}

backup_file() {
    local file="$1"
    local stamp
    stamp="$(date +%Y%m%d%H%M%S)"
    cp -p "$file" "${file}.noje-backup-${stamp}" || fail "Unable to back up $file."
    printf 'Backup created: %s\n' "${file}.noje-backup-${stamp}"
}

set_pwquality_value() {
    local key="$1"
    local value="$2"

    if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$PWQUALITY_FILE"; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$PWQUALITY_FILE"
    else
        printf '%s = %s\n' "$key" "$value" >> "$PWQUALITY_FILE"
    fi
}

is_human_account() {
    local account="$1"
    local record uid shell

    record="$(getent passwd "$account" 2>/dev/null)" || return 1
    IFS=: read -r _ _ uid _ _ _ shell <<< "$record"
    [[ "$uid" =~ ^[0-9]+$ ]] || return 1
    ((uid >= 1000)) || return 1
    [[ "$shell" != '/usr/sbin/nologin' && "$shell" != '/sbin/nologin' && "$shell" != '/bin/false' && "$shell" != '/usr/bin/false' ]]
}

printf '=== Password Policy Setup ===\n\n'

((EUID == 0)) || fail 'Run this plugin as root, for example: sudo bash The_Script.sh'

if [[ ! -r /etc/os-release ]] || ! grep -Eq '^(ID|ID_LIKE)=(ubuntu|debian|.*debian.*)' /etc/os-release; then
    fail 'This implementation supports Ubuntu/Debian systems only.'
fi

[[ -f "$PWQUALITY_FILE" ]] || fail "$PWQUALITY_FILE does not exist. Install libpam-pwquality first."
[[ -f "$PAM_FILE" ]] || fail "$PAM_FILE does not exist."

if ! find /lib /usr/lib -name pam_pwquality.so -print -quit 2>/dev/null | grep -q .; then
    fail 'pam_pwquality is unavailable. Install libpam-pwquality first.'
fi

backup_file "$PWQUALITY_FILE"
backup_file "$PAM_FILE"

set_pwquality_value 'minlen' '10'
set_pwquality_value 'dcredit' '-1'
set_pwquality_value 'ocredit' '-1'

if ! grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' "$PAM_FILE"; then
    if grep -Eq '^[[:space:]]*password[[:space:]].*pam_unix\.so' "$PAM_FILE"; then
        sed -i '/^[[:space:]]*password[[:space:]].*pam_unix\.so/i password requisite pam_pwquality.so retry=3' "$PAM_FILE"
    else
        fail "Could not find a pam_unix password rule in $PAM_FILE."
    fi
fi

printf '\nPolicy configured:\n'
printf '  Minimum length: 10\n'
printf '  Minimum numbers: 1\n'
printf '  Minimum special characters: 1\n'

printf '\nVerified human accounts available for password update:\n'
getent passwd | awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)$/ { print "  " $1 }'
printf '\nEnter one username to update, or press Enter to skip: '
IFS= read -r username || true

if [[ -z "$username" ]]; then
    printf 'Password update skipped.\n'
    exit 0
fi

is_human_account "$username" || fail "'$username' is not a verified human login account."

printf 'Starting interactive password change for %s. Type 1P@ssword! when prompted if that is the competition password.\n' "$username"
passwd "$username"
