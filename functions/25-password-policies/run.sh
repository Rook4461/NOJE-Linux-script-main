#!/usr/bin/env bash
# Configure the Debian/Ubuntu password-quality policy and optionally update
# each interactive human account selected by the operator.

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

is_admin_account() {
    local account="$1"
    local group
    local groups

    [[ "$account" == 'root' ]] && return 0
    groups="$(id -nG "$account" 2>/dev/null)" || return 1
    for group in $groups; do
        case "$group" in
            sudo|admin|wheel) return 0 ;;
        esac
    done
    return 1
}

printf '=== Password Policy Setup ===\n\n'

((EUID == 0)) || fail 'Run this plugin as root, for example: sudo bash The_Script.sh'

declare -a human_users=()
declare -a admin_users=()
declare -a candidate_users=()
declare -a selected_users=()

collect_human_users() {
    human_users=()
    while IFS=: read -r account _ uid _ _ _ shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        ((uid >= 1000)) || continue
        is_human_account "$account" || continue
        human_users+=("$account")
    done < <(getent passwd)
}

collect_admin_users() {
    admin_users=()
    while IFS=: read -r account _ uid _ _ _ shell; do
        if [[ "$account" == 'root' ]]; then
            admin_users+=("$account")
        elif [[ "$uid" =~ ^[0-9]+$ ]] && ((uid >= 1000)) && is_human_account "$account" && is_admin_account "$account"; then
            admin_users+=("$account")
        fi
    done < <(getent passwd)
}

apply_general_policy() {
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

    collect_human_users
    printf '\nPolicy configured for %d human user(s):\n' "${#human_users[@]}"
    printf '  Minimum length: 10\n'
    printf '  Minimum numbers: 1\n'
    printf '  Minimum special characters: 1\n'
}

update_selected_passwords() {
    if ((${#selected_users[@]} == 0)); then
        printf '\nNo accounts selected. No passwords were changed.\n'
        return 0
    fi

    local default_password='1P@ssword!'
    local failures=0
    local updated=0
    local account

    for account in "${selected_users[@]}"; do
        if ! printf '%s:%s\n' "$account" "$default_password" | chpasswd; then
            printf 'Unable to update password for %s.\n' "$account" >&2
            failures=$((failures + 1))
            continue
        fi

        if chage -d 0 "$account"; then
            printf 'Password updated for %s and marked for reset at next login.\n' "$account"
            updated=$((updated + 1))
        else
            printf 'Password updated for %s, but it could not be marked for reset.\n' "$account" >&2
            failures=$((failures + 1))
        fi
    done

    if ((failures > 0)); then
        fail "$failures password update(s) failed."
    fi

    printf '\nPassword updates completed for %d account(s).\n' "$updated"
}

prompt_for_password_changes() {
    selected_users=()
    for account in "${candidate_users[@]}"; do
        role=''
        if is_admin_account "$account"; then
            role=' (administrator)'
        fi

        printf '\nChange password for %s%s? [y/N]: ' "$account" "$role"
        IFS= read -r answer || true
        case "$answer" in
            y|Y|yes|YES)
                selected_users+=("$account")
                ;;
            *)
                printf 'Skipped %s.\n' "$account"
                ;;
        esac
    done
    update_selected_passwords
}

pause_menu() {
    printf '\nPress Enter to return to the password policy menu...'
    IFS= read -r _ || true
}

while true; do
    printf '\n=== Password Policies ===\n'
    printf '1) Apply general password policy\n'
    printf '2) Pwd change\n'
    printf '3) Change admin pwd\n'
    printf '0) Back\n'
    printf 'Select an option: '
    IFS= read -r choice || break

    case "$choice" in
        1)
            apply_general_policy
            pause_menu
            ;;
        2)
            collect_human_users
            candidate_users=("${human_users[@]-}")
            if ((${#candidate_users[@]} == 0)); then
                printf '\nNo eligible human login accounts were found.\n'
            else
                prompt_for_password_changes
            fi
            pause_menu
            ;;
        3)
            collect_admin_users
            candidate_users=("${admin_users[@]-}")
            if ((${#candidate_users[@]} == 0)); then
                printf '\nNo administrator accounts were found.\n'
            else
                prompt_for_password_changes
            fi
            pause_menu
            ;;
        0|q|Q)
            break
            ;;
        *)
            printf 'Invalid selection. Choose 1, 2, 3, or 0.\n'
            ;;
    esac
done
