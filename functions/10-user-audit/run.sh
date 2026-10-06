#!/usr/bin/env bash
# Real local user audit and management console for Linux hardening.
# This script inventories all local accounts and provides interactive user management.
# IMPORTANT: Account deletion, password changes, and group removals are real system changes.
# Run as root and confirm every destructive action before proceeding.

set -u
IFS=$'\n\t'

AUTHORIZED_ADMIN_USERS=(link zelda impa urbosa darunia)
AUTHORIZED_USERS=(tingle beedle groose malon ruto sidon midna rauru teba mipha paya skullkid anju dampe kingrhoam saria epona linebeck purah tatl)

is_authorized_user() {
    local target="$1"
    local user

    for user in "${AUTHORIZED_ADMIN_USERS[@]}" "${AUTHORIZED_USERS[@]}"; do
        [[ "$target" == "$user" ]] && return 0
    done
    return 1
}

is_authorized_admin() {
    local target="$1"
    local user

    for user in "${AUTHORIZED_ADMIN_USERS[@]}"; do
        [[ "$target" == "$user" ]] && return 0
    done
    return 1
}

warn_high_risk() {
    printf '\n*** WARNING: This script can permanently change accounts and authentication. ***\n'
    printf 'Deleting a user, resetting a password, or removing sudo access is a real system action.\n'
    printf 'Run this as root only and confirm each action before it is executed.\n\n'
}

get_passwd_entries() {
    if command -v getent >/dev/null 2>&1; then
        getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null || true
    else
        cat /etc/passwd 2>/dev/null || true
    fi
}

get_user_passwd_entry() {
    local user="$1"
    if command -v getent >/dev/null 2>&1; then
        getent passwd "$user" 2>/dev/null || awk -F: -v target="$user" '$1 == target { print }' /etc/passwd 2>/dev/null || true
    else
        awk -F: -v target="$user" '$1 == target { print }' /etc/passwd 2>/dev/null || true
    fi
}

is_admin_user() {
    local user="$1"
    [[ -z "$user" ]] && return 1

    if id -u "$user" 2>/dev/null | grep -Eq '^0$'; then
        return 0
    fi

    local groups
    groups="$(id -nG "$user" 2>/dev/null || true)"
    if printf '%s\n' "$groups" | tr ' ' '\n' | grep -Eq '^(sudo|wheel|adm|admin)$'; then
        return 0
    fi

    return 1
}

get_password_state() {
    local user="$1"
    local status
    status="$(passwd -S "$user" 2>/dev/null || true)"

    if [[ -z "$status" ]]; then
        printf 'unknown'
        return
    fi

    case "${status%% *}" in
        P) printf 'set' ;;
        NP) printf 'no-password' ;;
        L|LK) printf 'locked' ;;
        *) printf 'unknown' ;;
    esac
}

get_account_status() {
    local user="$1"
    local shell_path=""
    shell_path="$(get_user_passwd_entry "$user" | cut -d: -f7 || true)"

    if [[ -z "$shell_path" ]]; then
        printf 'missing'
        return
    fi

    if [[ "$shell_path" == *nologin* || "$shell_path" == *false* || "$shell_path" == *sync* ]]; then
        printf 'disabled'
    else
        printf 'active'
    fi
}

get_user_type() {
    local user="$1"
    local uid home_dir shell_path

    uid="$(get_user_passwd_entry "$user" | cut -d: -f3 || echo 0)"
    home_dir="$(get_user_passwd_entry "$user" | cut -d: -f6 || true)"
    shell_path="$(get_user_passwd_entry "$user" | cut -d: -f7 || true)"

    if [[ -z "$uid" ]]; then
        printf 'unknown'
        return
    fi

    if [[ "$uid" == "0" ]]; then
        printf 'root'
        return
    fi

    if [[ "$shell_path" == *nologin* || "$shell_path" == *false* || "$shell_path" == *sync* || "$shell_path" == *halt* || "$shell_path" == *shutdown* ]]; then
        printf 'system'
        return
    fi

    if [[ "$uid" -ge 1000 ]] && { [[ "$home_dir" == /home/* ]] || [[ "$home_dir" == /Users/* ]] || [[ -n "$home_dir" ]]; }; then
        printf 'human'
        return
    fi

    if [[ "$uid" -lt 1000 ]]; then
        printf 'system'
        return
    fi

    printf 'system'
}

print_user_list() {
    printf '\n=== Human and Administrative Accounts ===\n'
    printf '%-18s %-8s %-8s %-24s %-8s %-12s %-12s\n' 'USER' 'UID' 'TYPE' 'GROUPS' 'ADMIN' 'PASSWORD' 'STATUS'
    printf '%-18s %-8s %-8s %-24s %-8s %-12s %-12s\n' '------------------' '--------' '--------' '------------------------' '--------' '------------' '------------'

    local -a admin_users=()
    local -a regular_users=()
    local user groups_list admin_flag password_flag account_state user_type

    while IFS=: read -r user _ uid _ _ home shell; do
        [[ -n "$user" ]] || continue

        user_type="$(get_user_type "$user")"
        if [[ "$user_type" != "human" && "$user_type" != "root" ]]; then
            continue
        fi

        groups_list="$(id -nG "$user" 2>/dev/null || echo 'unknown')"
        if is_admin_user "$user"; then
            admin_flag='YES'
            admin_users+=("$user|$uid|$user_type|$groups_list|$admin_flag|$(get_password_state "$user")|$(get_account_status "$user")")
        else
            admin_flag='NO'
            regular_users+=("$user|$uid|$user_type|$groups_list|$admin_flag|$(get_password_state "$user")|$(get_account_status "$user")")
        fi
    done < <(get_passwd_entries)

    for entry in "${admin_users[@]}"; do
        IFS='|' read -r user uid user_type groups_list admin_flag password_flag account_state <<< "$entry"
        printf '%-18s %-8s %-8s %-24s %-8s %-12s %-12s\n' "$user" "$uid" "$user_type" "${groups_list// /,}" "$admin_flag" "$password_flag" "$account_state"
    done

    for entry in "${regular_users[@]}"; do
        IFS='|' read -r user uid user_type groups_list admin_flag password_flag account_state <<< "$entry"
        printf '%-18s %-8s %-8s %-24s %-8s %-12s %-12s\n' "$user" "$uid" "$user_type" "${groups_list// /,}" "$admin_flag" "$password_flag" "$account_state"
    done
}

show_user_details() {
    local user="$1"

    printf '\n=== Details for %s ===\n' "$user"
    id "$user" 2>/dev/null || { printf 'User %s does not exist.\n' "$user"; return 1; }
    printf '\nGroups: %s\n' "$(id -nG "$user" 2>/dev/null || echo 'unknown')"
    printf 'Password state: %s\n' "$(get_password_state "$user")"
    printf 'Account status: %s\n' "$(get_account_status "$user")"

    if command -v chage >/dev/null 2>&1; then
        printf '\n--- Password aging ---\n'
        chage -l "$user" 2>/dev/null || printf 'Password aging information unavailable.\n'
    fi

    local home_dir
    home_dir="$(get_user_passwd_entry "$user" | cut -d: -f6 || true)"
    if [[ -n "$home_dir" ]]; then
        printf '\n--- Home directory ---\n'
        ls -ld "$home_dir" 2>/dev/null || printf 'Unable to inspect %s\n' "$home_dir"
    fi
}

remove_admin_rights() {
    local user="$1"
    local group
    local removal_made=0

    if is_authorized_admin "$user"; then
        printf 'Refusing to remove administrator rights from authorized administrator %s.\n' "$user"
        return 1
    fi

    printf 'Removing admin rights from %s...\n' "$user"
    for group in sudo wheel adm admin; do
        if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fxq "$group"; then
            if gpasswd -d "$user" "$group" 2>/dev/null; then
                printf 'Removed %s from group %s\n' "$user" "$group"
                removal_made=1
            else
                printf 'Failed to remove %s from group %s\n' "$user" "$group"
            fi
        fi
    done

    if (( removal_made == 0 )); then
        printf 'No admin groups were found for %s.\n' "$user"
    else
        printf 'Current groups for %s: %s\n' "$user" "$(id -nG "$user" 2>/dev/null || echo 'none')"
    fi
}

delete_user_account() {
    local user="$1"
    local confirm

    if is_authorized_user "$user"; then
        printf 'Refusing to delete authorized account %s or its home directory.\n' "$user"
        return 1
    fi

    printf '\nThis is destructive. %s will be deleted from the system and their home directory may be removed.\n' "$user"
    read -r -p "Type '$user' to confirm deletion, or press Enter to cancel: " confirm
    if [[ "$confirm" != "$user" ]]; then
        printf 'Deletion canceled.\n'
        return
    fi

    if userdel -r "$user" 2>/dev/null; then
        printf 'User %s has been deleted.\n' "$user"
    else
        printf 'User deletion failed for %s.\n' "$user"
    fi
}

show_user_groups() {
    local user="$1"
    printf '\n=== Groups for %s ===\n' "$user"
    groups "$user" 2>/dev/null || printf 'Unable to read group memberships for %s.\n' "$user"
}

remove_from_group() {
    local user="$1"
    local group

    read -r -p "Enter the group name to remove from $user: " group
    [[ -n "$group" ]] || { printf 'No group provided.\n'; return; }

    if ! id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fxq "$group"; then
        printf '%s is not a member of %s.\n' "$user" "$group"
        return
    fi

    if gpasswd -d "$user" "$group" 2>/dev/null; then
        printf '%s was removed from %s.\n' "$user" "$group"
    else
        printf 'Failed to remove %s from %s.\n' "$user" "$group"
    fi
}

change_user_password() {
    local user="$1"
    printf '\nChanging password for %s.\n' "$user"
    printf 'You will be prompted for the new password on the next line.\n'
    passwd "$user"
}

manage_user() {
    local user="$1"
    local choice

    while true; do
        printf '\n=== Manage user: %s ===\n' "$user"
        printf '1) Delete user\n'
        printf '2) Remove admin rights\n'
        printf '3) Show group memberships\n'
        printf '4) Change password\n'
        printf '5) Remove from a group\n'
        printf '6) Show detailed account info\n'
        printf '0) Back to user list\n'
        read -r -p 'Select an action: ' choice

        case "$choice" in
            1)
                delete_user_account "$user"
                ;;
            2)
                remove_admin_rights "$user"
                ;;
            3)
                show_user_groups "$user"
                ;;
            4)
                change_user_password "$user"
                ;;
            5)
                remove_from_group "$user"
                ;;
            6)
                show_user_details "$user"
                ;;
            0)
                return
                ;;
            *)
                printf 'Invalid option. Try again.\n'
                ;;
        esac

        printf '\nPress Enter to continue...' 
        read -r _ || true
    done
}

main() {
    warn_high_risk

    if [[ "$(id -u)" -ne 0 ]]; then
        printf 'This script is designed to manage local users, but you are not running as root.\n'
        printf 'The listing still works, but account changes will fail unless you run with sudo/root privileges.\n\n'
    fi

    while true; do
        print_user_list
        printf '\nType the username you want to edit, or press Enter to refresh the list.\n'
        printf 'Type q to exit.\n'
        read -r -p 'Select a user: ' target_user

        case "$target_user" in
            q|Q|'' )
                if [[ -z "$target_user" ]]; then
                    continue
                fi
                printf 'Exiting user audit.\n'
                return 0
                ;;
        esac

        if ! get_user_passwd_entry "$target_user" | grep -q .; then
            printf 'User %s was not found.\n' "$target_user"
            continue
        fi

        manage_user "$target_user"
    done
}

main "$@"
