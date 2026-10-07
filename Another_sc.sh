#!/usr/bin/env bash
# NOJE Linux Security Toolkit - OKCUP Round 1 / Ubuntu 24.04 SUPER edition
#
# Built for the supplied OKCUP Round 1 practice scenario.
#
# Philosophy:
#   1) Preserve evidence / forensics first.
#   2) Audit broadly before changing anything.
#   3) Never disable scoreengine.
#   4) Never delete an authorized user or home directory.
#   5) Treat findings as REVIEW items unless the scenario clearly supports fixing them.
#   6) Back up configuration before modifying it where practical.
#
# This is intentionally a single-file toolkit. It is heavily audit-oriented,
# interactive, and designed for fast CyberPatriot/competition use.
#
# Expected platform for this round: Ubuntu 24.04.

set -u

###############################################################################
# Round-specific configuration
###############################################################################

AUTHORIZED_ADMINS=(link zelda impa urbosa darunia)
AUTHORIZED_USERS=(tingle beedle groose malon ruto sidon midna rauru teba mipha paya skullkid anju dampe kingrhoam saria epona linebeck purah tatl)

# The supplied README asks for a secure default maximum password age.
# 90 days is retained as the toolkit's competition baseline from the original
# NOJE script. Change this constant only if the round's scoring evidence says
# another value is expected.
DEFAULT_MAX_PASSWORD_DAYS=90

# Groups that grant administrator-equivalent sudo capability on Ubuntu.
ADMIN_GROUPS=(sudo admin wheel)

# Services / agents explicitly inconsistent with the scenario's statement
# that this company does not use centralized maintenance or polling tools.
MGMT_AGENT_PATTERNS='zabbix|zabbix-agent|nagios|nrpe|munin|puppet|salt-minion|chef-client|datadog-agent|telegraf|osquery|landscape-client|landscape-common|tripwire|aide'

# Tool names called out or commonly encountered in these practice images.
SECURITY_TOOL_PATTERNS='aircrack|burpsuite|hashcat|hydra|john|johnny|metasploit|msfconsole|ncat|netcat|nikto|nmap|scapy|sqlmap|wireshark|zenmap|ettercap|bettercap|responder|tcpdump'

###############################################################################
# Generic helpers
###############################################################################

tty_read() {
    # Always read interactive answers from the terminal when one exists.
    # Many remediation loops use process substitution/pipes for their audit data,
    # which otherwise steals stdin from the user's prompt.
    if [[ -r /dev/tty ]]; then
        IFS= builtin read "$@" </dev/tty
    else
        IFS= builtin read "$@"
    fi
}

pause_screen() {
    printf '\nPress Enter to continue...'
    tty_read -r _ || true
}

need_root() {
    if (( EUID != 0 )); then
        printf 'This action requires root. Re-run the toolkit with sudo.\n' >&2
        return 1
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

section() {
    printf '\n\n============================================================\n'
    printf '%s\n' "$1"
    printf '============================================================\n'
}

subsection() {
    printf '\n--- %s ---\n' "$1"
}

pass_msg() { printf 'PASS: %s\n' "$*"; }
warn_msg() { printf 'WARN: %s\n' "$*"; }
review_msg() { printf 'REVIEW: %s\n' "$*"; }
info_msg() { printf 'INFO: %s\n' "$*"; }

is_authorized_user() {
    local target="$1" item
    for item in "${AUTHORIZED_ADMINS[@]}" "${AUTHORIZED_USERS[@]}"; do
        [[ "$target" == "$item" ]] && return 0
    done
    return 1
}

is_authorized_admin() {
    local target="$1" item
    for item in "${AUTHORIZED_ADMINS[@]}"; do
        [[ "$target" == "$item" ]] && return 0
    done
    return 1
}

is_protected_scoreengine() {
    local value="${1,,}"
    [[ "$value" == *scoreengine* ]]
}

get_passwd_record() {
    getent passwd "$1" 2>/dev/null || true
}

get_user_uid() { get_passwd_record "$1" | awk -F: '{print $3}'; }
get_user_gid() { get_passwd_record "$1" | awk -F: '{print $4}'; }
get_user_home() { get_passwd_record "$1" | awk -F: '{print $6}'; }
get_user_shell() { get_passwd_record "$1" | awk -F: '{print $7}'; }

is_human_account() {
    local user="$1" record uid shell home
    record="$(get_passwd_record "$user")"
    [[ -n "$record" ]] || return 1
    IFS=: read -r _ _ uid _ _ home shell <<< "$record"
    [[ "$uid" =~ ^[0-9]+$ ]] || return 1
    (( uid >= 1000 && uid != 65534 )) || return 1
    [[ "$shell" != */nologin && "$shell" != */false ]] || return 1
    [[ -n "$home" ]] || return 1
    return 0
}

is_admin_account() {
    local user="$1" group
    [[ "$user" == root ]] && return 0
    have id || return 1
    for group in "${ADMIN_GROUPS[@]}"; do
        id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fxq "$group" && return 0
    done
    return 1
}

password_state() {
    local status
    status="$(passwd -S "$1" 2>/dev/null || true)"
    case "${status#* }" in
        P*) printf 'set' ;;
        NP*) printf 'NO PASSWORD' ;;
        L*|LK*) printf 'LOCKED' ;;
        *) printf 'unknown' ;;
    esac
}

pwquality_value() {
    local key="$1"
    awk -F= -v key="$key" '
        /^[[:space:]]*#/ { next }
        {
            name=$1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
            if (name == key) {
                value=$2
                sub(/[[:space:]]+#.*/, "", value)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                if (found && configured != value) {
                    conflict=1
                }
                configured=value
                found=1
            }
        }
        END {
            if (conflict) print "__conflicting_values__"
            else if (found) print configured
        }
    ' /etc/security/pwquality.conf 2>/dev/null
}

login_max_password_days() {
    awk -v max="$DEFAULT_MAX_PASSWORD_DAYS" '
        $1 == "PASS_MAX_DAYS" {
            count++
            if ($2 !~ /^[0-9]+$/ || $2 > max) invalid=1
            value=$2
        }
        END {
            if (count && !invalid) print value
        }
    ' /etc/login.defs 2>/dev/null
}

backup_file() {
    local file="$1" stamp destination
    [[ -f "$file" ]] || return 0
    stamp="$(date +%Y%m%d%H%M%S)"
    destination="$(mktemp "${file}.noje-backup-${stamp}.XXXXXX")" || return 1
    if ! cp -p -- "$file" "$destination"; then
        rm -f -- "$destination"
        return 1
    fi
    info_msg "Backup created: $destination"
}

###############################################################################
# Startup / evidence preservation
###############################################################################

check_forensics_questions() {
    section 'FORENSICS / EVIDENCE CHECK'
    info_msg 'The README says valid Forensics Questions are directly on the Desktop.'
    info_msg 'Read them before making changes to the machine.'
    local desktop candidate found=0
    while IFS=: read -r user _ uid _ _ home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        (( uid >= 1000 && uid != 65534 )) || continue
        [[ "$home" == /home/* && -d "$home" ]] || continue
        desktop="$home/Desktop"
        [[ -d "$desktop" ]] || continue
        while IFS= read -r -d '' candidate; do
            found=1
            printf 'FORENSICS FILE: %s\n' "$candidate"
        done < <(find "$desktop" -maxdepth 1 -type f -iname '*Forensics*' -print0 2>/dev/null)
    done < <(getent passwd)
    if (( ! found )); then
        info_msg 'No Desktop file whose name contains "Forensics" was found by this helper.'
    fi
}

system_overview() {
    section 'SYSTEM OVERVIEW'
    local id=unknown version=unknown pretty=unknown arch=unknown kernel hostname
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        id="${ID:-unknown}"
        version="${VERSION_ID:-unknown}"
        pretty="${PRETTY_NAME:-unknown}"
    fi
    arch="$(dpkg --print-architecture 2>/dev/null || uname -m)"
    kernel="$(uname -r 2>/dev/null || printf unknown)"
    hostname="$(hostname 2>/dev/null || printf unknown)"
    printf 'OS:       %s\n' "$pretty"
    printf 'ID:       %s\n' "$id"
    printf 'Version:  %s\n' "$version"
    printf 'Arch:     %s\n' "$arch"
    printf 'Kernel:   %s\n' "$kernel"
    printf 'Hostname: %s\n' "$hostname"
    printf 'Uptime:   '; uptime -p 2>/dev/null || uptime 2>/dev/null || true
    [[ "$id" == ubuntu && "$version" == 24.04 ]] && pass_msg 'Ubuntu 24.04 confirmed.' || warn_msg 'Scenario requires Ubuntu 24.04.'
}

###############################################################################
# Account auditing
###############################################################################

list_human_accounts() {
    while IFS=: read -r user _ uid gid gecos home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] || continue
        (( uid >= 1000 && uid != 65534 )) || continue
        [[ "$shell" != */nologin && "$shell" != */false ]] || continue
        [[ -n "$home" ]] || continue
        printf '%s\t%s\t%s\t%s\t%s\n' "$user" "$uid" "$gid" "$home" "$shell"
    done < <(getent passwd)
}

show_accounts() {
    section 'HUMAN ACCOUNT INVENTORY'
    printf '%-18s %-7s %-8s %-6s %-12s %-10s %-10s\n' USER UID ADMIN AUTHORIZED PASSWORD STATUS
    printf '%-18s %-7s %-8s %-6s %-12s %-10s %-10s\n' '------------------' '-------' '--------' '------' '------------' '----------' '----------'
    local user uid admin authorized pstate status
    while IFS=$'\t' read -r user uid _ _ _; do
        if is_admin_account "$user"; then admin=YES; else admin=NO; fi
        if is_authorized_user "$user"; then authorized=YES; else authorized=NO; fi
        pstate="$(password_state "$user")"
        if [[ "$(get_user_shell "$user")" == */nologin || "$(get_user_shell "$user")" == */false ]]; then
            status=DISABLED
        else
            status=ACTIVE
        fi
        printf '%-18s %-7s %-8s %-6s %-12s %-10s %-10s\n' "$user" "$uid" "$admin" "$authorized" "$pstate" "$status" "$([ -d "$(get_user_home "$user")" ] && printf HOME_OK || printf NO_HOME)"
    done < <(list_human_accounts)
}

account_reconcile() {
    section 'AUTHORIZED ACCOUNT RECONCILIATION'
    subsection 'Authorized administrators'
    local user found=0
    for user in "${AUTHORIZED_ADMINS[@]}"; do
        if getent passwd "$user" >/dev/null 2>&1; then
            found=1
            if is_human_account "$user"; then pass_msg "$user exists as a human login account."; else warn_msg "$user exists but does not look like a normal human login account."; fi
            if is_admin_account "$user"; then pass_msg "$user has administrator group membership."; else warn_msg "$user is not currently in sudo/admin/wheel."; fi
        else
            warn_msg "Authorized administrator $user is MISSING."
        fi
    done

    subsection 'Authorized users'
    for user in "${AUTHORIZED_USERS[@]}"; do
        if getent passwd "$user" >/dev/null 2>&1; then
            found=1
            if is_human_account "$user"; then pass_msg "$user exists as a human login account."; else warn_msg "$user exists but may not be an active human login account."; fi
            if is_admin_account "$user"; then warn_msg "$user currently has administrator-equivalent group membership."; fi
        else
            warn_msg "Authorized user $user is MISSING."
        fi
    done

    subsection 'Human accounts NOT authorized by the README'
    local count=0
    while IFS=$'\t' read -r user _ _ _ _; do
        if ! is_authorized_user "$user"; then
            review_msg "Unauthorized human account: $user"
            count=$((count + 1))
        fi
    done < <(list_human_accounts)
    (( count == 0 )) && pass_msg 'No unauthorized human login accounts found.'

    subsection 'Unauthorized administrators'
    count=0
    while IFS=$'\t' read -r user _ _ _ _; do
        if is_admin_account "$user" && ! is_authorized_admin "$user"; then
            warn_msg "Unauthorized administrator: $user"
            count=$((count + 1))
        fi
    done < <(list_human_accounts)
    (( count == 0 )) && pass_msg 'No unauthorized human administrators found.'
    (( found == 1 )) || true

    subsection 'UID 0 audit'
    local uid0
    uid0="$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null | paste -sd ' ' -)"
    printf 'UID 0 accounts: %s\n' "${uid0:-none found}"
    if [[ "$uid0" == root ]]; then
        pass_msg 'Only root owns UID 0.'
    elif [[ -z "$uid0" ]]; then
        warn_msg 'No UID 0 account was found.'
    else
        warn_msg "Unexpected UID 0 account set: $uid0"
    fi
}

account_details() {
    local user="$1" record home shell uid groups admin pstate
    record="$(get_passwd_record "$user")"
    [[ -n "$record" ]] || { warn_msg "Account not found: $user"; return 1; }
    IFS=: read -r _ _ uid _ _ home shell <<< "$record"
    groups="$(id -nG "$user" 2>/dev/null || true)"
    if is_admin_account "$user"; then admin=YES; else admin=NO; fi
    pstate="$(password_state "$user")"
    subsection "Account details: $user"
    printf 'UID:             %s\n' "$uid"
    printf 'Home:            %s\n' "$home"
    printf 'Shell:           %s\n' "$shell"
    printf 'Groups:          %s\n' "$groups"
    printf 'Admin:           %s\n' "$admin"
    printf 'Authorized:      %s\n' "$(is_authorized_user "$user" && printf YES || printf NO)"
    printf 'Password state:  %s\n' "$pstate"
    if have chage; then chage -l "$user" 2>/dev/null || true; fi
    if [[ -n "$home" && -e "$home" ]]; then
        stat -c 'Home metadata: owner=%U:%G mode=%A numeric=%a' -- "$home" 2>/dev/null || true
    else
        warn_msg 'Home directory is missing.'
    fi
}

account_audit_passwords() {
    section 'ACCOUNT PASSWORD / EXPIRY AUDIT'
    local user uid pstate exp warn_inactive shell
    while IFS=$'\t' read -r user uid _ _ shell; do
        pstate="$(password_state "$user")"
        printf '\n%s\n' "$user"
        printf '  password: %s\n' "$pstate"
        if [[ "$pstate" == 'NO PASSWORD' ]]; then warn_msg "$user has no password."; fi
        if [[ "$pstate" == LOCKED* ]]; then review_msg "$user password is locked; verify whether that is intentional."; fi
        if have chage; then
            chage -l "$user" 2>/dev/null | sed 's/^/  /' || true
            exp="$(chage -l "$user" 2>/dev/null | awk -F': ' '/Account expires/ {print $2; exit}')"
            [[ "$exp" == 'never' || -z "$exp" ]] || review_msg "$user account has an expiration date: $exp"
        fi
    done < <(list_human_accounts)
}

account_home_permissions() {
    section 'HOME DIRECTORY / SSH PERMISSION AUDIT'
    local user home path mode owner
    while IFS=$'\t' read -r user _ _ home _; do
        if [[ ! -d "$home" ]]; then warn_msg "$user home missing: $home"; continue; fi
        owner="$(stat -c '%U' -- "$home" 2>/dev/null || printf unknown)"
        mode="$(stat -c '%a' -- "$home" 2>/dev/null || printf unknown)"
        if [[ "$owner" != "$user" ]]; then warn_msg "$home owner is $owner; expected $user."; else pass_msg "$home owner is $user."; fi
        printf '  %-24s mode=%s\n' "$home" "$mode"
        if [[ "$mode" =~ ^[0-7]+$ ]]; then
            if (( ((10#$mode / 10) % 10 & 2) || (10#$mode % 10 & 2) )); then
                warn_msg "$home is writable by group or other users (mode $mode)."
            else
                pass_msg "$home is not group/other writable."
            fi
        else
            warn_msg "Could not determine permissions for $home."
        fi
        path="$home/.ssh"
        if [[ -e "$path" ]]; then
            owner="$(stat -c '%U' -- "$path" 2>/dev/null || printf unknown)"
            mode="$(stat -c '%a' -- "$path" 2>/dev/null || printf unknown)"
            if [[ "$owner" != "$user" ]]; then warn_msg "$path owner=$owner expected=$user"; fi
            printf '  %-24s mode=%s owner=%s\n' "$path" "$mode" "$owner"
            if [[ -d "$path" && "$mode" =~ ^[0-7]+$ ]]; then
                if (( 10#$mode % 100 != 0 )); then
                    warn_msg "$path grants group/other permissions (mode $mode); restrict it, commonly to 700."
                else
                    pass_msg "$path has no group/other permissions."
                fi
            fi
            for path in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
                [[ -e "$path" ]] || continue
                owner="$(stat -c '%U' -- "$path" 2>/dev/null || printf unknown)"
                mode="$(stat -c '%a' -- "$path" 2>/dev/null || printf unknown)"
                if [[ "$owner" != "$user" ]] || find "$path" -maxdepth 0 -perm /077 -print -quit 2>/dev/null | grep -q .; then
                    warn_msg "Review SSH key file: $path owner=$owner mode=$mode"
                else
                    pass_msg "$path owner/mode look safe."
                fi
            done
        fi
    done < <(list_human_accounts)
}

account_remove_unauthorized() {
    local user confirm
    need_root || return 1
    while IFS=$'\t' read -r user _ _ _ _; do
        is_authorized_user "$user" && continue
        printf '\nUnauthorized human account: %s\n' "$user"
        printf 'Actions: [l]ock [d]elete [s]kip: '
        tty_read -r confirm || true
        case "$confirm" in
            l|L)
                passwd -l "$user" && info_msg "Locked $user."
                ;;
            d|D)
                printf 'Type the username exactly to delete the account and request removal of its home: '
                tty_read -r confirm || true
                if [[ "$confirm" == "$user" ]]; then
                    userdel -r "$user" && info_msg "Deleted $user and requested home removal."
                else
                    info_msg 'Deletion cancelled.'
                fi
                ;;
            *) info_msg 'Left unchanged.' ;;
        esac
    done < <(list_human_accounts)
}

account_remove_unauthorized_admin() {
    need_root || return 1
    local user group changed
    while IFS=$'\t' read -r user _ _ _ _; do
        is_admin_account "$user" || continue
        is_authorized_admin "$user" && continue
        changed=0
        printf '\nUnauthorized administrator: %s\n' "$user"
        for group in "${ADMIN_GROUPS[@]}"; do
            if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fxq "$group"; then
                if [[ "$group" == sudo || "$group" == admin || "$group" == wheel ]]; then
                    printf 'Remove %s from %s? [y/N]: ' "$user" "$group"
                    tty_read -r confirm || true
                    case "$confirm" in y|Y|yes|YES) gpasswd -d "$user" "$group" && changed=1 ;; esac
                fi
            fi
        done
        (( changed == 0 )) && info_msg "No administrator group removed from $user."
    done < <(list_human_accounts)
}

sudoers_audit() {
    section 'SUDOERS AUDIT'
    need_root || return 1
    local line file
    if have visudo; then
        visudo -c && pass_msg 'sudoers syntax is valid.' || warn_msg 'sudoers syntax check FAILED.'
    fi
    printf '\nPotential sudo privilege rules:\n'
    grep -RniE --exclude='*.bak' --exclude='*.backup' '(^|[[:space:]])(NOPASSWD:|ALL[[:space:]]*=\(ALL|sudo[[:space:]]+)' /etc/sudoers /etc/sudoers.d 2>/dev/null | while IFS= read -r line; do
        printf '  %s\n' "$line"
    done
    printf '\nSudoers file permissions:\n'
    for file in /etc/sudoers /etc/sudoers.d/*; do
        [[ -f "$file" ]] || continue
        stat -c '  %n owner=%U:%G mode=%A numeric=%a' -- "$file" 2>/dev/null || true
    done
    subsection 'NOPASSWD / suspicious broad rules'
    if grep -RniE 'NOPASSWD:[[:space:]]*ALL|ALL[[:space:]]*=\([^)]*\)[[:space:]]*ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null; then
        warn_msg 'Broad sudo rules were found. Review them against the scenario.'
    else
        pass_msg 'No obvious broad NOPASSWD/ALL rule found by this heuristic.'
    fi
    subsection 'Potential non-authorized sudo users'
    local user admin=0
    while IFS=$'\t' read -r user _ _ _ _; do
        if is_admin_account "$user" && ! is_authorized_admin "$user"; then
            warn_msg "$user has sudo/admin/wheel membership but is not an authorized administrator."
            admin=1
        fi
    done < <(list_human_accounts)
    (( admin == 0 )) && pass_msg 'No unauthorized human administrator found through group membership.'
}

###############################################################################
# Password policy
###############################################################################

password_policy_audit() {
    section 'PASSWORD POLICY AUDIT'
    local file
    for file in /etc/security/pwquality.conf /etc/pam.d/common-password /etc/login.defs; do
        [[ -f "$file" ]] && info_msg "$file exists." || warn_msg "$file is missing."
    done
    subsection 'pwquality.conf'
    if [[ -f /etc/security/pwquality.conf ]]; then
        grep -E '^[[:space:]]*(minlen|dcredit|ucredit|lcredit|ocredit|maxrepeat|maxsequence|difok)[[:space:]]*=' /etc/security/pwquality.conf 2>/dev/null || info_msg 'No selected pwquality settings found.'
        local key expected actual
        for key in minlen dcredit ocredit; do
            case "$key" in
                minlen) expected=10 ;;
                *) expected=-1 ;;
            esac
            actual="$(pwquality_value "$key")"
            [[ "$actual" == "$expected" ]] && pass_msg "pwquality $key=$actual is configured." || warn_msg "pwquality $key should be $expected (currently ${actual:-unset})."
        done
    else
        warn_msg 'Cannot verify required pwquality settings because pwquality.conf is missing.'
    fi
    subsection 'PAM pwquality enforcement'
    if grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' /etc/pam.d/common-password 2>/dev/null; then
        pass_msg 'pam_pwquality is referenced by common-password.'
        grep -n 'pam_pwquality' /etc/pam.d/common-password 2>/dev/null || true
    else
        warn_msg 'pam_pwquality is not visibly enforced in common-password.'
    fi
    subsection 'login.defs'
    grep -E '^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)[[:space:]]+' /etc/login.defs 2>/dev/null || true
    local max
    max="$(login_max_password_days)"
    if [[ "$max" =~ ^[0-9]+$ ]] && (( max <= DEFAULT_MAX_PASSWORD_DAYS )); then
        pass_msg "PASS_MAX_DAYS=$max meets the NOJE $DEFAULT_MAX_PASSWORD_DAYS-day baseline."
    else
        warn_msg "PASS_MAX_DAYS is missing or greater than the NOJE $DEFAULT_MAX_PASSWORD_DAYS-day baseline."
    fi
    subsection 'Existing human-account password age'
    if (( EUID != 0 )); then
        info_msg 'Run as root to verify each account password age.'
    else
        local user shadow_record max_age last_change
        while IFS=$'\t' read -r user _ _ _ _; do
            shadow_record="$(getent shadow "$user" 2>/dev/null)"
            max_age="$(awk -F: 'NR == 1 {print $5}' <<< "$shadow_record")"
            last_change="$(awk -F: 'NR == 1 {print $3}' <<< "$shadow_record")"
            if [[ "$max_age" =~ ^[0-9]+$ ]] && (( max_age <= DEFAULT_MAX_PASSWORD_DAYS )); then
                pass_msg "$user maximum password age is $max_age days."
            else
                warn_msg "$user maximum password age is ${max_age:-unknown}; expected at most $DEFAULT_MAX_PASSWORD_DAYS days."
            fi
            if [[ "$last_change" == 0 ]]; then
                review_msg "$user must change their password at next login."
            fi
        done < <(list_human_accounts)
    fi
}

password_policy_apply() {
    need_root || return 1
    local answer
    printf 'This will apply system-wide password quality rules, set defaults for new accounts, set a %s-day maximum age, and force existing human login accounts to change passwords at next login. Backups will be created. Continue? [y/N]: ' "$DEFAULT_MAX_PASSWORD_DAYS"
    tty_read -r answer || true
    case "$answer" in y|Y|yes|YES) ;; *) info_msg 'No password-policy changes made.'; return 0 ;; esac
    local changed_pam=0 failed_ages=0 user
    [[ -f /etc/security/pwquality.conf ]] || { warn_msg 'pwquality.conf missing; no changes made.'; return 1; }
    [[ -f /etc/pam.d/common-password ]] || { warn_msg 'common-password missing; no changes made.'; return 1; }
    [[ -f /etc/login.defs ]] || { warn_msg 'login.defs missing; no changes made.'; return 1; }
    have chage || { warn_msg 'chage is unavailable; no password-policy changes made.'; return 1; }
    if ! grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' /etc/pam.d/common-password &&
        ! grep -Eq '^[[:space:]]*password[[:space:]].*pam_unix\.so' /etc/pam.d/common-password; then
        warn_msg 'Could not find a pam_unix password line; no password-policy changes made.'
        return 1
    fi
    if ! find /lib /usr/lib -type f -name pam_pwquality.so -print -quit 2>/dev/null | grep -q .; then
        warn_msg 'pam_pwquality.so is unavailable; install libpam-pwquality before applying this policy.'
        return 1
    fi
    backup_file /etc/security/pwquality.conf || return 1
    backup_file /etc/pam.d/common-password || return 1
    backup_file /etc/login.defs || return 1

    local key value
    for key in minlen dcredit ocredit; do
        case "$key" in
            minlen) value=10 ;;
            *) value=-1 ;;
        esac
        if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" /etc/security/pwquality.conf; then
            sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" /etc/security/pwquality.conf || return 1
        else
            printf '%s = %s\n' "$key" "$value" >> /etc/security/pwquality.conf || return 1
        fi
    done
    if grep -Eq '^[[:space:]]*PASS_MAX_DAYS[[:space:]]+' /etc/login.defs; then
        sed -i -E "s|^[[:space:]]*PASS_MAX_DAYS[[:space:]]+.*|PASS_MAX_DAYS        ${DEFAULT_MAX_PASSWORD_DAYS}|" /etc/login.defs || return 1
    else
        printf 'PASS_MAX_DAYS        %s\n' "$DEFAULT_MAX_PASSWORD_DAYS" >> /etc/login.defs || return 1
    fi

    if ! grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' /etc/pam.d/common-password; then
        if grep -Eq '^[[:space:]]*password[[:space:]].*pam_unix\.so' /etc/pam.d/common-password; then
            sed -i '/^[[:space:]]*password[[:space:]].*pam_unix\.so/i password requisite pam_pwquality.so retry=3' /etc/pam.d/common-password || return 1
            changed_pam=1
        else
            warn_msg 'Could not find a pam_unix password line; PAM policy is not enforced.'
            return 1
        fi
    fi
    pass_msg 'System-wide password quality rules and new-account password-age default written.'
    (( changed_pam )) && pass_msg 'PAM password quality enforcement enabled for password changes.'

    while IFS=$'\t' read -r user _ _ _ _; do
        if chage -M "$DEFAULT_MAX_PASSWORD_DAYS" "$user"; then
            pass_msg "Set maximum password age for existing account $user."
        else
            warn_msg "Could not set maximum password age for existing account $user."
            failed_ages=$((failed_ages + 1))
        fi
        if chage -d 0 "$user"; then
            pass_msg "$user must change their password at next login."
        else
            warn_msg "Could not require a password change for existing account $user."
            failed_ages=$((failed_ages + 1))
        fi
    done < <(list_human_accounts)

    password_policy_audit
    (( failed_ages == 0 )) || return 1
}

###############################################################################
# SSH audit / remediation
###############################################################################

ssh_service_name() {
    if systemctl list-unit-files ssh.service --no-legend 2>/dev/null | grep -q '^ssh\.service'; then
        printf 'ssh'
    elif systemctl list-unit-files sshd.service --no-legend 2>/dev/null | grep -q '^sshd\.service'; then
        printf 'sshd'
    fi
}

ssh_audit_access_controls() {
    subsection 'SSH access-control directives'
    local file found=0
    for file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$file" ]] || continue
        if grep -Eq '^[[:space:]]*(AllowUsers|AllowGroups|DenyUsers|DenyGroups|Match)[[:space:]]+' "$file" 2>/dev/null; then
            found=1
            printf '  %s\n' "$file"
            grep -nE '^[[:space:]]*(AllowUsers|AllowGroups|DenyUsers|DenyGroups|Match)[[:space:]]+' "$file" 2>/dev/null | sed 's/^/    /'
        fi
    done
    if (( ! found )); then
        info_msg 'No explicit Allow/Deny/Match access-control directives found.'
    else
        info_msg 'Verify these directives do not block any authorized users.'
    fi
}

ssh_audit() {
    section 'SSH / OPENSSH AUDIT'
    local service effective root_login empty_pw password_auth pubkey maxtries root_state ciphers macs kex port
    service="$(ssh_service_name)"
    if [[ -z "$service" ]]; then
        warn_msg 'OpenSSH server service was not found.'
    else
        if systemctl is-active --quiet "$service"; then pass_msg "$service is active."; else warn_msg "$service is not active."; fi
        if systemctl is-enabled --quiet "$service"; then pass_msg "$service is enabled."; else warn_msg "$service is not enabled."; fi
    fi

    if ! have sshd; then
        warn_msg 'sshd binary is unavailable.'
        return 1
    fi
    effective="$(sshd -T 2>/dev/null)" || { warn_msg 'Unable to read effective sshd configuration.'; return 1; }
    root_login="$(awk '$1=="permitrootlogin"{print $2;exit}' <<< "$effective")"
    empty_pw="$(awk '$1=="permitemptypasswords"{print $2;exit}' <<< "$effective")"
    password_auth="$(awk '$1=="passwordauthentication"{print $2;exit}' <<< "$effective")"
    pubkey="$(awk '$1=="pubkeyauthentication"{print $2;exit}' <<< "$effective")"
    maxtries="$(awk '$1=="maxauthtries"{print $2;exit}' <<< "$effective")"
    ciphers="$(awk '$1=="ciphers"{$1="";sub(/^[[:space:]]+/,"");print;exit}' <<< "$effective")"
    macs="$(awk '$1=="macs"{$1="";sub(/^[[:space:]]+/,"");print;exit}' <<< "$effective")"
    kex="$(awk '$1=="kexalgorithms"{$1="";sub(/^[[:space:]]+/,"");print;exit}' <<< "$effective")"
    port="$(awk '$1=="port"{print $2;exit}' <<< "$effective")"
    root_state="$(passwd -S root 2>/dev/null | awk '{print $2}')"

    printf '\nEffective settings:\n'
    printf '  PermitRootLogin      %s\n' "${root_login:-unknown}"
    printf '  PermitEmptyPasswords %s\n' "${empty_pw:-unknown}"
    printf '  PasswordAuthentication %s\n' "${password_auth:-unknown}"
    printf '  PubkeyAuthentication %s\n' "${pubkey:-unknown}"
    printf '  MaxAuthTries         %s\n' "${maxtries:-unknown}"
    printf '  Port                 %s\n' "${port:-unknown}"
    printf '  Root password state  %s\n' "${root_state:-unknown}"

    [[ "$root_login" == no ]] && pass_msg 'SSH root login disabled.' || warn_msg 'SSH root login is not explicitly disabled.'
    [[ "$empty_pw" == no ]] && pass_msg 'SSH empty-password logins disabled.' || warn_msg 'SSH empty-password setting needs review.'
    [[ "$root_state" == L || "$root_state" == LK ]] && pass_msg 'Root password is locked.' || warn_msg 'Root password is not confirmed locked.'
    [[ "$pubkey" == yes ]] && pass_msg 'Public-key authentication is enabled.' || review_msg 'Public-key authentication is not enabled; this may be intentional because the scenario requires authorized users to remain able to SSH.'
    if [[ "$maxtries" =~ ^[0-9]+$ ]] && (( maxtries <= 4 )); then pass_msg 'MaxAuthTries is 4 or less.'; else warn_msg 'MaxAuthTries is above the NOJE baseline.'; fi
    [[ "$password_auth" == yes ]] && pass_msg 'Password authentication remains enabled for authorized-user availability.' || warn_msg 'PasswordAuthentication is disabled; verify authorized users can actually log in using their configured credentials/keys.'

    if grep -Eiq '(^|,)3des-cbc(,|$)|(^|,)aes(128|192|256)-cbc(,|$)' <<< "$ciphers"; then warn_msg 'Legacy CBC/3DES cipher detected.'; else pass_msg 'No reviewed CBC/3DES cipher detected.'; fi
    if grep -Eiq 'hmac-md5|hmac-sha1|umac-64' <<< "$macs"; then warn_msg 'Legacy MAC detected.'; else pass_msg 'No reviewed legacy MAC detected.'; fi
    if grep -Eiq 'group1-sha1|group14-sha1|group-exchange-sha1' <<< "$kex"; then warn_msg 'Legacy/SHA-1 key exchange detected.'; else pass_msg 'No reviewed SHA-1 key exchange detected.'; fi

    ssh_audit_access_controls

    subsection 'SSH key / config permissions'
    local file owner mode
    for file in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf /etc/ssh/ssh_host_*_key; do
        [[ -f "$file" ]] || continue
        owner="$(stat -c '%U' -- "$file" 2>/dev/null || printf unknown)"
        mode="$(stat -c '%a' -- "$file" 2>/dev/null || printf unknown)"
        if [[ "$file" == *_key ]]; then
            if [[ "$owner" == root ]] && ! find "$file" -maxdepth 0 -perm /077 -print -quit 2>/dev/null | grep -q .; then
                pass_msg "$file root-owned with restrictive mode $mode."
            else
                warn_msg "$file owner=$owner mode=$mode"
            fi
        else
            printf '  %s owner=%s mode=%s\n' "$file" "$owner" "$mode"
        fi
    done

    subsection 'Listening SSH sockets'
    if have ss; then
        ss -lntup 2>/dev/null | grep -E '(:22[[:space:]]|sshd)' || info_msg 'No obvious SSH listener was displayed by the socket query.'
    fi
}

ssh_apply_baseline() {
    need_root || return 1
    local service config dropin answer temp backup had=0
    service="$(ssh_service_name)"
    [[ -n "$service" ]] || { warn_msg 'SSH service not found.'; return 1; }
    systemctl is-active --quiet "$service" || { warn_msg 'SSH is not active; baseline will not be applied until it is active.'; return 1; }
    config='/etc/ssh/sshd_config'
    [[ -f "$config" ]] || return 1
    [[ -d /etc/ssh/sshd_config.d ]] || return 1
    grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]|$)' "$config" || { warn_msg 'Expected Ubuntu sshd_config.d Include was not found; aborting baseline.'; return 1; }
    dropin='/etc/ssh/sshd_config.d/00-noje-hardening.conf'
    printf 'Apply: PermitRootLogin no, PermitEmptyPasswords no, MaxAuthTries 4. PasswordAuthentication will not be disabled. Continue? [y/N]: '
    tty_read -r answer || true
    case "$answer" in y|Y|yes|YES) ;; *) info_msg 'SSH baseline unchanged.'; return 0 ;; esac
    if [[ -f "$dropin" ]]; then
        had=1
        backup="${dropin}.noje-backup-$(date +%Y%m%d%H%M%S)"
        cp -p -- "$dropin" "$backup" || return 1
        info_msg "Backed up existing drop-in to $backup"
    fi
    temp="$(mktemp /etc/ssh/sshd_config.d/.noje.XXXXXX)" || return 1
    printf 'PermitRootLogin no\nPermitEmptyPasswords no\nMaxAuthTries 4\n' > "$temp" || { rm -f "$temp"; return 1; }
    chmod 0644 "$temp"
    mv -f -- "$temp" "$dropin" || { rm -f "$temp"; return 1; }
    if sshd -t; then
        systemctl reload "$service" || {
            warn_msg 'SSH reload failed; attempting rollback.'
            if (( had )); then cp -p -- "$backup" "$dropin"; else rm -f -- "$dropin"; fi
            systemctl reload "$service" 2>/dev/null || true
            return 1
        }
        pass_msg 'SSH baseline applied and configuration validated.'
    else
        warn_msg 'sshd -t failed; rolling back.'
        if (( had )); then cp -p -- "$backup" "$dropin"; else rm -f -- "$dropin"; fi
        return 1
    fi
    ssh_audit
}

ssh_ensure_enabled() {
    need_root || return 1
    local service
    service="$(ssh_service_name)"
    [[ -n "$service" ]] || { warn_msg 'SSH service not found.'; return 1; }
    systemctl enable --now "$service" && pass_msg 'SSH enabled and active.' || warn_msg 'Could not enable/start SSH.'
}

###############################################################################
# Firewall / network audit
###############################################################################

firewall_audit() {
    section 'FIREWALL / NETWORK AUDIT'
    if have ufw; then
        ufw status verbose 2>/dev/null || true
        local state
        state="$(ufw status 2>/dev/null | head -n1)"
        [[ "$state" == 'Status: active' ]] && pass_msg 'UFW is active.' || warn_msg 'UFW is not reported active.'
    else
        warn_msg 'UFW command is not installed.'
    fi

    subsection 'Listening TCP/UDP sockets'
    if have ss; then
        ss -lntup 2>/dev/null || true
    else
        warn_msg 'ss command unavailable.'
    fi

    subsection 'Listening process review'
    if have ss; then
        local line
        while IFS= read -r line; do
            [[ "$line" == Netid* || -z "$line" ]] && continue
            review_msg "$line"
        done < <(ss -lntup 2>/dev/null)
    fi
}

firewall_enable_prompt() {
    need_root || return 1
    have ufw || { warn_msg 'UFW is not installed.'; return 1; }
    local answer
    printf 'Enable UFW now? This can affect SSH access. Because SSH is critical, review current rules first. [y/N]: '
    tty_read -r answer || true
    case "$answer" in
        y|Y|yes|YES)
            if ! ufw allow OpenSSH; then
                warn_msg 'Could not add the OpenSSH allow rule; UFW was not enabled.'
                return 1
            fi
            ufw --force enable && pass_msg 'UFW enabled with an OpenSSH allow rule.' || { warn_msg 'UFW enable failed.'; return 1; }
            ;;
        *) info_msg 'Firewall unchanged.' ;;
    esac
}

###############################################################################
# Services, timers, sockets, and centralized management tools
###############################################################################

service_is_review_candidate() {
    local name="${1%.service}"
    [[ "$name" =~ ^(telnet|rlogin|rsh|rexec|tftp|xinetd|vsftpd|proftpd|pure-ftpd|smbd|nmbd|rpcbind|nfs-server|snmpd|apache2|nginx|httpd|lighttpd|postfix|exim4|sendmail|dovecot)$ ]]
}

service_audit() {
    section 'SERVICE / TIMER / SOCKET AUDIT'
    need_root || return 1
    subsection 'Running services'
    local service reason
    while IFS= read -r service; do
        [[ -n "$service" ]] || continue
        if is_protected_scoreengine "$service" || [[ "$service" == ssh.service || "$service" == sshd.service ]]; then
            printf 'PROTECTED/CRITICAL: %s\n' "$service"
        elif service_is_review_candidate "$service"; then
            review_msg "$service is running and matches a service class that should be reviewed against the scenario."
        else
            printf 'RUNNING: %s\n' "$service"
        fi
    done < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}')

    subsection 'Enabled services (including stopped services)'
    while IFS= read -r service; do
        [[ -n "$service" ]] || continue
        service="${service%%[[:space:]]*}"
        [[ "$service" == *.service ]] || continue
        if service_is_review_candidate "$service"; then
            review_msg "Enabled review candidate: $service"
        fi
    done < <(systemctl list-unit-files --type=service --state=enabled --no-legend --plain 2>/dev/null | awk '{print $1}')

    subsection 'Timers'
    systemctl list-timers --all --no-legend --plain 2>/dev/null | sed 's/^/  /' || true

    subsection 'Listening sockets'
    systemctl list-sockets --all --no-legend --plain 2>/dev/null | sed 's/^/  /' || true

    subsection 'Centralized maintenance / polling agents'
    local packages units processes
    packages="$(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | grep -Ei "$MGMT_AGENT_PATTERNS" || true)"
    [[ -n "$packages" ]] && { warn_msg 'Potentially unauthorized management/monitoring packages:'; printf '%s\n' "$packages" | sed 's/^/  /'; } || pass_msg 'No known management-agent package matches found.'
    units="$(systemctl list-unit-files --no-legend --plain 2>/dev/null | grep -Ei "$MGMT_AGENT_PATTERNS" || true)"
    [[ -n "$units" ]] && { warn_msg 'Potentially unauthorized management/monitoring service units:'; printf '%s\n' "$units" | sed 's/^/  /'; } || pass_msg 'No known management-agent service matches found.'
    processes="$(pgrep -af "$MGMT_AGENT_PATTERNS" 2>/dev/null || true)"
    [[ -n "$processes" ]] && { warn_msg 'Potential management/monitoring processes found:'; printf '%s\n' "$processes" | sed 's/^/  /'; } || pass_msg 'No known management-agent process matches found.'
}

###############################################################################
# Persistence / cron / systemd / autostart
###############################################################################

persistence_audit() {
    section 'PERSISTENCE AUDIT'
    local file user line count=0

    subsection 'System persistence files'
    for file in /etc/crontab /etc/rc.local /etc/profile /etc/bash.bashrc; do
        [[ -f "$file" ]] || continue
        printf '\nFILE: %s\n' "$file"
        sed -n '1,220p' "$file" 2>/dev/null | sed 's/^/  /' || true
    done

    subsection 'Cron directories'
    for file in /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/*; do
        [[ -f "$file" ]] || continue
        printf 'CRON FILE: %s\n' "$file"
        grep -nEv '^[[:space:]]*($|#)' "$file" 2>/dev/null | sed 's/^/  /' || true
    done

    subsection 'Per-user crontabs'
    while IFS=$'\t' read -r user _ _ _ _; do
        if crontab -l -u "$user" 2>/dev/null | grep -qvE '^[[:space:]]*($|#)'; then
            warn_msg "Crontab exists for $user"
            crontab -l -u "$user" 2>/dev/null | sed 's/^/  /'
        fi
    done < <(list_human_accounts)

    subsection 'Systemd unit files outside packaged defaults'
    for file in /etc/systemd/system/*.service /etc/systemd/system/*.timer /etc/systemd/system/*.path /etc/systemd/system/*.socket; do
        [[ -f "$file" ]] || continue
        case "$file" in
            *scoreengine*) printf 'PROTECTED/REVIEW: %s\n' "$file" ;;
            *)
                count=$((count + 1))
                printf 'SYSTEMD UNIT: %s\n' "$file"
                grep -nE '^[[:space:]]*(ExecStart|ExecStartPre|ExecStartPost|User|Group|WorkingDirectory|Environment|EnvironmentFile|After|WantedBy)=' "$file" 2>/dev/null | sed 's/^/  /' || true
                ;;
        esac
    done
    (( count == 0 )) && info_msg 'No /etc/systemd/system custom units were listed by the simple glob.'

    subsection 'User autostart / user systemd persistence'
    while IFS=$'\t' read -r user _ _ home _; do
        for file in "$home/.config/autostart"/*.desktop "$home/.config/systemd/user"/*.service "$home/.config/systemd/user"/*.timer; do
            [[ -f "$file" ]] || continue
            printf 'USER PERSISTENCE [%s]: %s\n' "$user" "$file"
            grep -nE '^(Exec|TryExec|Name|Description|Type|WantedBy)=' "$file" 2>/dev/null | sed 's/^/  /' || true
        done
    done < <(list_human_accounts)

    subsection 'Suspicious execution patterns in startup files'
    local suspicious='curl|wget|base64[[:space:]]+-d|/dev/tcp|/dev/shm|/tmp/|nohup|socat.*exec|nc[[:space:]].*-e|python[0-9]*[[:space:]]+-c|bash[[:space:]]+-c|perl[[:space:]]+-e|ruby[[:space:]]+-e'
    while IFS= read -r -d '' file; do
        if grep -Eiq "$suspicious" "$file" 2>/dev/null; then
            review_msg "Suspicious execution/download pattern in $file"
            grep -Ein "$suspicious" "$file" 2>/dev/null | sed 's/^/  /' || true
        fi
    done < <(
        find /etc /home /root -xdev -type f \( \
            -name '.bashrc' -o -name '.profile' -o -name '.bash_profile' -o \
            -name '*.sh' -o -path '*/.config/autostart/*.desktop' -o \
            -path '*/.config/systemd/user/*.service' -o -path '/etc/cron.d/*' \
        \) -print0 2>/dev/null
    )
}

###############################################################################
# Bash configuration comparison
###############################################################################

bashrc_audit() {
    section 'BASH CONFIGURATION AUDIT'
    need_root || return 1
    local reference='/etc/skel/.bashrc' file different=0
    [[ -r "$reference" ]] || { warn_msg "Reference file missing: $reference"; return 1; }
    while IFS= read -r -d '' file; do
        if diff -q -- "$reference" "$file" >/dev/null 2>&1; then
            pass_msg "MATCH: $file"
        else
            different=$((different + 1))
            warn_msg "DIFFERS: $file"
            diff -u -- "$reference" "$file" || true
            if [[ -f "$file" ]]; then
                bash -n "$file" 2>&1 && pass_msg "Syntax OK: $file" || warn_msg "Syntax problem: $file"
            fi
        fi
    done < <(find /home /root -type f -name .bashrc -print0 2>/dev/null)
    printf '\nDifferent .bashrc files: %d\n' "$different"
    info_msg 'A difference is not proof of compromise; inspect custom lines before restoring.'
}

###############################################################################
# Temporary / suspicious files / processes / filesystem permissions
###############################################################################

suspicious_filename_audit() {
    section 'SUSPICIOUS FILE / TEMP EXECUTABLE AUDIT'
    local path
    while IFS= read -r -d '' path; do
        if is_protected_scoreengine "$path"; then
            printf 'PROTECTED: %s\n' "$path"
        else
            review_msg "$path"
            stat -c '  owner=%U:%G mode=%A size=%s modified=%y' -- "$path" 2>/dev/null || true
            have file && printf '  mime=%s\n' "$(file --brief --mime-type -- "$path" 2>/dev/null || printf unknown)"
        fi
    done < <(
        find /home /tmp /var/tmp /dev/shm -xdev \( \
            -iname '*keylog*' -o -iname '*rootkit*' -o -iname '*meterpreter*' -o \
            -iname '*payload*' -o -iname '*exploit*' -o -iname '*backdoor*' -o \
            -iname '*cryptominer*' -o -iname '*reverse-shell*' -o -iname '*bind-shell*' -o \
            -iname '*.elf' -o -iname '*.run' -o -iname '*.AppImage' \
        \) -print0 2>/dev/null
    )

    subsection 'Executable files in temporary locations'
    while IFS= read -r -d '' path; do
        if is_protected_scoreengine "$path"; then
            printf 'PROTECTED: %s\n' "$path"
        else
            review_msg "Executable in temporary path: $path"
            stat -c '  owner=%U:%G mode=%A size=%s modified=%y' -- "$path" 2>/dev/null || true
        fi
    done < <(find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 -print0 2>/dev/null)
}

process_audit() {
    section 'PROCESS / NETWORK PROCESS AUDIT'
    subsection 'Processes'
    ps auxww 2>/dev/null | sed -n '1,260p' || true

    subsection 'Processes with suspicious command names'
    pgrep -af 'keylog|meterpreter|reverse.?shell|bind.?shell|cryptominer|xmrig|socat|nc[[:space:]].*-e|ncat[[:space:]].*-e' 2>/dev/null || info_msg 'No obvious process-name matches.'

    subsection 'Listening sockets with owning processes'
    if have ss; then
        ss -lntup 2>/dev/null || true
    fi
}

suid_sgid_audit() {
    section 'SUID / SGID AUDIT'
    need_root || return 1
    local file count=0
    while IFS= read -r -d '' file; do
        count=$((count + 1))
        if is_protected_scoreengine "$file"; then
            printf 'PROTECTED/REVIEW: %s\n' "$file"
        else
            printf '%s\n' "$file"
        fi
    done < <(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)
    printf 'SUID/SGID file count: %d\n' "$count"
    info_msg 'Unexpected additions to a known-good baseline deserve manual review.'
}

world_writable_audit() {
    section 'WORLD-WRITABLE / DANGEROUS PERMISSIONS AUDIT'
    need_root || return 1
    subsection 'World-writable files in selected sensitive areas'
    find /etc /usr/local/bin /usr/local/sbin /opt /home /tmp /var/tmp /dev/shm -xdev -type f -perm -0002 -print 2>/dev/null | sed 's/^/REVIEW: /'
    subsection 'World-writable directories in selected sensitive areas'
    find /etc /usr/local/bin /usr/local/sbin /opt /home /tmp /var/tmp /dev/shm -xdev -type d -perm -0002 -print 2>/dev/null | sed 's/^/REVIEW: /'
    info_msg 'Sticky-bit directories such as /tmp are normal; review the surrounding mode/ownership before changing them.'
}

capability_audit() {
    section 'FILE CAPABILITY AUDIT'
    need_root || return 1
    if have getcap; then
        getcap -r /usr /bin /sbin /usr/local /opt /home 2>/dev/null | sed 's/^/REVIEW: /' || true
    else
        info_msg 'getcap is not installed.'
    fi
}

deleted_open_files_audit() {
    section 'DELETED-OPEN-FILE AUDIT'
    if have lsof; then
        lsof +L1 2>/dev/null | sed -n '1,240p' || true
    else
        info_msg 'lsof is not installed; deleted-open-file check skipped.'
    fi
}

###############################################################################
# Software / package / Snap / Flatpak / Chrome audit
###############################################################################

software_package_audit() {
    section 'SOFTWARE / PACKAGE AUDIT'
    subsection 'Known hacking/security-tool packages'
    local security_tools
    security_tools="$(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | grep -Ei "$SECURITY_TOOL_PATTERNS" || true)"
    if [[ -n "$security_tools" ]]; then
        warn_msg 'Potentially unauthorized security-tool packages found:'
        printf '%s\n' "$security_tools" | sed 's/^/  /'
    else
        pass_msg 'No known prohibited security-tool package names found.'
    fi

    subsection 'Snap packages'
    if have snap; then
        snap list 2>/dev/null || true
        info_msg 'Review every non-required Snap against the scenario. Some applications may need Ubuntu Software for removal.'
    else
        info_msg 'snap command not present.'
    fi

    subsection 'Flatpak packages'
    if have flatpak; then
        flatpak list 2>/dev/null || true
    else
        info_msg 'flatpak command not present.'
    fi

    subsection 'Portable / installer files in user homes'
    find /home -xdev -type f \( -iname '*.deb' -o -iname '*.run' -o -iname '*.AppImage' -o -iname '*.bin' -o -iname '*.msi' -o -iname '*.exe' \) -print 2>/dev/null | sed 's/^/REVIEW: /'

    subsection 'Management / polling packages'
    local mgmt
    mgmt="$(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | grep -Ei "$MGMT_AGENT_PATTERNS" || true)"
    [[ -n "$mgmt" ]] && { warn_msg 'Management/polling package matches:'; printf '%s\n' "$mgmt" | sed 's/^/  /'; } || pass_msg 'No known centralized maintenance/polling packages found.'
}

software_remove_security_tools() {
    need_root || return 1
    # This function already gets an explicit answer from the user; use -y for apt so
    # apt does not ask a second confirmation through the audit loop's stdin.
    local package answer
    while IFS= read -r package; do
        [[ -n "$package" ]] || continue
        is_protected_scoreengine "$package" && { info_msg "Protected: $package"; continue; }
        printf '\nPotentially prohibited package: %s\nPurge? [y/N]: ' "$package"
        tty_read -r answer || true
        case "$answer" in
            y|Y|yes|YES)
                apt-get purge -y "$package" || warn_msg "Could not purge $package"
                ;;
            *) info_msg "Kept $package" ;;
        esac
    done < <(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | grep -Ei "$SECURITY_TOOL_PATTERNS" || true)
}

software_snap_remove() {
    need_root || return 1
    have snap || { info_msg 'snap is not installed.'; return 0; }
    local snapname answer
    snap list 2>/dev/null | awk 'NR>1 {print $1}' | while IFS= read -r snapname; do
        [[ -n "$snapname" ]] || continue
        case "$snapname" in
            core|core20|core22|core24|snapd|bare|gnome-3-*|gtk-common-themes|mesa-*) continue ;;
        esac
        printf 'Review Snap %s. Remove? [y/N]: ' "$snapname"
        tty_read -r answer || true
        case "$answer" in y|Y|yes|YES) snap remove "$snapname" || warn_msg "Could not remove $snapname" ;; esac
    done
}

chrome_audit() {
    section 'GOOGLE CHROME AUDIT'
    local installed=NO
    dpkg-query -W -f='${Status}' google-chrome-stable 2>/dev/null | grep -q '^install ok installed$' && installed=YES
    printf 'google-chrome-stable installed: %s\n' "$installed"
    [[ "$installed" == YES ]] && pass_msg 'Google Chrome package is installed.' || warn_msg 'Google Chrome is not installed; the scenario requires latest stable Chrome.'
    [[ -f /usr/share/applications/google-chrome.desktop ]] && pass_msg 'Chrome desktop launcher exists.' || warn_msg 'Chrome desktop launcher missing.'

    if ! have xdg-mime; then
        warn_msg 'xdg-mime is unavailable; browser defaults cannot be fully checked.'
        return
    fi
    local account uid gid home shell mime browser mismatch
    for mime in x-scheme-handler/http x-scheme-handler/https text/html application/xhtml+xml; do
        printf '\nMIME: %s\n' "$mime"
        while IFS=: read -r account _ uid gid _ home shell; do
            [[ "$uid" =~ ^[0-9]+$ ]] && (( uid >= 1000 && uid != 65534 )) || continue
            [[ "$home" == /home/* && -d "$home" ]] || continue
            [[ "$shell" != */nologin && "$shell" != */false ]] || continue
            browser="$(runuser -u "$account" -- env HOME="$home" XDG_CONFIG_HOME="$home/.config" xdg-mime query default "$mime" 2>/dev/null || true)"
            printf '  %-18s %s\n' "$account" "${browser:-not set}"
            [[ "$browser" == google-chrome.desktop ]] || mismatch=1
        done < <(getent passwd)
    done
    : "${mismatch:=0}"
    (( mismatch == 0 )) && pass_msg 'All checked browser MIME defaults report Google Chrome.' || warn_msg 'At least one checked browser default is not google-chrome.desktop.'
}

chrome_set_defaults() {
    need_root || return 1
    have xdg-mime || { warn_msg 'xdg-mime is unavailable.'; return 1; }
    [[ -f /usr/share/applications/google-chrome.desktop ]] || { warn_msg 'Chrome desktop file is missing; install Chrome first.'; return 1; }
    local account uid gid home shell answer
    printf 'Set Chrome as default browser for all eligible /home users? [y/N]: '
    tty_read -r answer || true
    case "$answer" in y|Y|yes|YES) ;; *) info_msg 'Browser defaults unchanged.'; return 0 ;; esac
    while IFS=: read -r account _ uid gid _ home shell; do
        [[ "$uid" =~ ^[0-9]+$ ]] && (( uid >= 1000 && uid != 65534 )) || continue
        [[ "$home" == /home/* && -d "$home" ]] || continue
        [[ "$shell" != */nologin && "$shell" != */false ]] || continue
        if runuser -u "$account" -- env HOME="$home" XDG_CONFIG_HOME="$home/.config" xdg-mime default google-chrome.desktop x-scheme-handler/http x-scheme-handler/https text/html application/xhtml+xml; then
            pass_msg "Chrome defaults set for $account."
        else
            warn_msg "Could not set Chrome defaults for $account."
        fi
    done < <(getent passwd)
    chrome_audit
}

chrome_install() (
    need_root || return 1
    local distro_id=unknown distro_version=unknown arch temp key_file keyring repo_file expected_fpr
    . /etc/os-release
    distro_id="${ID:-unknown}"
    distro_version="${VERSION_ID:-unknown}"
    arch="$(dpkg --print-architecture 2>/dev/null || true)"
    [[ "$distro_id" == ubuntu && "$distro_version" == 24.04 ]] || { warn_msg 'Chrome installer is restricted to Ubuntu 24.04.'; return 1; }
    [[ "$arch" == amd64 ]] || { warn_msg "Chrome installer expects amd64; found $arch."; return 1; }
    if ! have curl || ! have gpg; then
        apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg || return 1
    fi
    temp="$(mktemp -d)" || return 1
    trap 'rm -rf -- "$temp"' EXIT
    key_file="$temp/google-linux-signing-key.pub"
    keyring='/etc/apt/keyrings/google-chrome.gpg'
    repo_file='/etc/apt/sources.list.d/google-chrome-noje.list'
    expected_fpr='EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796'
    curl -fsSL --retry 3 https://dl.google.com/linux/linux_signing_key.pub -o "$key_file" || return 1
    gpg --show-keys --with-colons "$key_file" 2>/dev/null | awk -F: -v expected="$expected_fpr" '$1=="fpr" && $10==expected {found=1} END{exit !found}' || { warn_msg 'Google signing-key fingerprint verification failed.'; return 1; }
    install -d -m 0755 /etc/apt/keyrings || return 1
    gpg --dearmor --output "$temp/google-chrome.gpg" "$key_file" || return 1
    install -m 0644 "$temp/google-chrome.gpg" "$keyring" || return 1
    if ! grep -RqsF -- 'https://dl.google.com/linux/chrome/deb' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
        printf 'deb [arch=amd64 signed-by=%s] https://dl.google.com/linux/chrome/deb stable main\n' "$keyring" > "$temp/google-chrome.list"
        install -m 0644 "$temp/google-chrome.list" "$repo_file" || return 1
    fi
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y google-chrome-stable xdg-utils || return 1
    pass_msg 'Google Chrome installed/updated from the official repository.'
)

###############################################################################
# Media / non-work files
###############################################################################

media_audit() {
    section 'NON-WORK MEDIA / ARCHIVE AUDIT'
    local file mime
    while IFS= read -r -d '' file; do
        is_protected_scoreengine "$file" && { printf 'PROTECTED: %s\n' "$file"; continue; }
        mime='unknown'
        have file && mime="$(file --brief --mime-type -- "$file" 2>/dev/null || printf unknown)"
        review_msg "$file"
        printf '  mime=%s owner=%s:%s mode=%s size=%s\n' "$mime" \
            "$(stat -c '%U' -- "$file" 2>/dev/null || printf unknown)" \
            "$(stat -c '%G' -- "$file" 2>/dev/null || printf unknown)" \
            "$(stat -c '%A' -- "$file" 2>/dev/null || printf unknown)" \
            "$(stat -c '%s' -- "$file" 2>/dev/null || printf unknown)"
    done < <(
        find /home -xdev -type f \( \
            -iname '*.avi' -o -iname '*.flac' -o -iname '*.gif' -o -iname '*.jpeg' -o -iname '*.jpg' -o \
            -iname '*.m4a' -o -iname '*.mkv' -o -iname '*.mov' -o -iname '*.mp3' -o -iname '*.mp4' -o \
            -iname '*.ogg' -o -iname '*.opus' -o -iname '*.wav' -o -iname '*.webm' -o -iname '*.wmv' -o \
            -iname '*.bmp' -o -iname '*.webp' -o -iname '*.zip' -o -iname '*.tar' -o -iname '*.tgz' -o \
            -iname '*.tar.gz' -o -iname '*.7z' -o -iname '*.rar' -o -iname '*.iso' -o -iname '*.dmg' -o \
            -iname '*.exe' -o -iname '*.msi' -o -iname '*.deb' \
        \) -print0 2>/dev/null
    )
    info_msg 'The scenario prohibits non-work-related media; review candidates rather than assuming every image/archive is automatically unauthorized.'
}

media_delete_prompt() {
    need_root || return 1
    local file answer
    while IFS= read -r -d '' file; do
        is_protected_scoreengine "$file" && continue
        printf '\nCandidate: %s\n' "$file"
        have file && printf 'Type: %s\n' "$(file --brief --mime-type -- "$file" 2>/dev/null || printf unknown)"
        printf 'Type DELETE to permanently remove this file: '
        tty_read -r answer || true
        if [[ "$answer" == DELETE ]]; then
            rm -f -- "$file" && [[ ! -e "$file" ]] && pass_msg "Deleted and verified: $file" || warn_msg "Could not verify deletion: $file"
        else
            info_msg 'Kept.'
        fi
    done < <(find /home -xdev -type f \( -iname '*.mp3' -o -iname '*.mp4' -o -iname '*.mkv' -o -iname '*.avi' -o -iname '*.mov' -o -iname '*.flac' -o -iname '*.wav' -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.png' -o -iname '*.gif' -o -iname '*.webp' -o -iname '*.webm' -o -iname '*.zip' -o -iname '*.7z' -o -iname '*.rar' -o -iname '*.iso' \) -print0 2>/dev/null)
}

###############################################################################
# ClamAV / malware scan
###############################################################################

clamav_scan() {
    section 'CLAMAV SCAN'
    if ! have clamscan; then
        info_msg 'ClamAV is not installed. No scanner was installed automatically.'
        return 1
    fi
    need_root || return 1
    info_msg 'Scanning /home /tmp /var/tmp /dev/shm. No files will be deleted automatically.'
    clamscan --recursive --infected --no-summary /home /tmp /var/tmp /dev/shm
    case $? in
        0) pass_msg 'ClamAV reported no detections.' ;;
        1) warn_msg 'ClamAV reported detections; inspect the scan output.' ;;
        *) warn_msg 'ClamAV scan completed with a nonstandard/error status.' ;;
    esac
}

###############################################################################
# Updates / packages
###############################################################################

updates_audit() {
    section 'UBUNTU UPDATE AUDIT'
    if ! have apt-get; then warn_msg 'apt-get unavailable.'; return 1; fi
    info_msg 'Read-only package simulation; package lists are not refreshed by this audit and may be stale.'
    local simulation count
    simulation="$(apt-get -s upgrade 2>&1)" || { warn_msg 'Package upgrade simulation failed.'; printf '%s\n' "$simulation"; return 1; }
    count="$(printf '%s\n' "$simulation" | awk '/^Inst /{n++} END{print n+0}')"
    printf 'Upgradeable packages: %s\n' "$count"
    (( count == 0 )) && pass_msg 'No upgradeable packages reported by apt simulation.' || warn_msg "$count package(s) can be upgraded."
}

updates_apply() {
    need_root || return 1
    # The toolkit asks for confirmation before entering apt; -y prevents a second
    # confirmation prompt from interfering with redirected/process-substitution stdin.
    local answer
    printf 'Run apt-get update && apt-get upgrade now? The README warns GNOME may crash briefly and recommends waiting for completion before rebooting. [y/N]: '
    tty_read -r answer || true
    case "$answer" in
        y|Y|yes|YES)
            apt-get update && apt-get upgrade -y
            ;;
        *) info_msg 'Updates not applied.' ;;
    esac
}

###############################################################################
# Integrity of critical system files
###############################################################################

critical_file_permissions() {
    section 'CRITICAL FILE PERMISSION AUDIT'
    need_root || return 1
    local file owner group mode expected_owner expected_group expected_mode
    for file in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config; do
        [[ -e "$file" ]] || continue
        owner="$(stat -c '%U' -- "$file" 2>/dev/null || printf unknown)"
        group="$(stat -c '%G' -- "$file" 2>/dev/null || printf unknown)"
        mode="$(stat -c '%a' -- "$file" 2>/dev/null || printf unknown)"
        expected_owner=root
        expected_group=root
        case "$file" in
            /etc/shadow|/etc/gshadow) expected_group=shadow; expected_mode=640 ;;
            /etc/passwd|/etc/group) expected_mode=644 ;;
            /etc/sudoers) expected_mode=440 ;;
            /etc/ssh/sshd_config) expected_mode=644 ;;
        esac
        printf '%-24s owner=%-10s group=%-10s mode=%s expected=%s:%s %s\n' \
            "$file" "$owner" "$group" "$mode" "$expected_owner" "$expected_group" "$expected_mode"
        if [[ "$owner" == "$expected_owner" && "$group" == "$expected_group" && "$mode" == "$expected_mode" ]]; then
            pass_msg "$file ownership and mode match the Ubuntu baseline."
        else
            warn_msg "$file differs from the expected Ubuntu baseline; review before changing it."
        fi
    done
    subsection 'World-writable critical files'
    find /etc -maxdepth 3 -type f -perm -0002 -print 2>/dev/null | sed 's/^/WARN: /'
}

###############################################################################
# Login manager / root / shell / display checks
###############################################################################

login_manager_audit() {
    section 'LOGIN MANAGER / ROOT LOGIN AUDIT'
    local manager=unknown root_shell uid0
    if [[ -L /etc/systemd/system/display-manager.service ]]; then
        manager="$(readlink -f /etc/systemd/system/display-manager.service)"
    elif systemctl list-unit-files display-manager.service --no-legend 2>/dev/null | grep -q display-manager.service; then
        manager="$(systemctl show -p FragmentPath --value display-manager.service 2>/dev/null || printf unknown)"
    fi
    printf 'Display manager: %s\n' "$manager"
    [[ "$manager" == */gdm3.service ]] && pass_msg 'GDM3 is the configured display manager.' || warn_msg 'Scenario requires the expected login manager; GDM3 was not confirmed.'

    root_shell="$(get_user_shell root)"
    printf 'Root shell: %s\n' "$root_shell"
    [[ -n "$root_shell" ]] && info_msg 'Root shell exists for administrative use; scenario specifically prohibits direct user logins as root.'

    uid0="$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)"
    printf 'UID 0 entries:\n%s\n' "$uid0"
    [[ "$(wc -l <<< "$uid0")" -eq 1 && "$uid0" == root ]] && pass_msg 'Only root has UID 0.' || warn_msg 'Additional UID 0 entries exist.'
}

###############################################################################
# Comprehensive audit
###############################################################################

full_audit() {
    check_forensics_questions
    system_overview
    login_manager_audit
    account_reconcile
    show_accounts
    account_audit_passwords
    account_home_permissions
    sudoers_audit
    password_policy_audit
    ssh_audit
    firewall_audit
    service_audit
    persistence_audit
    bashrc_audit
    suspicious_filename_audit
    process_audit
    suid_sgid_audit
    world_writable_audit
    capability_audit
    deleted_open_files_audit
    software_package_audit
    chrome_audit
    media_audit
    critical_file_permissions
    subsection 'SCOREENGINE'
    if pgrep -af scoreengine 2>/dev/null; then
        pass_msg 'scoreengine process detected; it was not modified.'
    else
        warn_msg 'scoreengine process was not detected by pgrep. Do not stop/disable/remove it.'
    fi
    if systemctl is-active --quiet scoreengine.service 2>/dev/null; then
        pass_msg 'scoreengine.service is active.'
    else
        review_msg 'scoreengine.service was not reported active; verify the actual competition service/process name before taking any action.'
    fi
}

###############################################################################
# Integrated audit + action flows
###############################################################################

integrated_accounts() {
    section 'ACCOUNTS / AUTHORIZATION / PASSWORDS - AUDIT + ACTION'
    account_reconcile
    show_accounts
    account_audit_passwords
    account_home_permissions

    printf '\nThe audit above is complete. Review findings before changing access.\n'
    printf 'Open the account action pass? This re-checks each candidate before changing it. [y/N]: '
    local answer
    tty_read -r answer || true
    case "$answer" in
        y|Y|yes|YES)
            account_remove_unauthorized
            account_remove_unauthorized_admin
            ;;
        *)
            info_msg 'No account changes made.'
            ;;
    esac
}

integrated_passwords() {
    section 'PASSWORD POLICY - AUDIT + ACTION'
    password_policy_audit
    local need_fix=0 age_unverified=0 answer max
    max="$(login_max_password_days)"
    if ! [[ "$max" =~ ^[0-9]+$ ]] || (( max > DEFAULT_MAX_PASSWORD_DAYS )); then
        need_fix=1
    fi
    if ! grep -Eq '^[[:space:]]*password[[:space:]].*pam_pwquality\.so' /etc/pam.d/common-password 2>/dev/null; then
        need_fix=1
    fi
    local key expected actual user max_age
    for key in minlen dcredit ocredit; do
        case "$key" in
            minlen) expected=10 ;;
            *) expected=-1 ;;
        esac
        actual="$(pwquality_value "$key")"
        [[ "$actual" == "$expected" ]] || need_fix=1
    done
    if (( EUID == 0 )); then
        while IFS=$'\t' read -r user _ _ _ _; do
            max_age="$(getent shadow "$user" 2>/dev/null | awk -F: 'NR == 1 {print $5}')"
            if ! [[ "$max_age" =~ ^[0-9]+$ ]] || (( max_age > DEFAULT_MAX_PASSWORD_DAYS )); then
                need_fix=1
            fi
        done < <(list_human_accounts)
    else
        age_unverified=1
    fi
    if (( need_fix )); then
        printf '\nPassword-policy findings were detected. Apply the NOJE baseline now? [y/N]: '
        tty_read -r answer || true
        case "$answer" in
            y|Y|yes|YES) password_policy_apply ;;
            *) info_msg 'Password policy unchanged.' ;;
        esac
    else
        if (( age_unverified )); then
            info_msg 'Password quality and new-account defaults appear configured; run as root to verify current-account ages.'
        else
            pass_msg 'Password-policy baseline appears to be present; no action needed.'
        fi
    fi
}

integrated_ssh() {
    section 'SSH - AUDIT + ACTION'
    ssh_audit
    local answer service
    service="$(ssh_service_name)"

    if [[ -z "$service" ]]; then
        printf '\nOpenSSH server is missing. Install openssh-server now? [y/N]: '
        tty_read -r answer || true
        case "$answer" in
            y|Y|yes|YES)
                need_root || return 1
                apt-get install -y openssh-server && service="$(ssh_service_name)"
                ;;
            *) info_msg 'SSH installation skipped.' ;;
        esac
    fi

    if [[ -n "$service" ]] && ! systemctl is-active --quiet "$service"; then
        printf '\nSSH is not active. Enable/start the critical SSH service now? [y/N]: '
        tty_read -r answer || true
        case "$answer" in y|Y|yes|YES) ssh_ensure_enabled ;; *) info_msg 'SSH left unchanged.' ;; esac
    fi

    printf '\nApply the NOJE SSH login-hardening baseline if warnings above warrant it? [y/N]: '
    tty_read -r answer || true
    case "$answer" in y|Y|yes|YES) ssh_apply_baseline ;; *) info_msg 'SSH configuration unchanged.' ;; esac
}

integrated_firewall() {
    section 'FIREWALL / NETWORK - AUDIT + ACTION'
    firewall_audit
    local answer state
    if have ufw; then
        state="$(ufw status 2>/dev/null | head -n1)"
        if [[ "$state" != 'Status: active' ]]; then
            printf '\nUFW is not active. Enable it with OpenSSH allowed? [y/N]: '
            tty_read -r answer || true
            case "$answer" in y|Y|yes|YES) firewall_enable_prompt ;; *) info_msg 'Firewall unchanged.' ;; esac
        else
            pass_msg 'UFW is already active; no firewall action needed.'
        fi
    else
        info_msg 'UFW is unavailable, so no firewall action was offered.'
    fi
}

integrated_services() {
    section 'SERVICES / TIMERS / POLLING AGENTS - AUDIT + ACTION'
    service_audit
    printf '\nOpen the service action pass? Each candidate is re-checked before disable/stop. [y/N]: '
    local answer
    tty_read -r answer || true
    case "$answer" in
        y|Y|yes|YES)
            service_action_pass
            ;;
        *) info_msg 'No service changes made.' ;;
    esac
}

integrated_software() {
    section 'SOFTWARE / CHROME - AUDIT + ACTION'
    software_package_audit
    chrome_audit

    local answer
    printf '\nOpen the prohibited-software action pass? This re-checks packages before purging. [y/N]: '
    tty_read -r answer || true
    case "$answer" in
        y|Y|yes|YES) software_remove_security_tools ;;
        *) info_msg 'Security-tool packages left unchanged.' ;;
    esac

    printf '\nReview non-core Snap packages for removal? [y/N]: '
    tty_read -r answer || true
    case "$answer" in
        y|Y|yes|YES) software_snap_remove ;;
        *) info_msg 'Snap packages left unchanged.' ;;
    esac

    local installed
    installed=NO
    dpkg-query -W -f='${Status}' google-chrome-stable 2>/dev/null | grep -q '^install ok installed$' && installed=YES
    if [[ "$installed" != YES ]]; then
        printf '\nChrome is required by the scenario. Install it now? [y/N]: '
        tty_read -r answer || true
        case "$answer" in y|Y|yes|YES) chrome_install ;; *) info_msg 'Chrome installation skipped.' ;; esac
    fi

    printf '\nSet Chrome as the default browser for all eligible users if needed? [y/N]: '
    tty_read -r answer || true
    case "$answer" in y|Y|yes|YES) chrome_set_defaults ;; *) info_msg 'Chrome defaults unchanged.' ;; esac
}

integrated_persistence() {
    section 'PERSISTENCE / BASH - AUDIT + ACTION'
    persistence_audit
    bashrc_audit
    printf '\nOpen the .bashrc restoration/action pass for files that differ from the baseline? [y/N]: '
    local answer
    tty_read -r answer || true
    case "$answer" in
        y|Y|yes|YES) bashrc_action_pass ;;
        *) info_msg 'No shell configuration files changed.' ;;
    esac
    info_msg 'Cron/systemd/autostart findings remain review-first because arbitrary persistence can be legitimate or business-critical.'
}

integrated_files_malware() {
    section 'MALWARE / FILES - AUDIT + ACTION'
    suspicious_filename_audit
    process_audit
    suid_sgid_audit
    world_writable_audit
    capability_audit
    deleted_open_files_audit
    media_audit

    local answer
    printf '\nOpen the media/file cleanup pass? Review each candidate before deletion. [y/N]: '
    tty_read -r answer || true
    case "$answer" in
        y|Y|yes|YES) media_delete_prompt ;;
        *) info_msg 'No media/files deleted.' ;;
    esac

    printf '\nRun ClamAV if available? [y/N]: '
    tty_read -r answer || true
    case "$answer" in y|Y|yes|YES) clamav_scan ;; *) info_msg 'ClamAV scan skipped.' ;; esac
}

integrated_updates() {
    section 'UBUNTU UPDATES - AUDIT + ACTION'
    updates_audit || return 1
    local count answer simulation
    simulation="$(apt-get -s upgrade 2>&1)" || { warn_msg 'Package upgrade simulation failed; no update action was offered.'; printf '%s\n' "$simulation"; return 1; }
    count="$(printf '%s\n' "$simulation" | awk '/^Inst /{n++} END{print n+0}')"
    if [[ "$count" =~ ^[0-9]+$ ]] && (( count > 0 )); then
        printf '\n%d package(s) can be upgraded. Apply updates now? [y/N]: ' "$count"
        tty_read -r answer || true
        case "$answer" in y|Y|yes|YES) updates_apply ;; *) info_msg 'Updates not applied.' ;; esac
    fi
}

integrated_critical_files() {
    section 'CRITICAL FILES - AUDIT'
    critical_file_permissions
    info_msg 'Critical-file findings are intentionally audit-only; expected modes can vary by installed software and scenario state.'
}

###############################################################################
# Service actions
###############################################################################

service_action_pass() {
    need_root || return 1
    local service reason answer
    while IFS= read -r service; do
        [[ -n "$service" ]] || continue
        service="${service%%[[:space:]]*}"
        [[ "$service" == *.service ]] || continue
        is_protected_scoreengine "$service" && continue
        reason=''
        if service_is_review_candidate "$service"; then
            reason='matches a commonly unnecessary server/remote service class'
        fi
        [[ -n "$reason" ]] || continue
        printf '\nRe-checking candidate: %s\n' "$service"
        systemctl is-active "$service" 2>/dev/null || true
        systemctl is-enabled "$service" 2>/dev/null || true
        systemctl cat "$service" --no-pager 2>/dev/null | sed -n '1,100p' || true
        printf 'Stop and disable %s (%s)? [y/N]: ' "$service" "$reason"
        tty_read -r answer || true
        case "$answer" in
            y|Y|yes|YES)
                systemctl disable --now "$service" && pass_msg "$service stopped/disabled." || warn_msg "Could not disable $service."
                ;;
            *) info_msg "$service left unchanged." ;;
        esac
    done < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}')
}

###############################################################################
# .bashrc actions
###############################################################################

bashrc_action_pass() {
    need_root || return 1
    local reference='/etc/skel/.bashrc' file answer owner mode user
    [[ -r "$reference" ]] || { warn_msg "Reference file missing: $reference"; return 1; }
    while IFS= read -r -d '' file; do
        diff -q -- "$reference" "$file" >/dev/null 2>&1 && continue
        printf '\nDIFFERS: %s\n' "$file"
        diff -u -- "$reference" "$file" || true
        user="$(stat -c '%U' -- "$file" 2>/dev/null || printf unknown)"
        printf 'Restore this file from /etc/skel/.bashrc? [y/N]: '
        tty_read -r answer || true
        case "$answer" in
            y|Y|yes|YES)
                backup_file "$file" || continue
                cp -p -- "$reference" "$file" || { warn_msg "Could not restore $file"; continue; }
                owner="$user"
                [[ "$owner" != unknown && "$owner" != root ]] || owner='root'
                if [[ "$owner" != root ]]; then
                    chown "$owner":"$owner" "$file" 2>/dev/null || true
                fi
                mode="$(stat -c '%a' -- "$file" 2>/dev/null || printf 644)"
                chmod "$mode" "$file" 2>/dev/null || true
                pass_msg "Restored $file from the baseline."
                ;;
            *) info_msg "Kept $file unchanged." ;;
        esac
    done < <(find /home /root -type f -name .bashrc -print0 2>/dev/null)
}

###############################################################################
# Integrated competition workflow
###############################################################################

integrated_menu() {
    local choice
    while true; do
        section 'NOJE - AUDIT + ACTION CENTER'
        cat <<'MENU'
This mode audits a category first, then offers actions based on what was found.
The full competition audit remains read-only; this mode is for guided remediation.

1) Accounts / authorization / passwords
2) Password policy
3) SSH / critical service
4) Firewall / network
5) Services / timers / polling agents
6) Software / hacking tools / Snap / Chrome
7) Persistence / .bashrc
8) Malware / files / permissions / media
9) Ubuntu updates
10) Critical system files
0) Back
MENU
        tty_read -r -p 'Select: ' choice || return
        case "$choice" in
            1) integrated_accounts ;;
            2) integrated_passwords ;;
            3) integrated_ssh ;;
            4) integrated_firewall ;;
            5) integrated_services ;;
            6) integrated_software ;;
            7) integrated_persistence ;;
            8) integrated_files_malware ;;
            9) integrated_updates ;;
            10) integrated_critical_files ;;
            0|q|Q) return ;;
            *) warn_msg 'Invalid selection.' ;;
        esac
        pause_screen
    done
}

###############################################################################
# Safe-ish remediation menu
###############################################################################

remediation_menu() {
    local choice
    while true; do
        section 'ACTION CENTER / ADVANCED REMEDIATION'
        cat <<'MENU'
These actions are also available through the guided Audit + Action Center.
Use this menu when you already know what you want to change.

1) Remove/lock unauthorized human accounts
2) Remove administrator-group access from unauthorized human admins
3) Apply password policy baseline
4) Apply SSH hardening baseline
5) Enable/start SSH
6) Enable UFW with OpenSSH allowed
7) Purge recognized hacking-tool packages
8) Remove selected non-core Snap packages
9) Install/update Google Chrome
10) Set Chrome as default browser for all eligible users
11) Apply Ubuntu package updates
12) Review/delete prohibited media candidates
0) Back
MENU
        tty_read -r -p 'Select: ' choice || return
        case "$choice" in
            1) account_remove_unauthorized ;;
            2) account_remove_unauthorized_admin ;;
            3) password_policy_apply ;;
            4) ssh_apply_baseline ;;
            5) ssh_ensure_enabled ;;
            6) firewall_enable_prompt ;;
            7) software_remove_security_tools ;;
            8) software_snap_remove ;;
            9) chrome_install ;;
            10) chrome_set_defaults ;;
            11) updates_apply ;;
            12) media_delete_prompt ;;
            0|q|Q) return ;;
            *) warn_msg 'Invalid selection.' ;;
        esac
        pause_screen
    done
}

###############################################################################
# Focused audit menu
###############################################################################

audit_menu() {
    local choice
    while true; do
        section 'AUDIT MENU'
        cat <<'MENU'
1) Full competition audit
2) Accounts / authorization / passwords
3) Sudoers audit
4) Password policy
5) SSH audit
6) Firewall / listening ports
7) Services / timers / centralized agents
8) Persistence / cron / systemd / autostart
9) .bashrc comparison
10) Processes / suspicious files / temp executables
11) SUID / SGID / world-writable / capabilities
12) Software / hacking tools / Snap / Flatpak
13) Chrome / browser defaults
14) Media / archives
15) System updates
16) Critical-file permissions
17) Forensics reminder
0) Back
MENU
        tty_read -r -p 'Select: ' choice || return
        case "$choice" in
            1) full_audit ;;
            2) account_reconcile; show_accounts; account_audit_passwords; account_home_permissions ;;
            3) sudoers_audit ;;
            4) password_policy_audit ;;
            5) ssh_audit ;;
            6) firewall_audit ;;
            7) service_audit ;;
            8) persistence_audit ;;
            9) bashrc_audit ;;
            10) suspicious_filename_audit; process_audit ;;
            11) suid_sgid_audit; world_writable_audit; capability_audit ;;
            12) software_package_audit ;;
            13) chrome_audit ;;
            14) media_audit ;;
            15) updates_audit ;;
            16) critical_file_permissions ;;
            17) check_forensics_questions ;;
            0|q|Q) return ;;
            *) warn_msg 'Invalid selection.' ;;
        esac
        pause_screen
    done
}

###############################################################################
# Main menu
###############################################################################

main_menu() {
    local choice
    while true; do
        section 'NOJE OKCUP ROUND 1 - UBUNTU 24.04 SUPER TOOLKIT'
        cat <<'MENU'
AUDIT
  1) Full competition audit
  2) Focused audit menu

AUDIT + ACTION
  3) Guided audit + remediation

REMEDIATION
  4) Action center / advanced remediation

QUICK CHECKS
  5) Accounts / authorization
  6) SSH / critical service
  7) Software / Chrome
  8) Malware / persistence / files
  9) Firewall / network

OTHER
  10) System overview
  11) Forensics reminder
  12) Scoreengine status
  0) Exit
MENU
        tty_read -r -p 'Select: ' choice || return
        case "$choice" in
            1) full_audit ;;
            2) audit_menu ;;
            3) integrated_menu ;;
            4) remediation_menu ;;
            5) account_reconcile; show_accounts; account_audit_passwords ;;
            6) ssh_audit ;;
            7) software_package_audit; chrome_audit ;;
            8) persistence_audit; bashrc_audit; suspicious_filename_audit; process_audit ;;
            9) firewall_audit ;;
            10) system_overview; login_manager_audit ;;
            11) check_forensics_questions ;;
            12)
                subsection 'SCOREENGINE'
                pgrep -af scoreengine 2>/dev/null || warn_msg 'scoreengine process not detected.'
                systemctl status scoreengine.service --no-pager 2>/dev/null || true
                info_msg 'This toolkit intentionally does not provide a stop/disable/delete action for scoreengine.'
                ;;
            0|q|Q) printf 'Exiting.\n'; return 0 ;;
            *) warn_msg 'Invalid selection.' ;;
        esac
        pause_screen
    done
}

###############################################################################
# Direct command shortcuts
###############################################################################

case "${1:-}" in
    --audit) full_audit ;;
    --accounts) account_reconcile; show_accounts; account_audit_passwords ;;
    --ssh) ssh_audit ;;
    --passwords) password_policy_audit ;;
    --services) service_audit ;;
    --software) software_package_audit; chrome_audit ;;
    --persistence) persistence_audit ;;
    --bashrc) bashrc_audit ;;
    --malware) suspicious_filename_audit; process_audit ;;
    --firewall) firewall_audit ;;
    --media) media_audit ;;
    --scoreengine)
        pgrep -af scoreengine 2>/dev/null || true
        systemctl status scoreengine.service --no-pager 2>/dev/null || true
        ;;
    --forensics) check_forensics_questions ;;
    --help|-h)
        cat <<'HELP'
NOJE OKCUP Round 1 Ubuntu 24.04 SUPER toolkit

Interactive:
  sudo bash NOJE_OKCUP_Round1_Ubuntu24_SUPER.txt

Quick commands:
  --audit        full competition audit
  --accounts     account/authorization/password audit
  --ssh          SSH audit
  --passwords    password policy audit
  --services     services/timers/management audit
  --software     software/hacking tools audit
  --persistence  persistence audit
  --bashrc       .bashrc comparison
  --malware      suspicious files/process audit
  --firewall     firewall/network audit
  --media        media/archive audit
  --scoreengine  scoreengine status only
  --forensics    Desktop forensics-file reminder
HELP
        ;;
    *) main_menu ;;
esac
