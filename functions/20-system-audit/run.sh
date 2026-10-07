#!/usr/bin/env bash

set -u

fail() {
	printf 'Error: %s\n' "$1" >&2
	return 1
}

service_name() {
	if systemctl list-unit-files --no-legend ssh.service 2>/dev/null | grep -q '^ssh\.service'; then
		printf 'ssh'
	elif systemctl list-unit-files --no-legend sshd.service 2>/dev/null | grep -q '^sshd\.service'; then
		printf 'sshd'
	else
		printf ''
	fi
}

check_platform() {
	local id version
	id='unknown'
	version='unknown'
	if [[ -r /etc/os-release ]]; then
		. /etc/os-release
		id="${ID:-unknown}"
		version="${VERSION_ID:-unknown}"
	fi

	printf 'Platform: %s %s\n' "$id" "$version"
	if [[ "$id" == 'ubuntu' && "$version" == '24.04' ]]; then
		printf 'PASS: Ubuntu 24.04 is installed.\n'
	else
		printf 'FAIL: This competition requires Ubuntu 24.04.\n'
	fi
}

check_ssh() {
	local service
	service="$(service_name)"
	if [[ -z "$service" ]]; then
		printf 'FAIL: openssh-server service was not found.\n'
		return
	fi

	if systemctl is-active --quiet "$service"; then
		printf 'PASS: SSH service %s is active.\n' "$service"
	else
		printf 'FAIL: SSH service %s is not active.\n' "$service"
	fi

	if systemctl is-enabled --quiet "$service"; then
		printf 'PASS: SSH service %s is enabled.\n' "$service"
	else
		printf 'FAIL: SSH service %s is not enabled.\n' "$service"
	fi
}

audit_ssh_key_permissions() {
	local key path owner mode account
	local -a private_host_keys=()
	local -a user_ssh_paths=()

	printf '\n--- SSH host private-key permissions ---\n'
	for key in /etc/ssh/ssh_host_*_key; do
		[[ -f "$key" ]] || continue
		private_host_keys+=("$key")
	done
	if ((${#private_host_keys[@]} == 0)); then
		printf 'WARN: No SSH host private keys were found.\n'
	else
		for key in "${private_host_keys[@]}"; do
			owner="$(stat -c '%U' -- "$key" 2>/dev/null || printf 'unknown')"
			mode="$(stat -c '%a' -- "$key" 2>/dev/null || printf 'unknown')"
			if [[ "$owner" == 'root' ]] && ! find "$key" -maxdepth 0 -perm /077 -print -quit 2>/dev/null | grep -q .; then
				printf 'PASS: %s is root-owned with no group/other permissions (mode %s).\n' "$key" "$mode"
			else
				printf 'WARN: Review host key owner/mode: %s (%s, mode %s).\n' "$key" "$owner" "$mode"
			fi
		done
	fi

	printf '\n--- User SSH directory/key permissions ---\n'
	for path in /home/*; do
		[[ -d "$path" ]] || continue
		account="${path##*/}"
		for key in "$path/.ssh" "$path/.ssh/authorized_keys" "$path/.ssh/authorized_keys2"; do
			[[ -e "$key" ]] || continue
			user_ssh_paths+=("$account|$key")
		done
	done
	if ((${#user_ssh_paths[@]} == 0)); then
		printf 'No user .ssh directories or authorized_keys files found under /home.\n'
		return
	fi
	for path in "${user_ssh_paths[@]}"; do
		IFS='|' read -r account key <<< "$path"
		owner="$(stat -c '%U' -- "$key" 2>/dev/null || printf 'unknown')"
		mode="$(stat -c '%a' -- "$key" 2>/dev/null || printf 'unknown')"
		if [[ "$owner" != "$account" ]] || find "$key" -maxdepth 0 -perm /077 -print -quit 2>/dev/null | grep -q .; then
			printf 'WARN: Review %s (%s, mode %s); recommended owner is %s, with no group/other access.\n' "$key" "$owner" "$mode" "$account"
		else
			printf 'PASS: %s has owner-only permissions (mode %s).\n' "$key" "$mode"
		fi
	done
}

audit_ssh_security() {
	local effective root_login empty_passwords password_auth pubkey_auth max_auth_tries
	local ciphers macs kex root_state

	if ! command -v sshd >/dev/null 2>&1; then
		printf 'OpenSSH server is not installed; SSH configuration cannot be audited.\n'
		return 1
	fi
	effective="$(sshd -T 2>/dev/null)" || {
		printf 'Could not read effective sshd configuration; run this audit as root and check sshd_config syntax.\n' >&2
		return 1
	}
	root_login="$(awk '$1 == "permitrootlogin" { print $2; exit }' <<< "$effective")"
	empty_passwords="$(awk '$1 == "permitemptypasswords" { print $2; exit }' <<< "$effective")"
	password_auth="$(awk '$1 == "passwordauthentication" { print $2; exit }' <<< "$effective")"
	pubkey_auth="$(awk '$1 == "pubkeyauthentication" { print $2; exit }' <<< "$effective")"
	max_auth_tries="$(awk '$1 == "maxauthtries" { print $2; exit }' <<< "$effective")"
	ciphers="$(awk '$1 == "ciphers" { $1 = ""; sub(/^[[:space:]]+/, ""); print; exit }' <<< "$effective")"
	macs="$(awk '$1 == "macs" { $1 = ""; sub(/^[[:space:]]+/, ""); print; exit }' <<< "$effective")"
	kex="$(awk '$1 == "kexalgorithms" { $1 = ""; sub(/^[[:space:]]+/, ""); print; exit }' <<< "$effective")"
	root_state="$(passwd -S root 2>/dev/null | awk '{ print $2 }')"

	printf '\n=== Effective SSH Security Settings ===\n'
	printf 'PermitRootLogin: %s\n' "${root_login:-unknown}"
	[[ "$root_login" == 'no' ]] && printf 'PASS: Root SSH login is disabled.\n' || printf 'WARN: Root SSH login is not fully disabled.\n'
	printf 'PermitEmptyPasswords: %s\n' "${empty_passwords:-unknown}"
	[[ "$empty_passwords" == 'no' ]] && printf 'PASS: Empty-password SSH login is disabled.\n' || printf 'WARN: Empty-password SSH login is not disabled.\n'
	printf 'Root account password state: %s\n' "${root_state:-unknown}"
	[[ "$root_state" == 'L' || "$root_state" == 'LK' ]] && printf 'PASS: Root account password is locked.\n' || printf 'WARN: Root account password is not confirmed locked.\n'
	printf 'PasswordAuthentication: %s (left unchanged to avoid locking out required users)\n' "${password_auth:-unknown}"
	printf 'PubkeyAuthentication: %s\n' "${pubkey_auth:-unknown}"
	[[ "$pubkey_auth" == 'yes' ]] && printf 'PASS: Public-key authentication is enabled.\n' || printf 'WARN: Public-key authentication is not enabled.\n'
	printf 'MaxAuthTries: %s\n' "${max_auth_tries:-unknown}"
	if [[ "$max_auth_tries" =~ ^[0-9]+$ ]] && ((max_auth_tries <= 4)); then
		printf 'PASS: MaxAuthTries is 4 or lower.\n'
	else
		printf 'WARN: Consider limiting MaxAuthTries to 4 after reviewing access requirements.\n'
	fi

	printf '\nEffective ciphers: %s\n' "${ciphers:-unknown}"
	if grep -Eiq '(^|,)(3des-cbc|aes(128|192|256)-cbc)(,|$)' <<< "$ciphers"; then
		printf 'WARN: A legacy CBC/3DES cipher is enabled.\n'
	else
		printf 'PASS: No CBC/3DES cipher from the review list is enabled.\n'
	fi
	printf 'Effective MACs: %s\n' "${macs:-unknown}"
	if grep -Eiq '(^|,)(hmac-md5(-96)?(-etm@openssh\.com)?|hmac-sha1(-96)?(-etm@openssh\.com)?|umac-64(@openssh\.com|-etm@openssh\.com)?)(,|$)' <<< "$macs"; then
		printf 'WARN: A legacy MAC from the review list is enabled.\n'
	else
		printf 'PASS: No MD5/SHA1/64-bit UMAC MAC from the review list is enabled.\n'
	fi
	printf 'Effective key exchanges: %s\n' "${kex:-unknown}"
	if grep -Eiq 'diffie-hellman-(group1-sha1|group14-sha1|group-exchange-sha1)' <<< "$kex"; then
		printf 'WARN: A SHA-1/legacy Diffie-Hellman key exchange is enabled.\n'
	else
		printf 'PASS: No SHA-1/legacy Diffie-Hellman group from the review list is enabled.\n'
	fi
	printf 'OpenSSH on Ubuntu 24.04 supports SSH protocol 2 only; no Protocol directive is needed.\n'
	audit_ssh_key_permissions
}

check_login_manager() {
	local manager
	manager='unknown'
	if [[ -L /etc/systemd/system/display-manager.service ]]; then
		manager="$(readlink -f /etc/systemd/system/display-manager.service)"
	fi
	printf 'Display manager: %s\n' "$manager"
	[[ "$manager" == */gdm3.service ]] && printf 'PASS: GDM3 is the active display manager.\n' || printf 'WARN: GDM3 is not confirmed as the display manager.\n'
}

check_updates() {
	local updates
	if ! command -v apt-get >/dev/null 2>&1; then
		printf 'WARN: apt-get is unavailable; package updates were not checked.\n'
		return
	fi

	updates="$(apt-get -s upgrade 2>/dev/null | awk '/^Inst / { count++ } END { print count + 0 }')"
	printf 'Upgradeable packages: %s\n' "$updates"
	[[ "$updates" == '0' ]] && printf 'PASS: No simulated package upgrades are pending.\n' || printf 'WARN: Package updates are pending.\n'
}

check_scoreengine() {
	local process service
	process="$(pgrep -af scoreengine 2>/dev/null || true)"
	service="$(systemctl is-active scoreengine.service 2>/dev/null || true)"
	if [[ -n "$process" || "$service" == 'active' ]]; then
		printf 'PASS: scoreengine appears to be running and was not modified.\n'
	else
		printf 'WARN: scoreengine was not detected; this script did not stop or change it.\n'
	fi
}

audit_system() {
	printf '\n=== System Security Review ===\n'
	check_platform
	printf '\n--- SSH ---\n'
	check_ssh
	audit_ssh_security
	printf '\n--- Login manager ---\n'
	check_login_manager
	printf '\n--- Package updates ---\n'
	check_updates
	printf '\n--- Competition process ---\n'
	check_scoreengine
}

apply_ssh_login_baseline() {
	local service config_dir config dropin backup temp effective root_login empty_passwords max_auth_tries answer had_dropin=0
	service="$(service_name)"
	config='/etc/ssh/sshd_config'
	config_dir='/etc/ssh/sshd_config.d'
	dropin="$config_dir/00-noje-hardening.conf"

	((EUID == 0)) || { printf 'Run this action as root.\n'; return 1; }
	[[ -n "$service" ]] || { printf 'SSH service was not found; no changes made.\n'; return 1; }
	systemctl is-active --quiet "$service" || { printf 'SSH is not active; no configuration change made.\n'; return 1; }
	[[ -f "$config" ]] || { printf '%s was not found.\n' "$config"; return 1; }
	[[ -d "$config_dir" ]] || { printf '%s was not found; no configuration change made.\n' "$config_dir"; return 1; }
	grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf([[:space:]]|$)' "$config" || {
		printf 'The Ubuntu SSH drop-in include was not found; no configuration change made.\n'
		return 1
	}

	printf "This disables root and empty-password SSH login and limits authentication attempts to four. Other users' password authentication is unchanged.\n"
	printf 'Continue? [y/N]: '
	IFS= read -r answer || true
	case "$answer" in
		y|Y|yes|YES) ;;
		*) printf 'SSH configuration was not changed.\n'; return 0 ;;
	esac

	if [[ -e "$dropin" ]]; then
		had_dropin=1
		backup="${dropin}.noje-backup-$(date +%Y%m%d%H%M%S)"
		cp -p "$dropin" "$backup" || { printf 'Could not back up %s.\n' "$dropin" >&2; return 1; }
	fi
	temp="$(mktemp "$config_dir/.noje-hardening.XXXXXX")" || { printf 'Could not create a temporary SSH config file.\n' >&2; return 1; }
	if ! printf 'PermitRootLogin no\nPermitEmptyPasswords no\nMaxAuthTries 4\n' > "$temp" || ! chmod 0644 "$temp" || ! mv -f -- "$temp" "$dropin"; then
		rm -f -- "$temp"
		printf 'Could not install the SSH hardening drop-in.\n' >&2
		return 1
	fi

	if ! sshd -t 2>/dev/null; then
		if ((had_dropin)); then cp -p "$backup" "$dropin"; else rm -f -- "$dropin"; fi
		printf 'sshd rejected the change; the previous drop-in state was restored.\n' >&2
		return 1
	fi
	effective="$(sshd -T 2>/dev/null)" || effective=''
	root_login="$(awk '$1 == "permitrootlogin" { print $2; exit }' <<< "$effective")"
	empty_passwords="$(awk '$1 == "permitemptypasswords" { print $2; exit }' <<< "$effective")"
	max_auth_tries="$(awk '$1 == "maxauthtries" { print $2; exit }' <<< "$effective")"
	if [[ "$root_login" != 'no' || "$empty_passwords" != 'no' || "$max_auth_tries" != '4' ]]; then
		if ((had_dropin)); then cp -p "$backup" "$dropin"; else rm -f -- "$dropin"; fi
		printf 'Requested values did not become effective; previous drop-in state was restored. Check earlier SSH includes.\n' >&2
		return 1
	fi

	if ! systemctl reload "$service"; then
		if ((had_dropin)); then cp -p "$backup" "$dropin"; else rm -f -- "$dropin"; fi
		systemctl reload "$service" 2>/dev/null || true
		printf 'SSH reload failed; the previous drop-in state was restored.\n' >&2
		return 1
	fi
	printf 'SSH login baseline applied; service %s was reloaded and remains active.\n' "$service"
	if ((had_dropin)); then
		printf 'Previous drop-in backup: %s\n' "$backup"
	fi
	return 0
}

ensure_ssh_enabled() {
	local service
	service="$(service_name)"
	[[ -n "$service" ]] || { printf 'SSH service was not found.\n'; return 1; }
	((EUID == 0)) || { printf 'Run this action as root.\n'; return 1; }
	systemctl enable --now "$service" || return 1
	printf 'SSH service %s is enabled and active.\n' "$service"
}

service_review_reason() {
	local service="${1%.service}"
	case "$service" in
		telnet*|rsh*|rexec*|tftp*|xinetd)
			printf 'legacy remote-access or inetd service'
			;;
		vsftpd|proftpd|pure-ftpd*|wu-ftpd*)
			printf 'FTP server'
			;;
		smbd|nmbd|samba)
			printf 'Samba file-sharing service'
			;;
		rpcbind|nfs-server|nfs-kernel-server|nfs-mountd|snmpd)
			printf 'network filesystem or management service'
			;;
		apache2|nginx|httpd|lighttpd)
			printf 'web server'
			;;
		postfix|exim4|sendmail|dovecot)
			printf 'mail service'
			;;
		*)
			return 1
			;;
	esac
}

is_protected_service() {
	local service="${1%.service}"
	[[ "$service" == 'ssh' || "$service" == 'sshd' || "$service" == *scoreengine* ]]
}

audit_running_services() {
	local service reason answer service_listing
	local -a running_services=()

	((EUID == 0)) || { printf 'Run this audit as root so service state and remediation can be checked.\n'; return 1; }
	command -v systemctl >/dev/null 2>&1 || { printf 'systemctl is unavailable.\n'; return 1; }
	service_listing="$(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null)" || {
		printf 'Could not list running system services.\n' >&2
		return 1
	}

	while IFS= read -r service; do
		[[ -n "$service" ]] && running_services+=("$service")
	done < <(printf '%s\n' "$service_listing" | awk 'NF { print $1 }')

	printf '\n=== Running System Services ===\n'
	if ((${#running_services[@]} == 0)); then
		printf 'No running system services were found.\n'
		return 0
	fi

	for service in "${running_services[@]}"; do
		if is_protected_service "$service"; then
			printf 'PROTECTED: %s (never stopped by this audit)\n' "$service"
		elif reason="$(service_review_reason "$service")"; then
			printf 'REVIEW: %s (%s; verify it is not required)\n' "$service" "$reason"
		else
			printf 'RUNNING: %s (review manually if unexpected)\n' "$service"
		fi
	done

	printf '\nKnown candidates are not automatically unsafe; confirm they are unnecessary before disabling them.\n'
	for service in "${running_services[@]}"; do
		is_protected_service "$service" && continue
		reason="$(service_review_reason "$service")" || continue
		printf '\nDisable and stop %s (%s)? [y/N]: ' "$service" "$reason"
		IFS= read -r answer || true
		case "$answer" in
			y|Y|yes|YES)
				if systemctl disable --now "$service"; then
					printf 'Disabled and stopped %s.\n' "$service"
				else
					printf 'Could not disable/stop %s; check its systemd unit and dependencies.\n' "$service" >&2
				fi
				;;
			*)
				printf 'Left %s unchanged.\n' "$service"
				;;
		esac
	done
}

if ((EUID != 0)); then
	printf 'Review mode: some checks require root for complete results.\n'
fi

while true; do
	printf '\n=== System Security Review ===\n'
	printf '1) Run system audit\n'
	printf '2) Apply SSH login baseline\n'
	printf '3) Ensure SSH is enabled and active\n'
	printf '4) Audit running services and review candidates\n'
	printf '5) Run detailed SSH security audit\n'
	printf '0) Back\n'
	printf 'Select an option: '
	IFS= read -r choice || break

	case "$choice" in
		1) audit_system ;;
		2) apply_ssh_login_baseline ;;
		3) ensure_ssh_enabled ;;
		4) audit_running_services ;;
		5) audit_ssh_security ;;
		0|q|Q) break ;;
		*) printf 'Invalid selection.\n' ;;
	esac
	printf '\nPress Enter to return to the system security menu...'
	IFS= read -r _ || true
done
