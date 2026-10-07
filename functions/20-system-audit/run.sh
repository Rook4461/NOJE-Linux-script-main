#!/usr/bin/env bash

set -u

fail() {
	printf 'Error: %s\n' "$1" >&2
	return 1
}

service_name() {
	if systemctl list-unit-files ssh.service >/dev/null 2>&1; then
		printf 'ssh'
	elif systemctl list-unit-files sshd.service >/dev/null 2>&1; then
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

check_root_login() {
	local permit_root_login root_state
	permit_root_login='unknown'
	root_state='unknown'

	if command -v sshd >/dev/null 2>&1; then
		permit_root_login="$(sshd -T 2>/dev/null | awk '$1 == "permitrootlogin" { print $2; exit }')"
	fi
	root_state="$(passwd -S root 2>/dev/null | awk '{ print $2 }')"

	printf 'SSH PermitRootLogin: %s\n' "${permit_root_login:-unknown}"
	printf 'Root password state: %s\n' "${root_state:-unknown}"
	[[ "$permit_root_login" == 'no' ]] && printf 'PASS: Root SSH login is disabled.\n' || printf 'WARN: Root SSH login is not confirmed disabled.\n'
	[[ "$root_state" == 'L' || "$root_state" == 'LK' ]] && printf 'PASS: Root password is locked.\n' || printf 'WARN: Root password is not confirmed locked.\n'
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
	check_root_login
	printf '\n--- Login manager ---\n'
	check_login_manager
	printf '\n--- Package updates ---\n'
	check_updates
	printf '\n--- Competition process ---\n'
	check_scoreengine
}

disable_root_ssh() {
	local service backup config
	service="$(service_name)"
	config='/etc/ssh/sshd_config'

	((EUID == 0)) || { printf 'Run this action as root.\n'; return 1; }
	[[ -n "$service" ]] || { printf 'SSH service was not found; no changes made.\n'; return 1; }
	systemctl is-active --quiet "$service" || { printf 'SSH is not active; no configuration change made.\n'; return 1; }
	[[ -f "$config" ]] || { printf '%s was not found.\n' "$config"; return 1; }

	backup="${config}.noje-backup-$(date +%Y%m%d%H%M%S)"
	cp -p "$config" "$backup" || return 1
	if grep -Eq '^[[:space:]]*#?[[:space:]]*PermitRootLogin[[:space:]]+' "$config"; then
		sed -i -E 's|^[[:space:]]*#?[[:space:]]*PermitRootLogin[[:space:]]+.*|PermitRootLogin no|' "$config"
	else
		printf '\nPermitRootLogin no\n' >> "$config"
	fi

	if sshd -t 2>/dev/null; then
		systemctl reload "$service"
		printf 'Root SSH login disabled. SSH remained active. Backup: %s\n' "$backup"
	else
		cp -p "$backup" "$config"
		printf 'sshd rejected the change; configuration was restored.\n'
		return 1
	fi
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
	printf '2) Disable root SSH login\n'
	printf '3) Ensure SSH is enabled and active\n'
	printf '4) Audit running services and review candidates\n'
	printf '0) Back\n'
	printf 'Select an option: '
	IFS= read -r choice || break

	case "$choice" in
		1) audit_system ;;
		2) disable_root_ssh ;;
		3) ensure_ssh_enabled ;;
		4) audit_running_services ;;
		0|q|Q) break ;;
		*) printf 'Invalid selection.\n' ;;
	esac
	printf '\nPress Enter to return to the system security menu...'
	IFS= read -r _ || true
done
