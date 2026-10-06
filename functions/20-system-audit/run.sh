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

if ((EUID != 0)); then
	printf 'Review mode: some checks require root for complete results.\n'
fi

while true; do
	printf '\n=== System Security Review ===\n'
	printf '1) Run system audit\n'
	printf '2) Disable root SSH login\n'
	printf '3) Ensure SSH is enabled and active\n'
	printf '0) Back\n'
	printf 'Select an option: '
	IFS= read -r choice || break

	case "$choice" in
		1) audit_system ;;
		2) disable_root_ssh ;;
		3) ensure_ssh_enabled ;;
		0|q|Q) break ;;
		*) printf 'Invalid selection.\n' ;;
	esac
	printf '\nPress Enter to return to the system security menu...'
	IFS= read -r _ || true
done
