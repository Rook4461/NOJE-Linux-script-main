#!/usr/bin/env bash

set -u

is_protected_item() {
	[[ "${1,,}" == *scoreengine* ]]
}

list_suspicious_packages() {
	dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | grep -Ei 'aircrack|burpsuite|hashcat|hydra|john|metasploit|ncat|netcat|nikto|nmap|scapy|sqlmap|wireshark|zenmap' || true
}

review_suspicious_packages() {
	local package answer
	local -a packages=()
	while IFS= read -r package; do
		[[ -n "$package" ]] || continue
		packages+=("$package")
	done < <(list_suspicious_packages)

	printf '\n=== Potentially Unauthorized Security Tools ===\n'
	if ((${#packages[@]} == 0)); then
		printf 'No known tool packages were detected.\n'
		return
	fi

	for package in "${packages[@]}"; do
		if is_protected_item "$package"; then
			printf 'Protected and skipped: %s\n' "$package"
			continue
		fi

		printf 'Found package: %s\n' "$package"
		printf 'Purge %s? [y/N]: ' "$package"
		IFS= read -r answer || true
		case "$answer" in
			y|Y|yes|YES)
				if apt-get purge "$package"; then
					printf 'Removed %s.\n' "$package"
				else
					printf 'Unable to remove %s.\n' "$package" >&2
				fi
				;;
			*)
				printf 'Kept %s.\n' "$package"
				;;
		esac
	done
}

check_chrome() {
	local installed default_browser
	installed='no'
	default_browser='unknown'

	if command -v google-chrome >/dev/null 2>&1 || dpkg-query -W google-chrome-stable >/dev/null 2>&1; then
		installed='yes'
	fi
	if command -v xdg-settings >/dev/null 2>&1; then
		default_browser="$(xdg-settings get default-web-browser 2>/dev/null || true)"
	fi

	printf '\n=== Google Chrome ===\n'
	printf 'Installed: %s\n' "$installed"
	printf 'Default browser: %s\n' "$default_browser"
	[[ "$installed" == 'yes' ]] || printf 'WARN: google-chrome-stable is not installed.\n'
	[[ "$default_browser" == 'google-chrome.desktop' ]] || printf 'WARN: Google Chrome is not confirmed as the default browser for this user.\n'
}

set_chrome_default() {
	command -v xdg-settings >/dev/null 2>&1 || { printf 'xdg-settings is unavailable.\n'; return 1; }
	command -v google-chrome >/dev/null 2>&1 || { printf 'Google Chrome is not installed.\n'; return 1; }
	xdg-settings set default-web-browser google-chrome.desktop
	printf 'Google Chrome is now the default browser for the current desktop user.\n'
}

update_packages() {
	local answer
	command -v apt-get >/dev/null 2>&1 || { printf 'apt-get is unavailable.\n'; return 1; }
	printf 'Package updates can restart services and may temporarily affect GNOME.\n'
	printf 'Run apt-get update and upgrade now? [y/N]: '
	IFS= read -r answer || true
	case "$answer" in
		y|Y|yes|YES)
			apt-get update && apt-get upgrade
			;;
		*)
			printf 'Package update cancelled.\n'
			;;
	esac
}

audit_software() {
	printf '\n=== Software Review ===\n'
	if command -v dpkg-query >/dev/null 2>&1; then
		printf 'Installed package count: '
		dpkg-query -W -f='${binary:Package}\n' 2>/dev/null | wc -l
	else
		printf 'dpkg-query is unavailable; package inventory was not collected.\n'
	fi
	review_suspicious_packages
	check_chrome
}

((EUID == 0)) || printf 'Review mode: removal and package updates require root.\n'

while true; do
	printf '\n=== Software Review ===\n'
	printf '1) Audit installed software\n'
	printf '2) Review and remove suspicious tools\n'
	printf '3) Check Google Chrome/default browser\n'
	printf '4) Set Google Chrome as default browser\n'
	printf '5) Update Ubuntu packages\n'
	printf '0) Back\n'
	printf 'Select an option: '
	IFS= read -r choice || break

	case "$choice" in
		1) audit_software ;;
		2) ((EUID == 0)) && review_suspicious_packages || printf 'Run this action as root.\n' ;;
		3) check_chrome ;;
		4) set_chrome_default ;;
		5) ((EUID == 0)) && update_packages || printf 'Run this action as root.\n' ;;
		0|q|Q) break ;;
		*) printf 'Invalid selection.\n' ;;
	esac
	printf '\nPress Enter to return to the software review menu...'
	IFS= read -r _ || true
done
