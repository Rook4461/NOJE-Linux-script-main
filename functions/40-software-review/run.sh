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
	local answer
	((EUID == 0)) || { printf 'Run this action as root.\n'; return 1; }
	printf 'This installs Google Chrome system-wide and changes browser defaults for existing interactive accounts under /home.\n'
	printf 'Continue? [y/N]: '
	IFS= read -r answer || true
	case "$answer" in
		y|Y|yes|YES)
			if ! dpkg-query -W -f='${Status}' google-chrome-stable 2>/dev/null | grep -q '^install ok installed$'; then
				install_google_chrome_systemwide || return 1
			else
				printf 'Google Chrome is already installed system-wide.\n'
			fi
			set_chrome_defaults_for_users
			;;
		*)
			printf 'Chrome installation/default changes cancelled.\n'
			;;
	esac
}

install_google_chrome_systemwide() (
	local distro_id='unknown' distro_version='unknown' architecture temp_dir key_file keyring repo_url repo_file
	local google_key_fingerprint='EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796'

	((EUID == 0)) || { printf 'Run this action as root.\n' >&2; return 1; }
	[[ -r /etc/os-release ]] || { printf 'Cannot identify the operating system.\n' >&2; return 1; }
	. /etc/os-release
	distro_id="${ID:-unknown}"
	distro_version="${VERSION_ID:-unknown}"
	[[ "$distro_id" == 'ubuntu' && "$distro_version" == '24.04' ]] || {
		printf 'Chrome setup supports Ubuntu 24.04 only; found %s %s.\n' "$distro_id" "$distro_version" >&2
		return 1
	}

	architecture="$(dpkg --print-architecture)"
	[[ "$architecture" == 'amd64' ]] || {
		printf 'Google Chrome setup requires amd64; found %s.\n' "$architecture" >&2
		return 1
	}

	command -v apt-get >/dev/null 2>&1 || { printf 'apt-get is unavailable.\n' >&2; return 1; }
	if ! command -v gpg >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
		apt-get update || return 1
		DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl gnupg || return 1
	fi

	temp_dir="$(mktemp -d)" || { printf 'Could not create a temporary directory.\n' >&2; return 1; }
	trap 'rm -rf -- "$temp_dir"' EXIT
	key_file="$temp_dir/google-linux-signing-key.pub"
	keyring='/etc/apt/keyrings/google-chrome.gpg'
	repo_url='https://dl.google.com/linux/chrome/deb'
	repo_file='/etc/apt/sources.list.d/google-chrome-noje.list'

	if ! curl -fsSL --retry 3 'https://dl.google.com/linux/linux_signing_key.pub' -o "$key_file"; then
		printf "Could not download Google's Linux signing key.\n" >&2
		return 1
	fi
	if ! gpg --show-keys --with-colons "$key_file" 2>/dev/null | awk -F: -v expected="$google_key_fingerprint" '$1 == "fpr" && $10 == expected { found = 1 } END { exit !found }'; then
		printf 'Google signing-key fingerprint verification failed; Chrome was not installed.\n' >&2
		return 1
	fi

	install -d -m 0755 /etc/apt/keyrings || return 1
	if ! gpg --dearmor --output "$temp_dir/google-chrome.gpg" "$key_file"; then
		printf "Could not prepare Google's APT signing key.\n" >&2
		return 1
	fi
	install -m 0644 "$temp_dir/google-chrome.gpg" "$keyring" || return 1

	if ! grep -RqsF -- "$repo_url" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null; then
		printf 'deb [arch=amd64 signed-by=%s] %s stable main\n' "$keyring" "$repo_url" > "$temp_dir/google-chrome.list" || return 1
		install -m 0644 "$temp_dir/google-chrome.list" "$repo_file" || return 1
	fi

	apt-get update || return 1
	DEBIAN_FRONTEND=noninteractive apt-get install -y google-chrome-stable xdg-utils || return 1
	command -v google-chrome-stable >/dev/null 2>&1 || {
		printf 'Package installation completed, but google-chrome-stable was not found.\n' >&2
		return 1
	}
	[[ -f /usr/share/applications/google-chrome.desktop ]] || {
		printf 'Chrome desktop launcher was not found; browser defaults were not changed.\n' >&2
		return 1
	}
	printf "Google Chrome is installed system-wide from Google's signed APT repository.\n"
)

set_chrome_defaults_for_users() {
	local account uid gid home shell config_dir failures=0 configured=0
	command -v runuser >/dev/null 2>&1 || { printf 'runuser is unavailable.\n' >&2; return 1; }
	command -v xdg-mime >/dev/null 2>&1 || { printf 'xdg-mime is unavailable.\n' >&2; return 1; }

	while IFS=: read -r account _ uid gid _ home shell; do
		[[ "$uid" =~ ^[0-9]+$ ]] || continue
		((uid >= 1000 && uid != 65534)) || continue
		[[ "$home" == /home/* && -d "$home" ]] || continue
		[[ "$shell" != */nologin && "$shell" != */false ]] || continue

		config_dir="$home/.config"
		if [[ ! -d "$config_dir" ]] && ! install -d -o "$uid" -g "$gid" -m 0755 "$config_dir"; then
			printf 'Could not create %s for %s.\n' "$config_dir" "$account" >&2
			failures=$((failures + 1))
			continue
		fi

		if runuser -u "$account" -- env HOME="$home" XDG_CONFIG_HOME="$config_dir" xdg-mime default google-chrome.desktop x-scheme-handler/http x-scheme-handler/https text/html application/xhtml+xml; then
			printf 'Google Chrome set as default for %s.\n' "$account"
			configured=$((configured + 1))
		else
			printf 'Could not set Google Chrome as default for %s.\n' "$account" >&2
			failures=$((failures + 1))
		fi
	done < <(getent passwd)

	if ((configured == 0)); then
		printf 'No eligible interactive user accounts with existing /home directories were found.\n'
		return 1
	fi
	printf 'Browser defaults set for %d account(s); failures: %d.\n' "$configured" "$failures"
	((failures == 0))
}

update_packages() {
	local answer ssh_service
	command -v apt-get >/dev/null 2>&1 || { printf 'apt-get is unavailable.\n'; return 1; }
	printf 'Package updates can restart services and may temporarily affect GNOME.\n'
	printf 'Run apt-get update and upgrade now? [y/N]: '
	IFS= read -r answer || true
	case "$answer" in
		y|Y|yes|YES)
			if ! apt-get update || ! apt-get upgrade; then
				printf 'Package update failed; SSH state was not checked or changed.\n' >&2
				return 1
			fi

			if systemctl list-unit-files --no-legend ssh.service 2>/dev/null | grep -q '^ssh.service'; then
				ssh_service='ssh'
			elif systemctl list-unit-files --no-legend sshd.service 2>/dev/null | grep -q '^sshd.service'; then
				ssh_service='sshd'
			else
				printf 'SSH service unit was not found after the update.\n'
				return 0
			fi

			if systemctl is-active --quiet "$ssh_service" && systemctl is-enabled --quiet "$ssh_service"; then
				printf 'SSH service %s is enabled and active after the update.\n' "$ssh_service"
			else
				printf 'SSH service %s is not both enabled and active after the update.\n' "$ssh_service"
				printf 'Enable and start it now? [y/N]: '
				IFS= read -r answer || true
				case "$answer" in
					y|Y|yes|YES)
						if systemctl enable --now "$ssh_service"; then
							printf 'SSH service %s is now enabled and active.\n' "$ssh_service"
						else
							printf 'Could not enable and start SSH service %s.\n' "$ssh_service" >&2
							return 1
						fi
						;;
					*)
						printf 'SSH service was left unchanged.\n'
						;;
				esac
			fi
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
	printf '4) Install Chrome and set default for all users\n'
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
