#!/usr/bin/env bash
# Modular menu framework for the NOJE Linux hardening project.
# Each menu item is a separate script under ./functions/<plugin>/run.sh.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
FUNCTIONS_DIR="$SCRIPT_DIR/functions"

declare -a plugin_scripts=()
declare -a plugin_names=()
declare -a plugin_descriptions=()

load_plugins() {
	plugin_scripts=()
	plugin_names=()
	plugin_descriptions=()

	local config plugin_dir script_path key value name description

	for config in "$FUNCTIONS_DIR"/*/plugin.conf; do
		[[ -f "$config" ]] || continue

		plugin_dir="${config%/plugin.conf}"
		# Underscore-prefixed directories are reserved for templates/support files.
		[[ "${plugin_dir##*/}" == _* ]] && continue

		script_path="$plugin_dir/run.sh"
		[[ -f "$script_path" ]] || continue

		name=""
		description=""
		while IFS='=' read -r key value || [[ -n "$key" || -n "$value" ]]; do
			value="${value%$'\r'}" # Accept Windows-style CRLF config files.
			case "$key" in
				name) name="$value" ;;
				description) description="$value" ;;
			esac
		done < "$config"

		# A plugin needs a display name; config files are parsed, never sourced.
		[[ -n "$name" ]] || continue

		plugin_scripts+=("$script_path")
		plugin_names+=("$name")
		plugin_descriptions+=("$description")
	done
}

while true; do
	load_plugins

	printf '\n=== NOJE Linux Security Menu ===\n'
	if ((${#plugin_names[@]} == 0)); then
		printf 'No functions are installed yet. Add a plugin under: %s\n' "$FUNCTIONS_DIR"
	else
		for index in "${!plugin_names[@]}"; do
			option=$((index + 1))
			printf ' %d) %s' "$option" "${plugin_names[$index]}"
			[[ -n "${plugin_descriptions[$index]}" ]] && printf ' — %s' "${plugin_descriptions[$index]}"
			printf '\n'
		done
	fi
	printf ' 0) Exit\n'

	if ! IFS= read -r -p 'Select an option: ' choice; then
		printf '\nExiting.\n'
		break
	fi

	case "$choice" in
		0|q|Q)
			printf 'Exiting.\n'
			break
			;;
	esac

	selected_index=""
	for index in "${!plugin_scripts[@]}"; do
		option=$((index + 1))
		if [[ "$choice" == "$option" ]]; then
			selected_index="$index"
			break
		fi
	done

	if [[ -z "$selected_index" ]]; then
		printf 'Invalid selection. Choose a listed number, 0, or q.\n'
		continue
	fi

	printf '\n--- Running: %s ---\n' "${plugin_names[$selected_index]}"
	if bash "${plugin_scripts[$selected_index]}"; then
		printf '\n--- Function finished ---\n'
	else
		status=$?
		printf '\n--- Function exited with status %d ---\n' "$status"
	fi

	IFS= read -r -p 'Press Enter to return to the menu...' _ || true
done
