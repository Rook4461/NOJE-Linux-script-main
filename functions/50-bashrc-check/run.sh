#!/usr/bin/env bash
# Read-only check for user .bashrc files that differ from the system skeleton.

set -u

bashrc_check() {
    local reference='/etc/skel/.bashrc'
    local file
    local checked=0
    local suspicious=0
    local errors=0
    local -a bashrc_files=()

    if ((EUID != 0)); then
        if ! command -v sudo >/dev/null 2>&1; then
            printf 'Error: sudo is required to inspect all user .bashrc files.\n' >&2
            return 1
        fi
        exec sudo -- bash "$(readlink -f -- "${BASH_SOURCE[0]}")"
    fi

    if [[ ! -r "$reference" ]]; then
        printf 'Error: reference file is missing or unreadable: %s\n' "$reference" >&2
        return 1
    fi

    while IFS= read -r -d '' file; do
        bashrc_files+=("$file")
    done < <(find /home -type f -name '.bashrc' -print0 2>/dev/null)

    printf 'Reference: %s\n' "$reference"
    printf 'Checking user .bashrc files under /home...\n'

    if ((${#bashrc_files[@]} == 0)); then
        printf 'No .bashrc files were found under /home.\n'
        return 0
    fi

    for file in "${bashrc_files[@]}"; do
        checked=$((checked + 1))
        if diff -q -- "$reference" "$file" >/dev/null 2>&1; then
            printf 'MATCH: %s\n' "$file"
        else
            case "$?" in
                1)
                    suspicious=$((suspicious + 1))
                    printf '\nDIFFERS: %s\n' "$file"
                    diff -u -- "$reference" "$file" || true
                    ;;
                *)
                    errors=$((errors + 1))
                    printf 'ERROR: Could not compare %s\n' "$file" >&2
                    ;;
            esac
        fi
    done

    printf '\nChecked: %d | Different: %d | Errors: %d\n' "$checked" "$suspicious" "$errors"
    printf 'This check is read-only; inspect differences before deciding whether to change a file.\n'
    ((errors == 0))
}

bashrc_check "$@"
