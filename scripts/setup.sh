#!/usr/bin/env bash

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./scripts/setup.sh [--register-codex]

Create OGhidra's two Python environments and initialize config.yaml.
Use --register-codex to also add the pyghidra and oghidra MCP servers.
EOF
}

register_codex_server() {
    local name=$1
    shift

    if codex mcp get "$name" --json >/dev/null 2>&1; then
        printf 'Codex MCP server %s already exists; leaving it unchanged.\n' "$name"
        return
    fi

    codex mcp add "$name" "$@"
}

register_codex=false
case "${1-}" in
    "")
        ;;
    --register-codex)
        register_codex=true
        shift
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

if (($# != 0)); then
    usage >&2
    exit 2
fi

script_directory=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_directory/.." && pwd -P)

python_command=${OGHIDRA_PYTHON:-}
if [[ -z "$python_command" ]]; then
    if command -v python3.12 >/dev/null 2>&1; then
        python_command=python3.12
    elif command -v python3 >/dev/null 2>&1; then
        python_command=python3
    else
        printf 'Error: Python 3.12 or later is required.\n' >&2
        exit 1
    fi
fi

if ! command -v "$python_command" >/dev/null 2>&1; then
    printf 'Error: Python executable not found: %s\n' "$python_command" >&2
    exit 1
fi

python_version=$(
    "$python_command" -c \
        'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
)
if [[ ! "$python_version" =~ ^([0-9]+)\.([0-9]+)$ ]] ||
    ((BASH_REMATCH[1] < 3 || (BASH_REMATCH[1] == 3 && BASH_REMATCH[2] < 12))); then
    printf 'Error: Python 3.12 or later is required; found %s.\n' "$python_version" >&2
    exit 1
fi

printf 'Creating or updating the PyGhidra environment...\n'
"$python_command" -m venv "$repository_root/.venv-ghidra"
"$repository_root/.venv-ghidra/bin/python" -m pip install "pyghidra-mcp==0.2.7"

printf 'Creating or updating the OGhidra environment...\n'
"$python_command" -m venv "$repository_root/.venv"
"$repository_root/.venv/bin/python" -m pip install -e "$repository_root"

config_path="$repository_root/config.yaml"
if [[ ! -e "$config_path" && ! -L "$config_path" ]]; then
    command cp "$repository_root/config.example.yaml" "$config_path"
    printf 'Created %s.\n' "$config_path"
else
    printf 'Keeping existing %s.\n' "$config_path"
fi

if [[ "$register_codex" == true ]]; then
    if ! command -v codex >/dev/null 2>&1; then
        printf 'Error: codex is required with --register-codex.\n' >&2
        exit 1
    fi

    register_codex_server pyghidra --url http://127.0.0.1:8001/mcp
    register_codex_server oghidra -- \
        "$repository_root/.venv/bin/oghidra-workflows" \
        --config "$config_path"
    codex mcp list
fi

printf 'Setup complete. Edit %s before starting OGhidra.\n' "$config_path"
