#!/usr/bin/env bash

set -euo pipefail

if [[ -z "${GHIDRA_INSTALL_DIR:-}" ]]; then
    printf 'Error: set GHIDRA_INSTALL_DIR to your Ghidra installation directory.\n' >&2
    exit 1
fi

script_directory=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository_root=$(CDPATH='' cd -- "$script_directory/.." && pwd -P)
pyghidra_executable="$repository_root/.venv-ghidra/bin/pyghidra-mcp"

if [[ ! -x "$pyghidra_executable" ]]; then
    printf 'Error: %s is missing or not executable; run ./scripts/setup.sh first.\n' \
        "$pyghidra_executable" >&2
    exit 1
fi

# Ghidra must find its ghidra: URL handler while restoring saved open programs.
export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }-Djava.protocol.handler.pkgs=ghidra.framework.protocol"

exec "$pyghidra_executable" \
    --gui \
    --transport streamable-http \
    --host 127.0.0.1 \
    --port 8001 \
    "$@"
