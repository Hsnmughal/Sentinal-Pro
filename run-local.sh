#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_python="$project_root/.venv/bin/python"

if [ ! -x "$project_python" ]; then
    echo "Create a virtual environment: python3 -m venv .venv" >&2
    echo "Then install: .venv/bin/python -m pip install -e ." >&2
    exit 1
fi

cd "$project_root"
exec "$project_python" -m sentinal run "$@"
