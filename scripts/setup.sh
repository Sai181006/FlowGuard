#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if command -v uv >/dev/null 2>&1; then
  uv venv --python "${FLOWGUARD_PYTHON:-3.14}" --allow-existing .venv
  uv pip sync --python .venv/bin/python requirements.txt
else
  "${FLOWGUARD_PYTHON:-python3}" -m venv .venv
  .venv/bin/python -m pip install -r requirements.txt
fi
.venv/bin/python -m unittest discover -s tests -v
