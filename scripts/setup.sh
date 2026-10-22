#!/usr/bin/env bash
# Create .venv with the pinned requirements and run the unit tests.
#
# On an Ubuntu Mininet lab, Mininet and Open vSwitch come from apt
# (sudo apt install -y mininet openvswitch-switch python3-venv). Set
# FLOWGUARD_SYSTEM_SITE_PACKAGES=1 so the venv can also import the apt-installed
# mininet module (python3 -m venv --system-site-packages), then run the lab
# with the venv interpreter, e.g. sudo .venv/bin/python experiments/demo.py.
# The native dashboard and localhost lab need no venv at all (stdlib only).
set -euo pipefail
cd "$(dirname "$0")/.."
system_site=()
if [[ "${FLOWGUARD_SYSTEM_SITE_PACKAGES:-0}" == "1" ]]; then
  system_site=(--system-site-packages)
fi
if command -v uv >/dev/null 2>&1; then
  uv venv --python "${FLOWGUARD_PYTHON:-3.14}" --allow-existing ${system_site[@]+"${system_site[@]}"} .venv
  uv pip sync --python .venv/bin/python requirements.txt
else
  "${FLOWGUARD_PYTHON:-python3}" -m venv ${system_site[@]+"${system_site[@]}"} .venv
  .venv/bin/python -m pip install -r requirements.txt
fi
.venv/bin/python -m unittest discover -s tests -v
