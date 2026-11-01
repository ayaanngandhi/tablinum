#!/usr/bin/env bash
# Run the unit suite and the end-to-end gate; print CHECK_PASS only if both pass.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python tests/gate.py

echo "CHECK_PASS"
