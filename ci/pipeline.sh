#!/usr/bin/env bash
# CI entrypoint that does not depend on a specific CI vendor.
# GitHub Actions template: ci/github-actions.yml
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "== unit and integration tests =="
python3 -m unittest discover -s tests -v

echo "== correct patch (expected exit 0) =="
bash examples/demo/run.sh --correct

echo "== regression patch (expected exit 20) =="
bash examples/demo/run.sh
