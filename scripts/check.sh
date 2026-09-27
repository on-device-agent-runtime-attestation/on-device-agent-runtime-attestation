#!/usr/bin/env bash
set -euo pipefail
python -m pip install -q -e ".[dev]"
if [ -d "../zero-trust-agent-benchmark" ]; then
  python -m pip install -q -e "../zero-trust-agent-benchmark"
fi
ruff check .
ruff format --check .
mypy src
pytest -q --cov=on_device_agent_runtime_attestation --cov-report=term-missing --cov-fail-under=90
bash scripts/tlc.sh
python bench/run_bench.py --split dev --out results/benchmark-dev --trials 100
python bench/run_bench.py --split test --out results/benchmark-test --trials 100
