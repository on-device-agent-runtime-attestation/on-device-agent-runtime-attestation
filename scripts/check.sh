#!/usr/bin/env bash
set -euo pipefail
python -m pip install -q -e ".[dev]"
ruff check .
ruff format --check .
mypy src bench
pytest -q --cov=on_device_agent_runtime_attestation --cov-report=term-missing --cov-fail-under=85
bash scripts/tlc.sh
python bench/run_bench.py
