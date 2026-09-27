# Reproducibility

## Environment

- Python 3.12.
- Package installation with `pip` or `uv`.
- Optional benchmark package: `zero-trust-agent-benchmark @ git+https://github.com/zero-trust-agent-benchmark/zero-trust-agent-benchmark@v0.1.0`.

## Local validation

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pip install "zero-trust-agent-benchmark @ git+https://github.com/zero-trust-agent-benchmark/zero-trust-agent-benchmark@v0.1.0"
.\.venv\Scripts\ruff check .
.\.venv\Scripts\ruff format --check .
.\.venv\Scripts\mypy src
.\.venv\Scripts\pytest -q --cov=on_device_agent_runtime_attestation --cov-report=term-missing --cov-fail-under=90
```

## Benchmark data

The repository intentionally does not vendor benchmark traces. When a sibling checkout exists at `..\zero-trust-agent-benchmark\traces`, scripts read those files. Otherwise continuous integration installs the benchmark package at tag `v0.1.0`.

Before any trace is used, the code asserts the split hash:

- Development split SHA-256: `4b6fcd37944e7ad85295805e8b73a4507680a87c9a09c5b1201ab43ef02d1e31`.
- Test split SHA-256: `d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b`.

## Benchmark run

```powershell
.\.venv\Scripts\python bench\run_bench.py --split dev --out results\benchmark-dev --trials 100
.\.venv\Scripts\python bench\run_bench.py --split test --out results\benchmark-test --trials 100
.\.venv\Scripts\python bench\run_artifact_verifier.py --out results\artifact-verifier --workers 4
```

Each result directory contains:

- `summary.json`: aggregate metrics, ablation rows, and per-trace decisions.
- `ablation.json`: version 1 through final defense rows.
- `trials.csv`: per-trace log used for class-level analysis.
- `env.json`: platform and dataset proof.
- `manifest.sha256`: result manifest hash.

## Formal model

```powershell
bash scripts\tlc.sh
```

The script skips only when Java or the model checker jar is unavailable. Continuous integration prepares the jar and runs the same script.

## Shortcut controls

The literal guard in `tests/test_benchmark_literal_guard.py` imports the benchmark generator token list and fails if source code copies benchmark-specific strings outside a public runtime allow list. The implementation also reviewed the benchmark shortcut audit and overfit check and avoids domain, trace identifier, and payload-string matching.
