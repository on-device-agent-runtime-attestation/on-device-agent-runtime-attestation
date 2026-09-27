# Contributing

Use Python 3.12, keep type checking strict, add tests for behavior changes, and record benchmark changes in `docs/hypotheses.md` when they affect a registered hypothesis.

```bash
python -m pip install -e ".[dev]"
bash scripts/check.sh
```
