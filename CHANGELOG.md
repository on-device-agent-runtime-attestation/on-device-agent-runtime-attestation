# Changelog

## 0.1.0 - 2026-09-26

- Initial public release with offline local attestation, multiple hash-extended registers, signed quotes, key rotation and revocation, appraisal tokens, context-aware degraded-mode gating, per-tool runtime measurement, formal model, tests, benchmark ablations, and model artifact verifier results.
- Benchmark data is not vendored; the unmodified public benchmark split hashes are asserted before use.
- Corrected the benchmark methodology so runtime tampering is crossed independently with trace labels. Labels are now used only for scoring, clean-runtime false positives and clean-runtime attack blocking are reported separately, and regression tests prevent reintroducing label leakage.
