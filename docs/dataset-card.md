# Dataset card

## Dataset

The experiments use the public benchmark dataset version `zero-trust-agent-benchmark-dataset-v4.1` from the benchmark package tag `v0.1.0`.

## Storage policy

No benchmark trace is stored in this repository. The test harness resolves either a sibling checkout at `..\zero-trust-agent-benchmark\traces` or the installed benchmark package resources.

## Integrity checks

The test split must have SHA-256 `d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b`. The development split must have SHA-256 `4b6fcd37944e7ad85295805e8b73a4507680a87c9a09c5b1201ab43ef02d1e31`. The harness raises an exception before use when a split hash differs.

## Intended use

The benchmark is used to measure how often a local attestation policy blocks tool calls after measurement tampering, and how often benign calls remain usable under matching golden measurements.

## Limitations

The traces evaluate tool-call decisions, not hardware compromise. Hardware-backed key protection is outside this dataset.

## Shortcut and overfit controls

The defense is based on tool risk, appraisal state, nonce freshness, runtime tool measurement, and taint provenance. It does not match trace identifiers, generated payloads, the benchmark domain, or exact benchmark-only field values.
