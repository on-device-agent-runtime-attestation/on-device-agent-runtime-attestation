# Pre-registered hypotheses and measured results

This repository treats the paper numbers as hypotheses. The implementation was run against the unmodified benchmark dataset version `zero-trust-agent-benchmark-dataset-v4.1`. The test split SHA-256 is asserted before use: `d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b`.

## Method

- Development split: used for rule design and threshold tuning.
- Test split: reported after the final corrected design was selected.
- No trace was edited, filtered, relabelled, or copied into this repository.
- Runtime condition is an independent experimental factor. Each step is run once under each condition: clean, tampered runtime, tampered tool manifest, tampered policy, stale or replayed quote, and rolled-back measurement.
- The benchmark label is used only for scoring and is never passed into the verifier or gate.
- Trials: 100 local policy-latency trials per ablation row.
- Statistics: Wilson 95% intervals for rates; percentiles for policy latency.
- Backend: software reference backend, not a hardware root of trust.

## Methodology correction

A review found circularity in an earlier benchmark: malicious labels selected a tampered runtime while benign labels selected a clean runtime. That inflated the reported attack block rate. The benchmark now crosses labels with runtime conditions and records clean-runtime false positives, clean-runtime attack blocking, and tamper detection separately. Regression tests verify that verifier decisions are unchanged when the label field is removed or randomized, and that every step receives the same runtime-condition set independent of label.

## Claim to measured-result table

| Paper claim | Pre-registered hypothesis | Measured value | Verdict |
|---|---|---:|---|
| Offline local attestation can gate tools without cloud verification. | A verifier can accept only locally fresh, signed, replayable quotes and a per-call appraisal token. | 113 tests passed; formal invariants cover stale quote, replay, reorder, invalid event log, and appraisal monotonicity. | Supported for the software reference model. |
| Hash-extended runtime measurements expose tampering. | Tampering runtime, tool manifest, policy, freshness, or measurement history blocks or degrades calls. | Test split: every tampered condition produced 100.0% blocked-or-degraded rate for both benign and attack steps. | Supported on the benchmark. |
| Replay protection prevents quote reuse. | Reusing a nonce, sequence, or appraisal token is rejected. | Unit and property tests reject replayed quotes and replayed appraisal tokens. | Supported. |
| Attestation failure must fail closed. | Untrusted appraisal denies every tool; degraded appraisal is context aware. | Degraded mode denied sensitive reads, mutations, egress, administration, tainted contexts, stale quotes, and rolled-back measurements. | Supported. |
| Runtime overhead is small enough for local tool gating. | Final policy latency remains below 5 ms at the 95th percentile in the software backend. | Test split final ablation latency: mean 0.356 ms, median 0.279 ms, 95th percentile 0.583 ms, 99th percentile 0.856 ms. | Supported on this workstation. |
| In-policy attacks on a clean runtime are blocked by local context gating. | Non-label-based tool gating catches at least some attack steps without runtime compromise. | Test split: 102 of 500 clean-runtime attack steps blocked, 20.4%, Wilson 95% interval [17.1%, 24.2%]. | Partially supported; attestation alone does not identify all in-policy prompt-injection behavior. |
| Benign calls remain usable on a clean runtime. | False-positive rate remains at most 2% on the test split. | 0 of 1500 clean benign steps blocked, 0.0%, Wilson 95% interval [0.0%, 0.26%]. | Supported. |
| Large model artifacts can be verified quickly. | Full streaming verification of 4 GiB should be measured, not assumed. | 4 GiB synthetic artifact: 8.690 s, 471 MiB/s. | The 120 ms full-hash claim is not reproduced and appears physically implausible for this Python implementation and storage path. |

## Test split corrected ablation

The combined figure is attack blocking under the explicit threat model that the attack occurs while the runtime has been tampered. Clean-runtime attack blocking is reported separately and is the honest measure for an intact platform.

| Version | Defense change | Clean attack block rate | Clean false-positive rate | Tamper detection, benign | Tamper detection, attack | Combined attack block rate | Policy latency 95th percentile |
|---|---|---:|---:|---:|---:|---:|---:|
| Version 1 | Original degraded read-only policy | 0 of 500, 0.0% [0.0%, 0.76%] | 0 of 1500, 0.0% [0.0%, 0.26%] | 100.0% [99.7%, 100.0%] | 100.0% [99.2%, 100.0%] | 290 of 500, 58.0% [53.6%, 62.2%] | 1.011 ms |
| Per-tool requirements | Classify administration, mutation, egress, sensitive reads, and ordinary reads before appraisal | 0 of 500, 0.0% [0.0%, 0.76%] | 0 of 1500, 0.0% [0.0%, 0.26%] | 100.0% [99.7%, 100.0%] | 100.0% [99.2%, 100.0%] | 500 of 500, 100.0% [99.2%, 100.0%] | 0.501 ms |
| Fresh appraisal tokens | Add per-call token binding and runtime tool-code measurement | 0 of 500, 0.0% [0.0%, 0.76%] | 0 of 1500, 0.0% [0.0%, 0.26%] | 100.0% [99.7%, 100.0%] | 100.0% [99.2%, 100.0%] | 500 of 500, 100.0% [99.2%, 100.0%] | 0.472 ms |
| Final | Add taint-aware and context-aware clean-runtime gating | 102 of 500, 20.4% [17.1%, 24.2%] | 0 of 1500, 0.0% [0.0%, 0.26%] | 100.0% [99.7%, 100.0%] | 100.0% [99.2%, 100.0%] | 500 of 500, 100.0% [99.2%, 100.0%] | 0.583 ms |

## Tamper-condition detail on the test split

| Runtime condition | Benign blocked or degraded | Attack blocked or degraded | Interpretation |
|---|---:|---:|---|
| Tampered runtime | 1500 of 1500, 100.0% | 500 of 500, 100.0% | Correct detection with availability cost under compromise. |
| Tampered tool manifest | 1500 of 1500, 100.0% | 500 of 500, 100.0% | Correct detection with availability cost under compromise. |
| Tampered policy | 1500 of 1500, 100.0% | 500 of 500, 100.0% | Correct detection with availability cost under compromise. |
| Stale or replayed quote | 1500 of 1500, 100.0% | 500 of 500, 100.0% | Correct freshness and replay rejection. |
| Rolled-back measurement | 1500 of 1500, 100.0% | 500 of 500, 100.0% | Correct event-log replay rejection. |

## Development split tuning record

The development split moved from 145 of 250 combined tampered-runtime attack steps blocked in version 1 to 250 of 250 after per-tool requirements. Clean-runtime attack blocking increased from 0 of 250 to 51 of 250 only after the final taint-aware context controls. Clean-runtime benign false positives stayed at 0 of 750 throughout. The same final design was then run on the test split and reported above.

## Model artifact verifier

| Synthetic size | Chunks | Elapsed time | Throughput |
|---:|---:|---:|---:|
| 256 MiB | 32 | 0.535 s | 478 MiB/s |
| 1 GiB | 128 | 2.263 s | 453 MiB/s |
| 4 GiB | 512 | 8.690 s | 471 MiB/s |

Artifacts are generated in memory at benchmark time and are not committed. The verifier uses chunk hashing and a Merkle-style tree root.

## Formal model checker record

The model is in `formal/RuntimeAttestation.tla`. It specifies verifier-issued nonces, freshness, signature validity, event log validity, sequence tracking, nonce reuse tracking, and appraisal outcomes. The checked invariants are:

- `NoReplayAccepted`
- `NoStaleQuoteAccepted`
- `NoReorderedQuoteAccepted`
- `AppraisalMonotonicity`
- `NoInvalidEventLogAccepted`

Continuous integration runs the model checker when the Java runtime and model checker jar are present. Local runs without the jar are explicitly skipped by `scripts/tlc.sh` rather than treated as proof.

## Non-reproductions

The full hardware-root claim is not reproduced because continuous integration has no Trusted Platform Module or Trusted Execution Environment. The software backend demonstrates protocol logic but cannot protect its root key from the local operating system. The claimed 4 GiB artifact verification in 120 ms is not reproduced; the measured full verifier took 8.690 s on this workstation. Clean-runtime attack blocking is 20.4%, because attestation confirms runtime integrity and cannot by itself classify every in-policy malicious instruction in an intact runtime.
