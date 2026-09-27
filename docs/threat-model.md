# Threat model

## Assets

- Runtime measurement log and register values.
- Attestation root key and active attestation key.
- Verifier-issued nonce table and replay cache.
- Golden reference measurements.
- Tool authorization decision.

## Adversary

The adversary may control prompts, retrieved content, tool arguments, local files outside the measured base, and network destinations. The adversary may replay old quotes, reorder quotes, alter event logs, request privileged tools, or try to use revoked attestation keys.

## Security goals

- A stale quote is never accepted.
- A verifier nonce is single use.
- A sequence number is not accepted out of order for the same device.
- A quote signature covers nonce, timestamp, event log hash, event list, register values, key identifier, and device identifier.
- A replayed event log recomputes the quoted register values.
- Appraisal cannot become more trusted than the golden reference comparison allows.
- Tool execution fails closed on untrusted appraisal or verifier failure.

## Software reference backend limitations

The software reference backend is honest test infrastructure. It is useful for deterministic experiments and continuous integration. It does not provide hardware isolation, measured boot, sealed storage, rollback protection outside the verifier cache, or protection from an administrator on the same operating system. A production deployment should replace it with a hardware-backed or isolated backend.

## Hardware and emulator backends

A Trusted Platform Module (TPM) backend can bind attestation keys to hardware-protected non-exportable keys and Platform Configuration Registers (PCRs). A Trusted Execution Environment (TEE) backend can bind measurement and signing to an isolated execution domain. The manual software Trusted Platform Module workflow is an emulator path for integration experiments only; it is not stronger than the host on which it runs.

## Failure policy

Every verification error returns untrusted or denied. Degraded appraisal is deliberately narrow: local status style tools are allowed only when the call is not tainted and does not request sensitive data, egress, mutation, or administration. Blocking benign calls during a compromised runtime is reported as availability cost, not as a clean-runtime false positive.

## Defensive controls

The final defense binds each tool call to a short-lived appraisal token, remeasures the loaded tool identifier before execution, classifies the requested tool privilege, and treats non-user provenance as tainted after an appraisal downgrade. Degraded mode no longer treats every read as safe: sensitive reads, egress, mutation, and administration are denied.
