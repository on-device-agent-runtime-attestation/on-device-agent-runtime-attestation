# Threat Model

## Assets

Local agent runtime, tool binaries, model artifacts, identity documents, hardware quote material when available, measurement logs, nonces, accepted sequence numbers, and secrets.

## Attacker capabilities

The attacker may inject hostile instructions, replace local files, replay an older quote, send a stale quote, request a tool outside policy, attempt to exfiltrate a secret marker, or run on a host without a hardware root of trust.

## Security boundary

The software reference backend signs quotes with a process-local key. It tests protocol logic but cannot stop a privileged local attacker from changing code or state. Production deployments need a hardware-backed backend that protects signing keys and measurements outside the agent process.

## Failure policy

The verifier denies when identity is invalid, a nonce mismatches, a quote is stale, a sequence has already been accepted, a signature is invalid, a measurement mismatches, policy denies the tool, an unsafe destination is requested, a secret marker is present, or trust is below threshold.
