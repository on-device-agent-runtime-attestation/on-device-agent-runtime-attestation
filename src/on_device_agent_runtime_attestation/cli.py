from __future__ import annotations

import argparse
import secrets

from on_device_agent_runtime_attestation.backend import SoftwareReferenceBackend
from on_device_agent_runtime_attestation.identity import IdentityDocument
from on_device_agent_runtime_attestation.measurement import Measurement, MeasurementChain
from on_device_agent_runtime_attestation.policy import Policy, ToolRequest
from on_device_agent_runtime_attestation.trust import TrustState
from on_device_agent_runtime_attestation.verifier import LocalVerifier


def run_demo() -> int:
    chain = MeasurementChain().append(Measurement.from_bytes("agent-runtime", b"demo-runtime"))
    backend = SoftwareReferenceBackend()
    nonce = secrets.token_hex(16)
    quote = backend.quote(chain, nonce)
    identity = IdentityDocument.for_agent("demo")
    trust = TrustState(successes=100, failures=0, exponentially_weighted_success=0.95)
    trust.record("fs.read", True)
    request = ToolRequest("demo", "fs.read", {"path": "workspace/report.txt"})
    verifier = LocalVerifier(backend, Policy.default(), allow_threshold=0.5)
    decision = verifier.verify(
        identity=identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce=nonce,
        expected_measurements=chain.expected_digest_map(),
        trust_state=trust,
    )
    print(f"{decision.reason}: allowed={decision.allowed}")
    return 0 if decision.allowed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="On-device agent runtime attestation")
    parser.add_argument("command", choices=["demo"])
    args = parser.parse_args(argv)
    if args.command == "demo":
        return run_demo()
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
