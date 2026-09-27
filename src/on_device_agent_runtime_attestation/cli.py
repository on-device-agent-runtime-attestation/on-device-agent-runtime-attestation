from __future__ import annotations

import argparse
import secrets

from on_device_agent_runtime_attestation.protocol import (
    LocalVerifier,
    make_reference_backend,
    make_reference_policy,
)


def run_demo() -> int:
    backend = make_reference_backend()
    policy = make_reference_policy(backend.log.bank.values)
    verifier = LocalVerifier(backend=backend, policy=policy)
    challenge = verifier.challenge(secrets.token_hex(16))
    quote = backend.quote(challenge)
    result = verifier.verify(quote, requested_tool="read-only-file")
    print(f"{result.outcome.value}: allowed={result.allowed_tool}")
    return 0 if result.accepted else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="On-device agent runtime attestation")
    parser.add_argument("command", choices=["demo"])
    args = parser.parse_args(argv)
    if args.command == "demo":
        return run_demo()
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
