from __future__ import annotations

import hmac
import secrets
import time
from typing import Protocol

from on_device_agent_runtime_attestation.measurement import MeasurementChain
from on_device_agent_runtime_attestation.quote import AttestationQuote


class AttestationBackend(Protocol):
    name: str

    def quote(self, chain: MeasurementChain, nonce: str) -> AttestationQuote: ...
    def verify_signature(self, quote: AttestationQuote) -> bool: ...


class SoftwareReferenceBackend:
    """Software-only backend for tests and reproducible experiments."""

    name = "software-reference"

    def __init__(self, signing_key: bytes | None = None) -> None:
        self._signing_key = signing_key if signing_key is not None else secrets.token_bytes(32)
        self._sequence_number = 0

    def quote(self, chain: MeasurementChain, nonce: str) -> AttestationQuote:
        self._sequence_number += 1
        issued_at_unix_ms = int(time.time() * 1000)
        payload = AttestationQuote.payload(
            self.name, nonce, issued_at_unix_ms, self._sequence_number, chain
        )
        signature = hmac.digest(self._signing_key, payload, "sha256").hex()
        return AttestationQuote(
            self.name,
            nonce,
            issued_at_unix_ms,
            self._sequence_number,
            chain.root_digest(),
            chain.expected_digest_map(),
            signature,
        )

    def verify_signature(self, quote: AttestationQuote) -> bool:
        return quote.verifies_with_key(self._signing_key)


class TrustedPlatformModuleToolBackend:
    name = "trusted-platform-module-tool"

    def quote(self, chain: MeasurementChain, nonce: str) -> AttestationQuote:
        raise NotImplementedError("hardware quote production is deployment specific")

    def verify_signature(self, quote: AttestationQuote) -> bool:
        return quote.backend_name == self.name and bool(quote.signature)
