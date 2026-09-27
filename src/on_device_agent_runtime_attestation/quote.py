from __future__ import annotations

import hmac
import json
from dataclasses import dataclass

from on_device_agent_runtime_attestation.measurement import MeasurementChain


@dataclass(frozen=True, slots=True)
class AttestationQuote:
    backend_name: str
    nonce: str
    issued_at_unix_ms: int
    sequence_number: int
    measurement_root: str
    measurements: dict[str, str]
    signature: str

    @staticmethod
    def payload(
        backend_name: str,
        nonce: str,
        issued_at_unix_ms: int,
        sequence_number: int,
        chain: MeasurementChain,
    ) -> bytes:
        content = {
            "backend_name": backend_name,
            "issued_at_unix_ms": issued_at_unix_ms,
            "measurement_root": chain.root_digest(),
            "measurements": chain.expected_digest_map(),
            "nonce": nonce,
            "sequence_number": sequence_number,
        }
        return json.dumps(content, sort_keys=True, separators=(",", ":")).encode()

    def unsigned_payload(self) -> bytes:
        content = {
            "backend_name": self.backend_name,
            "issued_at_unix_ms": self.issued_at_unix_ms,
            "measurement_root": self.measurement_root,
            "measurements": self.measurements,
            "nonce": self.nonce,
            "sequence_number": self.sequence_number,
        }
        return json.dumps(content, sort_keys=True, separators=(",", ":")).encode()

    def verifies_with_key(self, key: bytes) -> bool:
        expected = hmac.digest(key, self.unsigned_payload(), "sha256").hex()
        return hmac.compare_digest(expected, self.signature)
