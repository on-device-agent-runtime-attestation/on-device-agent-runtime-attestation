from __future__ import annotations

import time
from dataclasses import dataclass

from on_device_agent_runtime_attestation.backend import AttestationBackend
from on_device_agent_runtime_attestation.identity import IdentityDocument
from on_device_agent_runtime_attestation.policy import Policy, ToolRequest
from on_device_agent_runtime_attestation.quote import AttestationQuote
from on_device_agent_runtime_attestation.trust import TrustState


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    reason: str


class LocalVerifier:
    def __init__(
        self,
        backend: AttestationBackend,
        policy: Policy,
        *,
        expected_trust_domain: str = "example.local",
        freshness_window_ms: int = 5 * 60 * 1000,
        allow_threshold: float = 0.75,
    ) -> None:
        self._backend = backend
        self._policy = policy
        self._expected_trust_domain = expected_trust_domain
        self._freshness_window_ms = freshness_window_ms
        self._allow_threshold = allow_threshold
        self._accepted_sequences: set[tuple[str, int]] = set()

    def verify(
        self,
        *,
        identity: IdentityDocument,
        role: str,
        request: ToolRequest,
        quote: AttestationQuote,
        expected_nonce: str,
        expected_measurements: dict[str, str],
        trust_state: TrustState,
        now_unix_ms: int | None = None,
    ) -> Decision:
        now = int(time.time() * 1000) if now_unix_ms is None else now_unix_ms
        if not identity.is_valid(
            expected_trust_domain=self._expected_trust_domain, now_unix_ms=now
        ):
            return Decision(False, "identity invalid")
        if quote.backend_name != self._backend.name:
            return Decision(False, "attestation backend mismatch")
        if quote.nonce != expected_nonce:
            return Decision(False, "nonce mismatch")
        if now - quote.issued_at_unix_ms > self._freshness_window_ms:
            return Decision(False, "quote stale")
        accepted_key = (quote.backend_name, quote.sequence_number)
        if accepted_key in self._accepted_sequences:
            return Decision(False, "quote replay")
        if not self._backend.verify_signature(quote):
            return Decision(False, "quote signature invalid")
        for label, digest in expected_measurements.items():
            if quote.measurements.get(label) != digest:
                return Decision(False, f"measurement mismatch: {label}")
        if not self._policy.tool_allowed(role, request):
            return Decision(False, "tool not allowed")
        if not self._policy.destination_allowed(request):
            return Decision(False, "destination not allowed")
        if self._policy.contains_secret_marker(request):
            return Decision(False, "secret marker detected")
        if not trust_state.verdict(request.tool, allow_threshold=self._allow_threshold):
            return Decision(False, "trust below threshold")
        self._accepted_sequences.add(accepted_key)
        return Decision(True, "allow")
