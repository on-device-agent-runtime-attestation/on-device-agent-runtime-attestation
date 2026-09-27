from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .appraisal import AppraisalOutcome, AppraisalPolicy, GoldenReference
from .event_log import MeasurementEvent, MeasurementLog, event_log_digest, replay_events
from .keys import KeyHierarchy


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class VerificationFailure(StrEnum):
    CLOCK_SKEW = "clock_skew"
    EVENT_LOG = "event_log"
    NONCE = "nonce"
    POLICY = "policy"
    REPLAY = "replay"
    REORDERED = "reordered"
    REVOKED_KEY = "revoked_key"
    SIGNATURE = "signature"
    STALE = "stale"


@dataclass(frozen=True, slots=True)
class NonceChallenge:
    nonce: str
    issued_at_seconds: int
    expires_at_seconds: int


@dataclass(frozen=True, slots=True)
class RuntimeQuote:
    device_identifier: str
    key_identifier: str
    nonce: str
    issued_at_seconds: int
    sequence_number: int
    register_values: dict[int, str]
    event_log_hash: str
    events: tuple[MeasurementEvent, ...]
    signature: str

    def signed_payload(self) -> str:
        return _canonical_json(
            {
                "device_identifier": self.device_identifier,
                "event_log_hash": self.event_log_hash,
                "events": [event.canonical() for event in self.events],
                "issued_at_seconds": self.issued_at_seconds,
                "key_identifier": self.key_identifier,
                "nonce": self.nonce,
                "register_values": self.register_values,
                "sequence_number": self.sequence_number,
            }
        )


@dataclass(frozen=True, slots=True)
class VerificationResult:
    accepted: bool
    outcome: AppraisalOutcome
    failure: VerificationFailure | None
    allowed_tool: bool
    latency_seconds: float


class AttestationBackend(Protocol):
    def quote(self, challenge: NonceChallenge) -> RuntimeQuote: ...

    def public_key(self, key_identifier: str) -> bytes | None: ...


class SoftwareReferenceBackend:
    """Offline software reference backend, not a hardware root of trust."""

    def __init__(self, device_identifier: str, root_key: bytes | None = None) -> None:
        self.device_identifier = device_identifier
        self.keys = KeyHierarchy(root_key)
        self.log = MeasurementLog(register_count=8)
        self._quote_sequence = 0

    @property
    def active_key_identifier(self) -> str:
        return self.keys.active_key_identifier

    def measure(
        self,
        *,
        register_index: int,
        label: str,
        content: bytes,
        metadata: dict[str, str] | None = None,
    ) -> MeasurementEvent:
        digest = hashlib.sha256(content).hexdigest()
        return self.log.append(
            register_index=register_index,
            label=label,
            digest=digest,
            metadata=metadata,
        )

    def quote(self, challenge: NonceChallenge) -> RuntimeQuote:
        self._quote_sequence += 1
        key_identifier = self.keys.active_key_identifier
        quote = RuntimeQuote(
            device_identifier=self.device_identifier,
            key_identifier=key_identifier,
            nonce=challenge.nonce,
            issued_at_seconds=int(time.time()),
            sequence_number=self._quote_sequence,
            register_values=dict(self.log.bank.values),
            event_log_hash=self.log.event_log_digest(),
            events=self.log.events,
            signature="",
        )
        signature = hmac.digest(
            self.keys.signing_key(key_identifier), quote.signed_payload().encode(), "sha256"
        )
        return RuntimeQuote(
            quote.device_identifier,
            quote.key_identifier,
            quote.nonce,
            quote.issued_at_seconds,
            quote.sequence_number,
            quote.register_values,
            quote.event_log_hash,
            quote.events,
            signature.hex(),
        )

    def public_key(self, key_identifier: str) -> bytes | None:
        return self.keys.verify_key(key_identifier)

    def rotate_key(self) -> str:
        return self.keys.rotate_attestation_key().key_identifier

    def revoke_key(self, key_identifier: str) -> None:
        self.keys.revoke(key_identifier)


class LocalVerifier:
    def __init__(
        self,
        *,
        backend: AttestationBackend,
        policy: AppraisalPolicy,
        freshness_seconds: int = 30,
        clock_skew_seconds: int = 5,
    ) -> None:
        self.backend = backend
        self.policy = policy
        self.freshness_seconds = freshness_seconds
        self.clock_skew_seconds = clock_skew_seconds
        self._issued: dict[str, NonceChallenge] = {}
        self._used_nonces: set[str] = set()
        self._last_sequence_by_device: dict[str, int] = {}

    def challenge(self, nonce: str, issued_at_seconds: int | None = None) -> NonceChallenge:
        issued = int(time.time()) if issued_at_seconds is None else issued_at_seconds
        challenge = NonceChallenge(nonce, issued, issued + self.freshness_seconds)
        self._issued[nonce] = challenge
        return challenge

    def verify(
        self, quote: RuntimeQuote, *, requested_tool: str, now_seconds: int | None = None
    ) -> VerificationResult:
        start = time.perf_counter()
        now = int(time.time()) if now_seconds is None else now_seconds
        failure = self._failure(quote, now)
        labels = {event.label for event in quote.events}
        outcome = AppraisalOutcome.UNTRUSTED
        if failure is None:
            outcome = self.policy.appraise(quote.register_values, labels)
            if outcome == AppraisalOutcome.UNTRUSTED:
                failure = VerificationFailure.POLICY
        allowed_tool = failure is None and self.policy.tool_allowed(outcome, requested_tool)
        accepted = failure is None and allowed_tool
        if accepted:
            self._used_nonces.add(quote.nonce)
            self._last_sequence_by_device[quote.device_identifier] = quote.sequence_number
        return VerificationResult(
            accepted=accepted,
            outcome=outcome,
            failure=failure,
            allowed_tool=allowed_tool,
            latency_seconds=time.perf_counter() - start,
        )

    def _failure(self, quote: RuntimeQuote, now: int) -> VerificationFailure | None:
        challenge = self._issued.get(quote.nonce)
        if challenge is None or quote.nonce in self._used_nonces:
            return VerificationFailure.REPLAY
        if now > challenge.expires_at_seconds:
            return VerificationFailure.STALE
        if abs(quote.issued_at_seconds - now) > self.clock_skew_seconds:
            return VerificationFailure.CLOCK_SKEW
        last_sequence = self._last_sequence_by_device.get(quote.device_identifier, 0)
        if quote.sequence_number <= last_sequence:
            return VerificationFailure.REORDERED
        key = self.backend.public_key(quote.key_identifier)
        if key is None:
            return VerificationFailure.REVOKED_KEY
        unsigned = RuntimeQuote(
            quote.device_identifier,
            quote.key_identifier,
            quote.nonce,
            quote.issued_at_seconds,
            quote.sequence_number,
            quote.register_values,
            quote.event_log_hash,
            quote.events,
            "",
        )
        expected = hmac.digest(key, unsigned.signed_payload().encode(), "sha256").hex()
        if not hmac.compare_digest(expected, quote.signature):
            return VerificationFailure.SIGNATURE
        try:
            bank = replay_events(quote.events)
        except ValueError:
            return VerificationFailure.EVENT_LOG
        if bank.values != quote.register_values:
            return VerificationFailure.EVENT_LOG
        if event_log_digest(quote.events) != quote.event_log_hash:
            return VerificationFailure.EVENT_LOG
        return None


def make_reference_backend() -> SoftwareReferenceBackend:
    backend = SoftwareReferenceBackend(
        "reference-agent", root_key=b"public-reference-root-key-for-tests"
    )
    backend.measure(register_index=0, label="bootloader", content=b"reference bootloader")
    backend.measure(register_index=1, label="agent runtime", content=b"reference runtime")
    backend.measure(register_index=2, label="tool manifest", content=b"reference tools")
    backend.measure(register_index=3, label="policy", content=b"reference policy")
    return backend


def make_reference_policy(register_values: dict[int, str]) -> AppraisalPolicy:
    return AppraisalPolicy(
        golden=GoldenReference(
            register_values={index: register_values[index] for index in range(4)},
            required_labels=frozenset({"bootloader", "agent runtime", "tool manifest", "policy"}),
        ),
        degraded_allowed_tools=frozenset({"ordinary_read", "local_status"}),
        trusted_allowed_tools=frozenset(
            {
                "administration",
                "egress",
                "local_status",
                "mutation",
                "ordinary_read",
                "sensitive_read",
            }
        ),
    )
