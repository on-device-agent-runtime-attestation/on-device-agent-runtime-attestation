from __future__ import annotations

from dataclasses import replace

from hypothesis import given
from hypothesis import strategies as st

from on_device_agent_runtime_attestation.appraisal import AppraisalOutcome
from on_device_agent_runtime_attestation.event_log import MeasurementEvent
from on_device_agent_runtime_attestation.protocol import (
    LocalVerifier,
    RuntimeQuote,
    SoftwareReferenceBackend,
    VerificationFailure,
    make_reference_backend,
    make_reference_policy,
)


def _verified_reference(
    nonce: str = "nonce",
) -> tuple[SoftwareReferenceBackend, LocalVerifier, RuntimeQuote]:
    backend = make_reference_backend()
    verifier = LocalVerifier(backend=backend, policy=make_reference_policy(backend.log.bank.values))
    quote = backend.quote(verifier.challenge(nonce))
    return backend, verifier, quote


def test_reference_quote_is_accepted_for_read_only_tool() -> None:
    _backend, verifier, quote = _verified_reference()
    result = verifier.verify(quote, requested_tool="ordinary_read")
    assert result.accepted
    assert result.outcome == AppraisalOutcome.TRUSTED


def test_trusted_quote_can_gate_write_file() -> None:
    _backend, verifier, quote = _verified_reference("write")
    assert verifier.verify(quote, requested_tool="mutation").accepted


def test_unknown_nonce_is_rejected_as_replay() -> None:
    backend = make_reference_backend()
    verifier = LocalVerifier(backend=backend, policy=make_reference_policy(backend.log.bank.values))
    quote = backend.quote(verifier.challenge("issued"))
    quote = replace(quote, nonce="never-issued")
    assert (
        verifier.verify(quote, requested_tool="ordinary_read").failure == VerificationFailure.REPLAY
    )


def test_reused_nonce_is_rejected() -> None:
    _backend, verifier, quote = _verified_reference("reuse")
    assert verifier.verify(quote, requested_tool="ordinary_read").accepted
    assert (
        verifier.verify(quote, requested_tool="ordinary_read").failure == VerificationFailure.REPLAY
    )


def test_stale_challenge_is_rejected() -> None:
    backend = make_reference_backend()
    verifier = LocalVerifier(
        backend=backend, policy=make_reference_policy(backend.log.bank.values), freshness_seconds=1
    )
    quote = backend.quote(verifier.challenge("stale", issued_at_seconds=100))
    quote = replace(quote, issued_at_seconds=100)
    assert (
        verifier.verify(quote, requested_tool="ordinary_read", now_seconds=102).failure
        == VerificationFailure.STALE
    )


def test_clock_skew_is_rejected() -> None:
    backend = make_reference_backend()
    verifier = LocalVerifier(
        backend=backend, policy=make_reference_policy(backend.log.bank.values), clock_skew_seconds=1
    )
    quote = backend.quote(verifier.challenge("skew", issued_at_seconds=100))
    quote = replace(quote, issued_at_seconds=100)
    assert (
        verifier.verify(quote, requested_tool="ordinary_read", now_seconds=104).failure
        == VerificationFailure.CLOCK_SKEW
    )


def test_reordered_sequence_number_is_rejected() -> None:
    backend = make_reference_backend()
    verifier = LocalVerifier(backend=backend, policy=make_reference_policy(backend.log.bank.values))
    first = backend.quote(verifier.challenge("one"))
    second = backend.quote(verifier.challenge("two"))
    assert verifier.verify(second, requested_tool="ordinary_read").accepted
    assert (
        verifier.verify(first, requested_tool="ordinary_read").failure
        == VerificationFailure.REORDERED
    )


def test_tampered_signature_is_rejected() -> None:
    _backend, verifier, quote = _verified_reference("sig")
    tampered = replace(quote, signature="0" * 64)
    assert (
        verifier.verify(tampered, requested_tool="ordinary_read").failure
        == VerificationFailure.SIGNATURE
    )


def test_tampered_register_value_is_rejected() -> None:
    _backend, verifier, quote = _verified_reference("register")
    values = dict(quote.register_values)
    values[0] = "0" * 64
    tampered = replace(quote, register_values=values)
    assert (
        verifier.verify(tampered, requested_tool="ordinary_read").failure
        == VerificationFailure.SIGNATURE
    )


def test_tampered_event_hash_is_rejected() -> None:
    _backend, verifier, quote = _verified_reference("hash")
    tampered = replace(quote, event_log_hash="1" * 64)
    assert (
        verifier.verify(tampered, requested_tool="ordinary_read").failure
        == VerificationFailure.SIGNATURE
    )


def test_tampered_events_are_rejected_by_signature() -> None:
    _backend, verifier, quote = _verified_reference("events")
    event = MeasurementEvent(1, 0, "boot", "f" * 64)
    tampered = replace(quote, events=(event, *quote.events[1:]))
    assert (
        verifier.verify(tampered, requested_tool="ordinary_read").failure
        == VerificationFailure.SIGNATURE
    )


def test_reordered_event_log_with_valid_signature_is_rejected() -> None:
    backend = make_reference_backend()
    verifier = LocalVerifier(backend=backend, policy=make_reference_policy(backend.log.bank.values))
    quote = backend.quote(verifier.challenge("event-order"))
    events = (quote.events[1], quote.events[0], *quote.events[2:])
    unsigned = replace(quote, events=events, signature="")
    key = backend.keys.signing_key(quote.key_identifier)
    import hmac

    signature = hmac.digest(key, unsigned.signed_payload().encode(), "sha256").hex()
    tampered = replace(unsigned, signature=signature)
    assert (
        verifier.verify(tampered, requested_tool="ordinary_read").failure
        == VerificationFailure.EVENT_LOG
    )


def test_revoked_key_is_rejected() -> None:
    backend, verifier, quote = _verified_reference("revoked")
    backend.revoke_key(quote.key_identifier)
    assert (
        verifier.verify(quote, requested_tool="ordinary_read").failure
        == VerificationFailure.REVOKED_KEY
    )


def test_key_rotation_accepts_new_key() -> None:
    backend = make_reference_backend()
    policy = make_reference_policy(backend.log.bank.values)
    backend.rotate_key()
    verifier = LocalVerifier(backend=backend, policy=policy)
    quote = backend.quote(verifier.challenge("rotated"))
    assert verifier.verify(quote, requested_tool="ordinary_read").accepted


def test_key_rotation_preserves_old_unrevoked_key() -> None:
    backend = make_reference_backend()
    policy = make_reference_policy(backend.log.bank.values)
    verifier = LocalVerifier(backend=backend, policy=policy)
    old_quote = backend.quote(verifier.challenge("old"))
    backend.rotate_key()
    assert verifier.verify(old_quote, requested_tool="ordinary_read").accepted


def test_degraded_appraisal_allows_read_only_tool() -> None:
    backend = make_reference_backend()
    policy = make_reference_policy(backend.log.bank.values)
    backend.measure(register_index=1, label="agent runtime", content=b"changed")
    verifier = LocalVerifier(backend=backend, policy=policy)
    quote = backend.quote(verifier.challenge("degraded-read"))
    result = verifier.verify(quote, requested_tool="ordinary_read")
    assert result.accepted
    assert result.outcome == AppraisalOutcome.DEGRADED


def test_degraded_appraisal_denies_write_tool() -> None:
    backend = make_reference_backend()
    policy = make_reference_policy(backend.log.bank.values)
    backend.measure(register_index=1, label="agent runtime", content=b"changed")
    verifier = LocalVerifier(backend=backend, policy=policy)
    quote = backend.quote(verifier.challenge("degraded-write"))
    result = verifier.verify(quote, requested_tool="mutation")
    assert not result.accepted
    assert result.outcome == AppraisalOutcome.DEGRADED


def test_untrusted_appraisal_denies_any_tool() -> None:
    backend = make_reference_backend()
    policy = make_reference_policy(backend.log.bank.values)
    backend.measure(register_index=1, label="agent runtime", content=b"changed")
    backend.measure(register_index=2, label="tool manifest", content=b"changed")
    verifier = LocalVerifier(backend=backend, policy=policy)
    quote = backend.quote(verifier.challenge("untrusted"))
    result = verifier.verify(quote, requested_tool="ordinary_read")
    assert not result.accepted
    assert result.outcome == AppraisalOutcome.UNTRUSTED


def test_missing_required_event_label_is_untrusted() -> None:
    backend = SoftwareReferenceBackend("minimal", root_key=b"root")
    backend.measure(register_index=0, label="bootloader", content=b"boot")
    policy = make_reference_policy(make_reference_backend().log.bank.values)
    verifier = LocalVerifier(backend=backend, policy=policy)
    quote = backend.quote(verifier.challenge("missing"))
    assert (
        verifier.verify(quote, requested_tool="ordinary_read").outcome == AppraisalOutcome.UNTRUSTED
    )


def test_latency_is_recorded() -> None:
    _backend, verifier, quote = _verified_reference("latency")
    assert verifier.verify(quote, requested_tool="ordinary_read").latency_seconds >= 0.0


@given(st.text(min_size=1, max_size=32))
def test_property_nonce_round_trip(nonce: str) -> None:
    _backend, verifier, quote = _verified_reference(nonce)
    assert quote.nonce == nonce
    assert verifier.verify(quote, requested_tool="ordinary_read").accepted


@given(st.binary(min_size=0, max_size=64))
def test_property_runtime_tamper_never_allows_write(content: bytes) -> None:
    backend = make_reference_backend()
    policy = make_reference_policy(backend.log.bank.values)
    backend.measure(register_index=1, label="agent runtime", content=content)
    verifier = LocalVerifier(backend=backend, policy=policy)
    quote = backend.quote(verifier.challenge(content.hex() or "empty"))
    assert not verifier.verify(quote, requested_tool="mutation").accepted
