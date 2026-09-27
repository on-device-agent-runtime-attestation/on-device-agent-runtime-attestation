from __future__ import annotations

import secrets

from hypothesis import given
from hypothesis import strategies as st

from on_device_agent_runtime_attestation.backend import SoftwareReferenceBackend
from on_device_agent_runtime_attestation.identity import IdentityDocument
from on_device_agent_runtime_attestation.measurement import Measurement, MeasurementChain
from on_device_agent_runtime_attestation.policy import Policy, ToolRequest
from on_device_agent_runtime_attestation.trust import TrustState
from on_device_agent_runtime_attestation.verifier import LocalVerifier


def build_inputs() -> tuple[
    SoftwareReferenceBackend, MeasurementChain, IdentityDocument, ToolRequest, TrustState, str
]:
    chain = MeasurementChain().append(Measurement.from_bytes("runtime", b"runtime"))
    backend = SoftwareReferenceBackend(b"k" * 32)
    identity = IdentityDocument.for_agent("agent-1")
    request = ToolRequest("agent-1", "fs.read", {"path": "workspace/file.txt"})
    trust = TrustState(successes=100, failures=0, exponentially_weighted_success=1.0)
    trust.record("fs.read", True)
    return backend, chain, identity, request, trust, secrets.token_hex(16)


def test_valid_request_is_allowed() -> None:
    backend, chain, identity, request, trust, nonce = build_inputs()
    quote = backend.quote(chain, nonce)
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
    assert decision.allowed


def test_replay_is_denied() -> None:
    backend, chain, identity, request, trust, nonce = build_inputs()
    quote = backend.quote(chain, nonce)
    verifier = LocalVerifier(backend, Policy.default(), allow_threshold=0.5)
    arguments = dict(
        identity=identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce=nonce,
        expected_measurements=chain.expected_digest_map(),
        trust_state=trust,
    )
    assert verifier.verify(**arguments).allowed
    second = verifier.verify(**arguments)
    assert not second.allowed
    assert second.reason == "quote replay"


def test_stale_quote_is_denied() -> None:
    backend, chain, identity, request, trust, nonce = build_inputs()
    quote = backend.quote(chain, nonce)
    verifier = LocalVerifier(backend, Policy.default(), freshness_window_ms=1, allow_threshold=0.5)
    decision = verifier.verify(
        identity=identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce=nonce,
        expected_measurements=chain.expected_digest_map(),
        trust_state=trust,
        now_unix_ms=quote.issued_at_unix_ms + 2,
    )
    assert not decision.allowed
    assert decision.reason == "quote stale"


def test_policy_and_leak_fail_closed() -> None:
    backend, chain, identity, _request, trust, nonce = build_inputs()
    quote = backend.quote(chain, nonce)
    request = ToolRequest("agent-1", "shell.exec", {"cmd": "echo sk-value"})
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
    assert not decision.allowed


@given(st.text(min_size=1).filter(lambda value: value != "expected"))
def test_nonce_mismatch_is_denied(other_nonce: str) -> None:
    backend, chain, identity, request, trust, _nonce = build_inputs()
    quote = backend.quote(chain, other_nonce)
    verifier = LocalVerifier(backend, Policy.default(), allow_threshold=0.5)
    decision = verifier.verify(
        identity=identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce="expected",
        expected_measurements=chain.expected_digest_map(),
        trust_state=trust,
    )
    assert not decision.allowed
    assert decision.reason == "nonce mismatch"
