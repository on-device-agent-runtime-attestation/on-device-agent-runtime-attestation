from __future__ import annotations

from dataclasses import replace

import pytest

from on_device_agent_runtime_attestation.backend import (
    SoftwareReferenceBackend as LegacySoftwareReferenceBackend,
)
from on_device_agent_runtime_attestation.backend import (
    TrustedPlatformModuleToolBackend,
)
from on_device_agent_runtime_attestation.identity import IdentityDocument
from on_device_agent_runtime_attestation.measurement import Measurement, MeasurementChain
from on_device_agent_runtime_attestation.policy import Policy, ToolRequest
from on_device_agent_runtime_attestation.trust import TrustState
from on_device_agent_runtime_attestation.verifier import LocalVerifier as LegacyLocalVerifier


def _legacy_case() -> tuple[
    LegacySoftwareReferenceBackend,
    LegacyLocalVerifier,
    IdentityDocument,
    MeasurementChain,
    ToolRequest,
    TrustState,
]:
    backend = LegacySoftwareReferenceBackend(signing_key=b"legacy")
    verifier = LegacyLocalVerifier(backend, Policy.default(), allow_threshold=0.1)
    identity = IdentityDocument.for_agent("agent-1")
    chain = MeasurementChain().append(Measurement.from_bytes("runtime", b"runtime"))
    request = ToolRequest("agent-1", "fs.read", {"path": "workspace/report.txt"})
    trust = TrustState(successes=10, failures=0, exponentially_weighted_success=1.0)
    trust.record("fs.read", True)
    return backend, verifier, identity, chain, request, trust


def test_legacy_verifier_allows_valid_request() -> None:
    backend, _verifier, identity, chain, request, trust = _legacy_case()
    verifier = LegacyLocalVerifier(
        backend, Policy.default(), freshness_window_ms=1, allow_threshold=0.1
    )
    quote = backend.quote(chain, "nonce")
    result = verifier.verify(
        identity=identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce="nonce",
        expected_measurements=chain.expected_digest_map(),
        trust_state=trust,
    )
    assert result.allowed


def test_legacy_verifier_rejects_identity_domain() -> None:
    backend, verifier, identity, chain, request, trust = _legacy_case()
    quote = backend.quote(chain, "nonce")
    bad_identity = replace(
        identity, subject="spiffe://other.test/agent/agent-1", trust_domain="other.test"
    )
    result = verifier.verify(
        identity=bad_identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce="nonce",
        expected_measurements=chain.expected_digest_map(),
        trust_state=trust,
    )
    assert result.reason == "identity invalid"


def test_legacy_verifier_rejects_nonce_mismatch() -> None:
    backend, verifier, identity, chain, request, trust = _legacy_case()
    quote = backend.quote(chain, "nonce")
    result = verifier.verify(
        identity=identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce="different",
        expected_measurements=chain.expected_digest_map(),
        trust_state=trust,
    )
    assert result.reason == "nonce mismatch"


def test_legacy_verifier_rejects_stale_quote() -> None:
    backend, _verifier, identity, chain, request, trust = _legacy_case()
    verifier = LegacyLocalVerifier(
        backend, Policy.default(), freshness_window_ms=1, allow_threshold=0.1
    )
    quote = backend.quote(chain, "nonce")
    result = verifier.verify(
        identity=identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce="nonce",
        expected_measurements=chain.expected_digest_map(),
        trust_state=trust,
        now_unix_ms=quote.issued_at_unix_ms + 2,
    )
    assert result.reason == "quote stale"


def test_legacy_verifier_rejects_replay() -> None:
    backend, verifier, identity, chain, request, trust = _legacy_case()
    quote = backend.quote(chain, "nonce")
    kwargs = {
        "identity": identity,
        "role": "assistant",
        "request": request,
        "quote": quote,
        "expected_nonce": "nonce",
        "expected_measurements": chain.expected_digest_map(),
        "trust_state": trust,
    }
    assert verifier.verify(**kwargs).allowed
    assert verifier.verify(**kwargs).reason == "quote replay"


def test_legacy_verifier_rejects_signature_mismatch() -> None:
    backend, verifier, identity, chain, request, trust = _legacy_case()
    quote = replace(backend.quote(chain, "nonce"), signature="0" * 64)
    result = verifier.verify(
        identity=identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce="nonce",
        expected_measurements=chain.expected_digest_map(),
        trust_state=trust,
    )
    assert result.reason == "quote signature invalid"


def test_legacy_verifier_rejects_measurement_mismatch() -> None:
    backend, verifier, identity, chain, request, trust = _legacy_case()
    quote = backend.quote(chain, "nonce")
    result = verifier.verify(
        identity=identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce="nonce",
        expected_measurements={"runtime": "0" * 64},
        trust_state=trust,
    )
    assert result.reason == "measurement mismatch: runtime"


def test_legacy_verifier_rejects_denied_destination() -> None:
    backend, verifier, identity, chain, _request, trust = _legacy_case()
    quote = backend.quote(chain, "nonce")
    request = ToolRequest("agent-1", "email.send", {"to": "outside@example.net"})
    result = verifier.verify(
        identity=identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce="nonce",
        expected_measurements=chain.expected_digest_map(),
        trust_state=trust,
    )
    assert result.reason == "destination not allowed"


def test_legacy_verifier_rejects_low_trust() -> None:
    backend, _verifier, identity, chain, request, _trust = _legacy_case()
    verifier = LegacyLocalVerifier(backend, Policy.default(), allow_threshold=0.9)
    quote = backend.quote(chain, "nonce")
    trust = TrustState(successes=0, failures=10, exponentially_weighted_success=0.0)
    result = verifier.verify(
        identity=identity,
        role="assistant",
        request=request,
        quote=quote,
        expected_nonce="nonce",
        expected_measurements=chain.expected_digest_map(),
        trust_state=trust,
    )
    assert result.reason == "trust below threshold"


def test_hardware_tool_backend_requires_deployment_specific_quote() -> None:
    with pytest.raises(NotImplementedError):
        TrustedPlatformModuleToolBackend().quote(MeasurementChain(), "nonce")
