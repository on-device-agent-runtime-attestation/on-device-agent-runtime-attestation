from __future__ import annotations

import hashlib
from pathlib import Path

from on_device_agent_runtime_attestation.dataset import (
    leak_count,
    load_json_lines,
    policy_blocks_malicious_steps,
    trace_requests,
)
from on_device_agent_runtime_attestation.identity import IdentityDocument
from on_device_agent_runtime_attestation.measurement import Measurement, MeasurementChain
from on_device_agent_runtime_attestation.model_artifact import verify_artifact
from on_device_agent_runtime_attestation.policy import Policy, ToolRequest
from on_device_agent_runtime_attestation.quote import AttestationQuote
from on_device_agent_runtime_attestation.trust import TrustState

FIXTURE = Path("tests") / "fixtures" / "sample.jsonl"


def test_load_json_lines_reads_fixture() -> None:
    assert len(list(load_json_lines(FIXTURE))) == 2


def test_trace_requests_extracts_all_tool_calls() -> None:
    trace = next(load_json_lines(FIXTURE))
    requests = trace_requests(trace)
    assert [request.tool for request in requests] == ["fs.read", "email.send"]


def test_policy_blocks_malicious_steps_detects_allowed_malicious_call() -> None:
    trace = next(load_json_lines(FIXTURE))
    assert not policy_blocks_malicious_steps(trace, Policy.default())


def test_leak_count_detects_secret_markers() -> None:
    trace = {
        "agent": {"agent_id": "agent", "role": "assistant"},
        "steps": [{"tool": "email.send", "args": {"body": "contains sk-marker"}}],
    }
    assert leak_count([trace], Policy.default()) == 1


def test_measurement_chain_root_changes_on_tamper() -> None:
    first = MeasurementChain().append(Measurement.from_bytes("runtime", b"one"))
    second = MeasurementChain().append(Measurement.from_bytes("runtime", b"two"))
    assert first.root_digest() != second.root_digest()


def test_measurement_chain_expected_measurements() -> None:
    chain = MeasurementChain().append(Measurement.from_bytes("tool", b"content"))
    assert chain.verify_expected({"tool": chain.measurements[0].digest})
    assert not chain.verify_expected({"tool": "0" * 64})


def test_measurement_chain_rejects_duplicate_names() -> None:
    chain = MeasurementChain().append(Measurement.from_bytes("runtime", b"one"))
    chain = chain.append(Measurement.from_bytes("runtime", b"two"))
    assert not chain.verify_expected({"runtime": chain.measurements[0].digest})


def test_identity_document_for_agent_uses_local_domain() -> None:
    identity = IdentityDocument.for_agent("agent-1")
    assert identity.subject.endswith("/agent/agent-1")
    assert identity.trust_domain == "example.local"


def test_policy_allows_known_tool_for_assistant() -> None:
    assert Policy.default().tool_allowed("assistant", ToolRequest("agent", "fs.read", {}))


def test_policy_denies_unknown_tool() -> None:
    assert not Policy.default().tool_allowed("assistant", ToolRequest("agent", "shell.exec", {}))


def test_policy_blocks_untrusted_destination() -> None:
    request = ToolRequest("agent", "email.send", {"to": "case@example.net"})
    assert not Policy.default().destination_allowed(request)


def test_policy_allows_workspace_path() -> None:
    request = ToolRequest("agent", "fs.read", {"path": "workspace/report.txt"})
    assert Policy.default().destination_allowed(request)


def test_trust_state_records_successes_and_failures() -> None:
    trust = TrustState(successes=0, failures=0, exponentially_weighted_success=0.5)
    trust.record("fs.read", True)
    trust.record("fs.write", False)
    assert trust.successes == 1
    assert trust.failures == 1


def test_trust_score_reflects_success_rate() -> None:
    high = TrustState(9, 1, 0.9)
    low = TrustState(1, 9, 0.1)
    assert high.combined_score("fs.read") > low.combined_score("fs.read")


def test_artifact_verification_accepts_matching_digest() -> None:
    path = Path("tests") / "fixtures" / "model.bin"
    assert verify_artifact(path, hashlib.sha256(path.read_bytes()).hexdigest())


def test_artifact_verification_rejects_wrong_digest() -> None:
    assert not verify_artifact(Path("tests") / "fixtures" / "model.bin", "0" * 64)


def test_quote_payload_binds_nonce_and_measurements() -> None:
    chain = MeasurementChain().append(Measurement.from_bytes("runtime", b"runtime"))
    payload = AttestationQuote.payload("software", "nonce", 1, 1, chain)
    assert b"nonce" in payload
    assert chain.root_digest().encode() in payload
