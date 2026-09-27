from __future__ import annotations

from dataclasses import replace

from on_device_agent_runtime_attestation.appraisal import AppraisalOutcome
from on_device_agent_runtime_attestation.execution import (
    ExecutionGate,
    ToolCallContext,
    ToolRisk,
    classify_tool_risk,
    measurement_requirement_for,
    runtime_measure_tool,
)
from on_device_agent_runtime_attestation.protocol import VerificationResult


def _result(outcome: AppraisalOutcome = AppraisalOutcome.TRUSTED) -> VerificationResult:
    return VerificationResult(True, outcome, None, True, 0.0)


def _call(tool: str, origin: str = "user", **arguments: object) -> ToolCallContext:
    return ToolCallContext(tool, arguments, origin, runtime_measure_tool(tool))


def test_risk_classifier_detects_administration() -> None:
    assert classify_tool_risk(_call("identity.grant")) == ToolRisk.ADMINISTRATION


def test_risk_classifier_detects_mutation_from_statement() -> None:
    assert (
        classify_tool_risk(_call("database.query", sql="delete from events")) == ToolRisk.MUTATION
    )


def test_risk_classifier_detects_sensitive_reference() -> None:
    assert (
        classify_tool_risk(_call("configuration.get", resource="secret://resource"))
        == ToolRisk.SENSITIVE_READ
    )


def test_degraded_gate_denies_tainted_context() -> None:
    gate = ExecutionGate(token_signing_key=b"key")
    token = gate.issue_token(
        _result(AppraisalOutcome.DEGRADED), quote_sequence_number=1, quote_nonce="n"
    )
    decision = gate.authorize(token=token, call=_call("file.read", origin="tool_output"))
    assert not decision.allowed
    assert decision.reason == "tainted context after downgrade"


def test_degraded_gate_denies_sensitive_read() -> None:
    gate = ExecutionGate(token_signing_key=b"key")
    token = gate.issue_token(
        _result(AppraisalOutcome.DEGRADED), quote_sequence_number=1, quote_nonce="n"
    )
    decision = gate.authorize(token=token, call=_call("file.read", path="private-key.txt"))
    assert not decision.allowed
    assert decision.reason == "sensitive read after downgrade"


def test_degraded_gate_allows_ordinary_user_read() -> None:
    gate = ExecutionGate(token_signing_key=b"key")
    token = gate.issue_token(
        _result(AppraisalOutcome.DEGRADED), quote_sequence_number=1, quote_nonce="n"
    )
    assert gate.authorize(token=token, call=_call("file.read", path="public.txt")).allowed


def test_gate_rejects_token_replay() -> None:
    gate = ExecutionGate(token_signing_key=b"key")
    token = gate.issue_token(_result(), quote_sequence_number=1, quote_nonce="n")
    call = _call("status.get")
    assert gate.authorize(token=token, call=call).allowed
    assert gate.authorize(token=token, call=call).reason == "appraisal token replay"


def test_gate_rejects_stale_token() -> None:
    gate = ExecutionGate(token_signing_key=b"key", token_ttl_seconds=1)
    token = gate.issue_token(_result(), quote_sequence_number=1, quote_nonce="n", now_seconds=10)
    assert (
        gate.authorize(token=token, call=_call("status.get"), now_seconds=12).reason
        == "appraisal token stale"
    )


def test_gate_rejects_bad_token_signature() -> None:
    gate = ExecutionGate(token_signing_key=b"key")
    token = gate.issue_token(_result(), quote_sequence_number=1, quote_nonce="n")
    bad = replace(token, signature="0" * 64)
    assert (
        gate.authorize(token=bad, call=_call("status.get")).reason
        == "appraisal token signature invalid"
    )


def test_gate_rejects_tool_measurement_mismatch() -> None:
    gate = ExecutionGate(token_signing_key=b"key")
    token = gate.issue_token(_result(), quote_sequence_number=1, quote_nonce="n")
    call = replace(_call("status.get"), measurement_digest="0" * 64)
    assert gate.authorize(token=token, call=call).reason == "tool measurement mismatch"


def test_measurement_requirement_adds_tool_configuration_for_egress() -> None:
    requirement = measurement_requirement_for(_call("mail.send"))
    assert 4 in requirement.required_registers
    assert "tool configuration" in requirement.required_event_labels


def test_untrusted_appraisal_denies_tool() -> None:
    gate = ExecutionGate(token_signing_key=b"key")
    token = gate.issue_token(
        _result(AppraisalOutcome.UNTRUSTED), quote_sequence_number=1, quote_nonce="n"
    )
    assert gate.authorize(token=token, call=_call("status.get")).reason == "untrusted appraisal"
