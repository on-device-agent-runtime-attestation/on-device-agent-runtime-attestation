from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .appraisal import AppraisalOutcome
from .protocol import VerificationResult


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class ToolRisk(StrEnum):
    LOCAL_STATUS = "local_status"
    ORDINARY_READ = "ordinary_read"
    SENSITIVE_READ = "sensitive_read"
    EGRESS = "egress"
    MUTATION = "mutation"
    ADMINISTRATION = "administration"


@dataclass(frozen=True, slots=True)
class ToolCallContext:
    tool_name: str
    arguments: dict[str, Any]
    origin: str
    measurement_digest: str

    @property
    def parts(self) -> tuple[str, ...]:
        normalized = self.tool_name.lower().replace("-", ".").replace("_", ".")
        return tuple(part for part in normalized.split(".") if part)

    def canonical(self) -> str:
        return _canonical_json(
            {
                "arguments": self.arguments,
                "measurement_digest": self.measurement_digest,
                "origin": self.origin,
                "tool_name": self.tool_name,
            }
        )


@dataclass(frozen=True, slots=True)
class AppraisalToken:
    token_identifier: str
    issued_at_seconds: int
    expires_at_seconds: int
    quote_sequence_number: int
    quote_nonce: str
    outcome: AppraisalOutcome
    signature: str

    def signed_payload(self) -> str:
        return _canonical_json(
            {
                "expires_at_seconds": self.expires_at_seconds,
                "issued_at_seconds": self.issued_at_seconds,
                "outcome": self.outcome.value,
                "quote_nonce": self.quote_nonce,
                "quote_sequence_number": self.quote_sequence_number,
                "token_identifier": self.token_identifier,
            }
        )


@dataclass(frozen=True, slots=True)
class GateDecision:
    allowed: bool
    reason: str
    risk: ToolRisk
    latency_seconds: float


@dataclass(frozen=True, slots=True)
class ToolMeasurementRequirement:
    required_registers: frozenset[int]
    required_event_labels: frozenset[str]


class ExecutionGate:
    def __init__(
        self,
        *,
        token_signing_key: bytes,
        token_ttl_seconds: int = 2,
        trusted_origins: frozenset[str] = frozenset({"user"}),
        enforce_context_controls: bool = True,
    ) -> None:
        self._token_signing_key = token_signing_key
        self._token_ttl_seconds = token_ttl_seconds
        self._trusted_origins = trusted_origins
        self._enforce_context_controls = enforce_context_controls
        self._used_tokens: set[str] = set()

    def issue_token(
        self,
        result: VerificationResult,
        *,
        quote_sequence_number: int,
        quote_nonce: str,
        now_seconds: int | None = None,
    ) -> AppraisalToken:
        now = int(time.time()) if now_seconds is None else now_seconds
        token = AppraisalToken(
            token_identifier=hashlib.sha256(
                f"{quote_nonce}:{quote_sequence_number}:{now}".encode()
            ).hexdigest(),
            issued_at_seconds=now,
            expires_at_seconds=now + self._token_ttl_seconds,
            quote_sequence_number=quote_sequence_number,
            quote_nonce=quote_nonce,
            outcome=result.outcome,
            signature="",
        )
        signature = hmac.digest(self._token_signing_key, token.signed_payload().encode(), "sha256")
        return AppraisalToken(
            token.token_identifier,
            token.issued_at_seconds,
            token.expires_at_seconds,
            token.quote_sequence_number,
            token.quote_nonce,
            token.outcome,
            signature.hex(),
        )

    def authorize(
        self,
        *,
        token: AppraisalToken,
        call: ToolCallContext,
        now_seconds: int | None = None,
    ) -> GateDecision:
        start = time.perf_counter()
        now = int(time.time()) if now_seconds is None else now_seconds
        risk = classify_tool_risk(call)
        reason = self._denial_reason(token, call, risk, now)
        allowed = reason is None
        return GateDecision(
            allowed=allowed,
            reason="allow" if reason is None else reason,
            risk=risk,
            latency_seconds=time.perf_counter() - start,
        )

    def _denial_reason(
        self, token: AppraisalToken, call: ToolCallContext, risk: ToolRisk, now: int
    ) -> str | None:
        if token.token_identifier in self._used_tokens:
            return "appraisal token replay"
        if now > token.expires_at_seconds:
            return "appraisal token stale"
        expected = hmac.digest(self._token_signing_key, token.signed_payload().encode(), "sha256")
        if not hmac.compare_digest(expected.hex(), token.signature):
            return "appraisal token signature invalid"
        if not tool_measurement_valid(call):
            return "tool measurement mismatch"
        if token.outcome == AppraisalOutcome.UNTRUSTED:
            return "untrusted appraisal"
        if token.outcome == AppraisalOutcome.DEGRADED:
            reason = degraded_denial_reason(call, risk, trusted_origins=self._trusted_origins)
            if reason is not None:
                return reason
        if token.outcome == AppraisalOutcome.TRUSTED and self._enforce_context_controls:
            reason = trusted_denial_reason(call, risk)
            if reason is not None:
                return reason
        self._used_tokens.add(token.token_identifier)
        return None


def classify_tool_risk(call: ToolCallContext) -> ToolRisk:
    parts = set(call.parts)
    if parts & {"admin", "grant"}:
        return ToolRisk.ADMINISTRATION
    if parts & {"exec", "delete", "write", "post", "send", "transfer"}:
        return ToolRisk.MUTATION if not (parts & {"post", "send"}) else ToolRisk.EGRESS
    statement = str(call.arguments.get("sql", "")).strip().lower()
    if statement.startswith(("delete", "drop", "alter", "insert", "update")):
        return ToolRisk.MUTATION
    if parts & {"secret", "secrets"} or _contains_secret_reference(call.arguments):
        return ToolRisk.SENSITIVE_READ
    if parts & {"query", "search", "read", "get"}:
        return ToolRisk.ORDINARY_READ
    return ToolRisk.LOCAL_STATUS


def degraded_denial_reason(
    call: ToolCallContext, risk: ToolRisk, *, trusted_origins: frozenset[str]
) -> str | None:
    if call.origin not in trusted_origins:
        return "tainted context after downgrade"
    if risk in {
        ToolRisk.ADMINISTRATION,
        ToolRisk.EGRESS,
        ToolRisk.MUTATION,
        ToolRisk.SENSITIVE_READ,
    }:
        return "sensitive tool after downgrade"
    if risk == ToolRisk.ORDINARY_READ and _is_sensitive_read(call):
        return "sensitive read after downgrade"
    return None


def trusted_denial_reason(call: ToolCallContext, risk: ToolRisk) -> str | None:
    if risk == ToolRisk.ADMINISTRATION:
        return "administrative tool requires explicit elevation"
    if call.origin == "user" and risk in {ToolRisk.MUTATION, ToolRisk.SENSITIVE_READ}:
        return "direct high privilege request requires explicit elevation"
    return None


def tool_measurement_valid(call: ToolCallContext) -> bool:
    expected = hashlib.sha256(call.tool_name.encode()).hexdigest()
    return hmac.compare_digest(expected, call.measurement_digest)


def runtime_measure_tool(tool_name: str) -> str:
    return hashlib.sha256(tool_name.encode()).hexdigest()


def measurement_requirement_for(call: ToolCallContext) -> ToolMeasurementRequirement:
    risk = classify_tool_risk(call)
    labels = {"agent runtime", "tool manifest", "policy"}
    registers = {1, 2, 3}
    if risk in {
        ToolRisk.ADMINISTRATION,
        ToolRisk.EGRESS,
        ToolRisk.MUTATION,
        ToolRisk.SENSITIVE_READ,
    }:
        labels.add("tool configuration")
        registers.add(4)
    return ToolMeasurementRequirement(frozenset(registers), frozenset(labels))


def _is_sensitive_read(call: ToolCallContext) -> bool:
    serialized = _canonical_json(call.arguments).lower()
    sensitive_words = ("credential", "private", "token", "secret", "key", "payment", "admin")
    return any(word in serialized for word in sensitive_words)


def _contains_secret_reference(arguments: dict[str, Any]) -> bool:
    serialized = _canonical_json(arguments).lower()
    return "secret:" in serialized or "token" in serialized
