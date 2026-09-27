"""Runtime attestation primitives for on-device agent tool calls."""

from on_device_agent_runtime_attestation.appraisal import (
    AppraisalOutcome,
    AppraisalPolicy,
    GoldenReference,
)
from on_device_agent_runtime_attestation.event_log import (
    MeasurementEvent,
    MeasurementLog,
    RegisterBank,
)
from on_device_agent_runtime_attestation.execution import (
    AppraisalToken,
    ExecutionGate,
    GateDecision,
    ToolCallContext,
    ToolRisk,
)
from on_device_agent_runtime_attestation.protocol import (
    LocalVerifier as RuntimeLocalVerifier,
)
from on_device_agent_runtime_attestation.protocol import (
    NonceChallenge,
    RuntimeQuote,
    SoftwareReferenceBackend,
    VerificationFailure,
    VerificationResult,
    make_reference_backend,
    make_reference_policy,
)

__all__ = [
    "AppraisalOutcome",
    "AppraisalPolicy",
    "AppraisalToken",
    "ExecutionGate",
    "GateDecision",
    "GoldenReference",
    "MeasurementEvent",
    "MeasurementLog",
    "NonceChallenge",
    "RegisterBank",
    "RuntimeLocalVerifier",
    "RuntimeQuote",
    "SoftwareReferenceBackend",
    "ToolCallContext",
    "ToolRisk",
    "VerificationFailure",
    "VerificationResult",
    "make_reference_backend",
    "make_reference_policy",
]
