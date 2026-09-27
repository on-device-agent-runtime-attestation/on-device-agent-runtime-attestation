"""Runtime attestation primitives for on-device agent tool calls."""

from on_device_agent_runtime_attestation.backend import (
    AttestationBackend,
    SoftwareReferenceBackend,
    TrustedPlatformModuleToolBackend,
)
from on_device_agent_runtime_attestation.identity import IdentityDocument
from on_device_agent_runtime_attestation.measurement import Measurement, MeasurementChain
from on_device_agent_runtime_attestation.policy import Policy, ToolRequest
from on_device_agent_runtime_attestation.quote import AttestationQuote
from on_device_agent_runtime_attestation.trust import TrustState
from on_device_agent_runtime_attestation.verifier import Decision, LocalVerifier

__all__ = [
    "AttestationBackend",
    "AttestationQuote",
    "Decision",
    "IdentityDocument",
    "LocalVerifier",
    "Measurement",
    "MeasurementChain",
    "Policy",
    "SoftwareReferenceBackend",
    "ToolRequest",
    "TrustState",
    "TrustedPlatformModuleToolBackend",
]
