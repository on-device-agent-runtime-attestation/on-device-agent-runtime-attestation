from __future__ import annotations

from pathlib import Path

from on_device_agent_runtime_attestation.measurement import Measurement, MeasurementChain
from on_device_agent_runtime_attestation.model_artifact import verify_artifact


def test_measurement_chain_root_changes_on_tamper() -> None:
    chain = MeasurementChain().append(Measurement.from_bytes("runtime", b"one"))
    tampered = MeasurementChain().append(Measurement.from_bytes("runtime", b"two"))
    assert chain.root_digest() != tampered.root_digest()


def test_expected_measurements_must_match() -> None:
    chain = MeasurementChain().append(Measurement.from_bytes("tool", b"content"))
    assert chain.verify_expected({"tool": chain.measurements[0].digest})
    assert not chain.verify_expected({"tool": "0" * 64})


def test_model_artifact_digest_verification(tmp_path: Path) -> None:
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"model")
    digest = Measurement.from_file("model", artifact).digest
    assert verify_artifact(artifact, digest)
    assert not verify_artifact(artifact, "0" * 64)
