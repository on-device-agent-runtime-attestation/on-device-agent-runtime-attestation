from __future__ import annotations

from pathlib import Path

from on_device_agent_runtime_attestation.artifact_verifier import (
    benchmark_synthetic_artifact,
    merkle_tree_hash_bytes,
    merkle_tree_hash_file,
    synthetic_chunk,
)


def test_synthetic_chunk_is_deterministic() -> None:
    assert synthetic_chunk(7, 128) == synthetic_chunk(7, 128)
    assert synthetic_chunk(7, 128) != synthetic_chunk(8, 128)


def test_merkle_tree_hash_changes_with_content() -> None:
    assert merkle_tree_hash_bytes([b"one"]) != merkle_tree_hash_bytes([b"two"])


def test_merkle_file_hash_matches_byte_hash(tmp_path: Path) -> None:
    path = tmp_path / "artifact.bin"
    chunks = [b"a" * 4, b"b" * 4]
    path.write_bytes(b"".join(chunks))
    assert merkle_tree_hash_file(path, chunk_size_bytes=4) == merkle_tree_hash_bytes(chunks)


def test_synthetic_benchmark_reports_throughput() -> None:
    result = benchmark_synthetic_artifact(1024 * 1024, chunk_size_bytes=256 * 1024, workers=2)
    assert result.size_bytes == 1024 * 1024
    assert result.chunk_count == 4
    assert result.throughput_mib_per_second > 0
