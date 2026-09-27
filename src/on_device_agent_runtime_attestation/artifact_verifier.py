from __future__ import annotations

import hashlib
import json
import math
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class TreeHashResult:
    size_bytes: int
    chunk_size_bytes: int
    chunk_count: int
    root_digest: str
    elapsed_seconds: float
    throughput_mib_per_second: float


def synthetic_chunk(index: int, size: int) -> bytes:
    seed = hashlib.sha256(f"synthetic-artifact-chunk:{index}".encode()).digest()
    repeats = math.ceil(size / len(seed))
    return (seed * repeats)[:size]


def merkle_tree_hash_bytes(chunks: list[bytes], *, workers: int = 4) -> str:
    leaf_hashes = _hash_chunks(chunks, workers=workers)
    return _tree_root(leaf_hashes)


def merkle_tree_hash_file(
    path: Path, *, chunk_size_bytes: int = 8 * 1024 * 1024, workers: int = 4
) -> str:
    chunks: list[bytes] = []
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size_bytes), b""):
            chunks.append(chunk)
    return _tree_root(_hash_chunks(chunks, workers=workers))


def benchmark_synthetic_artifact(
    size_bytes: int, *, chunk_size_bytes: int = 8 * 1024 * 1024, workers: int = 4
) -> TreeHashResult:
    chunk_count = math.ceil(size_bytes / chunk_size_bytes)
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        leaf_hashes = list(
            executor.map(
                lambda index: _hash_leaf(
                    synthetic_chunk(
                        index,
                        min(chunk_size_bytes, size_bytes - index * chunk_size_bytes),
                    )
                ),
                range(chunk_count),
            )
        )
    root_digest = _tree_root(leaf_hashes)
    elapsed = time.perf_counter() - start
    mib = size_bytes / (1024 * 1024)
    return TreeHashResult(
        size_bytes=size_bytes,
        chunk_size_bytes=chunk_size_bytes,
        chunk_count=chunk_count,
        root_digest=root_digest,
        elapsed_seconds=elapsed,
        throughput_mib_per_second=mib / elapsed if elapsed > 0 else float("inf"),
    )


def write_artifact_results(results: list[TreeHashResult], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    payload = [asdict(result) for result in results]
    (out / "summary.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    digest = hashlib.sha256((out / "summary.json").read_bytes()).hexdigest()
    (out / "manifest.sha256").write_text(f"{digest}  summary.json\n")


def _hash_leaf(chunk: bytes) -> str:
    return hashlib.sha256(b"leaf:" + chunk).hexdigest()


def _hash_chunks(chunks: list[bytes], *, workers: int) -> list[str]:
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(_hash_leaf, chunks))


def _tree_root(hex_digests: list[str]) -> str:
    if not hex_digests:
        return hashlib.sha256(b"empty").hexdigest()
    level = list(hex_digests)
    while len(level) > 1:
        next_level: list[str] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(hashlib.sha256(("node:" + left + right).encode()).hexdigest())
        level = next_level
    return level[0]
