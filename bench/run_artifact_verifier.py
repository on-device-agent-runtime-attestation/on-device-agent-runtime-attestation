from __future__ import annotations

import argparse
from pathlib import Path

from on_device_agent_runtime_attestation.artifact_verifier import (
    benchmark_synthetic_artifact,
    write_artifact_results,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("results") / "artifact-verifier")
    parser.add_argument("--chunk-size-mib", type=int, default=8)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    sizes = [256 * 1024 * 1024, 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024]
    results = [
        benchmark_synthetic_artifact(
            size,
            chunk_size_bytes=args.chunk_size_mib * 1024 * 1024,
            workers=args.workers,
        )
        for size in sizes
    ]
    write_artifact_results(results, args.out)
    for result in results:
        print(
            f"{result.size_bytes} bytes: {result.elapsed_seconds:.3f}s, "
            f"{result.throughput_mib_per_second:.1f} MiB/s"
        )


if __name__ == "__main__":
    main()
