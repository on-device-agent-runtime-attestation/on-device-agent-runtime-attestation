from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
from typing import Literal, cast

from on_device_agent_runtime_attestation.benchmark import run_benchmark, write_summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["dev", "test"], default="test")
    parser.add_argument("--out", type=Path, default=Path("results") / "benchmark-test")
    parser.add_argument("--trials", type=int, default=100)
    args = parser.parse_args()
    summary = run_benchmark(cast(Literal["dev", "test"], args.split), trials=args.trials)
    write_summary(summary, args.out)
    env = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "dataset_version": summary.dataset_version,
        "split_sha256": summary.split_sha256,
    }
    (args.out / "env.json").write_text(json.dumps(env, indent=2, sort_keys=True) + "\n")
    manifest_lines = []
    import hashlib

    for result_file in sorted(args.out.glob("*")):
        if result_file.name == "manifest.sha256" or not result_file.is_file():
            continue
        manifest_lines.append(
            f"{hashlib.sha256(result_file.read_bytes()).hexdigest()}  {result_file.name}"
        )
    (args.out / "manifest.sha256").write_text("\n".join(manifest_lines) + "\n")
    print(json.dumps(summary.to_dict(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
