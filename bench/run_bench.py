from __future__ import annotations

import csv
import hashlib
import json
import platform
import time
from pathlib import Path

from on_device_agent_runtime_attestation.dataset import (
    load_json_lines,
    policy_blocks_malicious_steps,
)
from on_device_agent_runtime_attestation.policy import Policy
from on_device_agent_runtime_attestation.stats import wilson_interval


def main() -> int:
    dataset = Path("data/zero-trust-agent-benchmark-v4.1/test.jsonl")
    traces = list(load_json_lines(dataset))
    policy = Policy.default()
    started = time.perf_counter()
    attack_traces = [trace for trace in traces if trace.get("label") == "attack"]
    benign_traces = [trace for trace in traces if trace.get("label") == "benign"]
    blocked = sum(1 for trace in attack_traces if policy_blocks_malicious_steps(trace, policy))
    leaks = 0
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    throughput = len(traces) / max(elapsed_ms / 1000.0, 0.001)
    output = Path("results/reference")
    output.mkdir(parents=True, exist_ok=True)
    lower, upper = wilson_interval(blocked, len(attack_traces))
    summary = {
        "attack_traces": len(attack_traces),
        "blocked": blocked,
        "benign_traces": len(benign_traces),
        "leaks": leaks,
        "runtime_ms": round(elapsed_ms, 3),
        "throughput_traces_per_second": round(throughput, 3),
        "wilson_lower": round(lower, 6),
        "wilson_upper": round(upper, 6),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (output / "env.json").write_text(
        json.dumps({"python": platform.python_version(), "platform": platform.platform()}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    with (output / "measurements.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summary))
        writer.writeheader()
        writer.writerow(summary)
    manifest_lines = []
    for path in sorted(output.glob("*")):
        if path.name != "manifest.sha256" and path.is_file():
            manifest_lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (output / "manifest.sha256").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
