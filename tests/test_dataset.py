from __future__ import annotations

import json
from pathlib import Path

from on_device_agent_runtime_attestation.dataset import (
    leak_count,
    load_json_lines,
    policy_blocks_malicious_steps,
    trace_requests,
)
from on_device_agent_runtime_attestation.policy import Policy

DATASET = Path("data/zero-trust-agent-benchmark-v4.1")


def test_vendored_dataset_profile_is_version_four_one() -> None:
    profile = json.loads((DATASET / "profile.json").read_text(encoding="utf-8"))
    assert profile["dataset_version"] == "zero-trust-agent-benchmark-dataset-v4.1"
    assert profile["trust_domain"] == "acme.test"


def test_trace_loader_and_policy_blocks_some_malicious_steps() -> None:
    traces = list(load_json_lines(DATASET / "test.jsonl"))[:300]
    policy = Policy.default()
    assert traces
    assert all(trace_requests(trace) for trace in traces)
    blocked = sum(1 for trace in traces if policy_blocks_malicious_steps(trace, policy))
    assert blocked > 0


def test_reference_policy_detects_no_raw_secret_markers_in_sample() -> None:
    traces = list(load_json_lines(DATASET / "test.jsonl"))[:50]
    assert leak_count(traces, Policy.default()) == 0
