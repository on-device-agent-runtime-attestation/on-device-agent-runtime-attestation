from __future__ import annotations

import importlib.util
import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from on_device_agent_runtime_attestation import benchmark
from on_device_agent_runtime_attestation.benchmark import (
    DATASET_VERSION,
    RUNTIME_CONDITIONS,
    TEST_SPLIT_SHA256,
    RuntimeCondition,
    _verify_step,
    assert_split_hash,
    evaluate_traces,
    load_benchmark_traces,
    measure_latency,
    run_benchmark,
    runtime_conditions_for_step,
    wilson_interval,
)

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("zero_trust_agent_benchmark") is None,
    reason="benchmark package is optional outside integration jobs",
)


@dataclass(frozen=True, slots=True)
class NoLabelStep:
    tool: str
    args: dict[str, object]
    context: dict[str, object]
    step: int


@dataclass(frozen=True, slots=True)
class SimpleStep:
    tool: str
    args: dict[str, object]
    context: dict[str, object]
    malicious: bool
    step: int


def test_test_split_hash_matches_pinned_value() -> None:
    assert assert_split_hash("test") == TEST_SPLIT_SHA256


def test_dev_split_hash_is_asserted() -> None:
    assert assert_split_hash("dev") == benchmark.DEV_SPLIT_SHA256


def test_dataset_version_string_is_recorded() -> None:
    assert benchmark.DATASET_VERSION == "zero-trust-agent-benchmark-dataset-v4.1"


def test_load_benchmark_traces_reads_test_split() -> None:
    traces = load_benchmark_traces("test")
    assert traces
    assert all(trace.split == "test" for trace in traces[:10])


def test_evaluate_traces_crosses_every_condition() -> None:
    traces = load_benchmark_traces("test")[:3]
    evaluations = evaluate_traces(traces)
    step_count = sum(len(trace.steps) for trace in traces)
    assert len(evaluations) == step_count * len(RUNTIME_CONDITIONS)
    assert {evaluation.condition for evaluation in evaluations} == {
        c.value for c in RUNTIME_CONDITIONS
    }


def test_clean_benign_steps_are_not_blocked_in_sample() -> None:
    traces = [trace for trace in load_benchmark_traces("test") if trace.label == "benign"][:10]
    evaluations = evaluate_traces(traces)
    clean_benign = [
        evaluation
        for evaluation in evaluations
        if evaluation.condition == RuntimeCondition.CLEAN.value and not evaluation.is_attack_step
    ]
    assert clean_benign
    assert not any(evaluation.blocked for evaluation in clean_benign)


def test_wilson_interval_contains_observed_rate() -> None:
    low, high = wilson_interval(8, 10)
    assert low < 0.8 < high


def test_wilson_interval_zero_total_is_zero_width() -> None:
    assert wilson_interval(0, 0) == (0.0, 0.0)


def test_latency_summary_uses_requested_trial_count() -> None:
    summary = measure_latency(5)
    assert summary.trials == 5
    assert summary.p95_ms >= summary.p50_ms


def test_small_benchmark_summary_is_serializable() -> None:
    summary = run_benchmark("test", trials=3)
    data = summary.to_dict()
    assert data["dataset_version"] == DATASET_VERSION
    assert json.dumps(data)


def test_sibling_trace_path_points_to_directory_when_present() -> None:
    path = benchmark.sibling_traces_path(Path.cwd())
    if path is not None:
        assert path.name == "traces"


def test_split_file_uses_real_jsonl() -> None:
    assert benchmark.split_file("test").name == "test.jsonl"


def test_verify_step_has_no_access_to_label() -> None:
    unlabeled_step = NoLabelStep("identity.grant", {"role": "reader"}, {"origin": "user"}, 0)
    benign_step = SimpleStep("identity.grant", {"role": "reader"}, {"origin": "user"}, False, 0)
    attack_step = SimpleStep("identity.grant", {"role": "reader"}, {"origin": "user"}, True, 0)
    unlabeled_decision = _verify_step(
        step=unlabeled_step,
        condition=RuntimeCondition.CLEAN,
        nonce="same-input-unlabeled",
        version="taint_aware_final",
    )
    benign_decision = _verify_step(
        step=benign_step,
        condition=RuntimeCondition.CLEAN,
        nonce="same-input-benign",
        version="taint_aware_final",
    )
    attack_decision = _verify_step(
        step=attack_step,
        condition=RuntimeCondition.CLEAN,
        nonce="same-input-attack",
        version="taint_aware_final",
    )
    assert unlabeled_decision == benign_decision == attack_decision


def test_runtime_condition_assignment_is_label_independent() -> None:
    traces = load_benchmark_traces("dev")[:200]
    counts = {"benign": 0, "attack": 0}
    tampered = {"benign": 0, "attack": 0}
    for trace in traces:
        for step in trace.steps:
            label = "attack" if step.malicious else "benign"
            conditions = runtime_conditions_for_step(str(trace.trace_id), int(step.step))
            counts[label] += len(conditions)
            tampered[label] += sum(
                1 for condition in conditions if condition != RuntimeCondition.CLEAN
            )
    benign_rate = tampered["benign"] / counts["benign"]
    attack_rate = tampered["attack"] / counts["attack"]
    assert abs(benign_rate - attack_rate) <= 0.001
