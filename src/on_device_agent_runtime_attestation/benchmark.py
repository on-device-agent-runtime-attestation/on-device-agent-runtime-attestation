from __future__ import annotations

import hashlib
import importlib.resources
import json
import math
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from pathlib import Path
from statistics import mean
from typing import Any, Literal, cast

from .appraisal import AppraisalOutcome, AppraisalPolicy, GoldenReference
from .execution import (
    ExecutionGate,
    ToolCallContext,
    classify_tool_risk,
    runtime_measure_tool,
)
from .protocol import LocalVerifier, make_reference_backend
from .protocol import make_reference_policy as final_reference_policy

DATASET_VERSION = "zero-trust-agent-benchmark-dataset-v4.1"
TEST_SPLIT_SHA256 = "d065bab9bed145490579cd7add6a574c6e23c21c0ea4525dc1c14b0fc15acd2b"
DEV_SPLIT_SHA256 = "4b6fcd37944e7ad85295805e8b73a4507680a87c9a09c5b1201ab43ef02d1e31"

DefenseVersion = Literal[
    "version_1",
    "per_tool_requirements",
    "fresh_appraisal_tokens",
    "taint_aware_final",
]


class RuntimeCondition(StrEnum):
    CLEAN = "clean"
    TAMPERED_RUNTIME = "tampered-runtime"
    TAMPERED_TOOL_MANIFEST = "tampered-tool-manifest"
    TAMPERED_POLICY = "tampered-policy"
    STALE_OR_REPLAYED_QUOTE = "stale-or-replayed-quote"
    ROLLED_BACK_MEASUREMENT = "rolled-back-measurement"


RUNTIME_CONDITIONS: tuple[RuntimeCondition, ...] = tuple(RuntimeCondition)
TAMPERED_CONDITIONS: tuple[RuntimeCondition, ...] = tuple(
    condition for condition in RUNTIME_CONDITIONS if condition != RuntimeCondition.CLEAN
)


@dataclass(frozen=True, slots=True)
class StepEvaluation:
    trace_id: str
    label: str
    family: str
    condition: str
    blocked: bool
    degraded: bool
    outcome: str
    reason: str
    is_attack_step: bool


@dataclass(frozen=True, slots=True)
class LatencySummary:
    trials: int
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float


@dataclass(frozen=True, slots=True)
class RateSummary:
    count: int
    total: int
    rate: float
    wilson_low: float
    wilson_high: float


@dataclass(frozen=True, slots=True)
class TamperMetric:
    condition: str
    label: str
    blocked_or_degraded_count: int
    total: int
    rate: float
    wilson_low: float
    wilson_high: float


@dataclass(frozen=True, slots=True)
class AblationEntry:
    version: str
    clean_attack_block_rate: RateSummary
    clean_false_positive_rate: RateSummary
    combined_attack_block_rate: RateSummary
    tamper_detection: tuple[TamperMetric, ...]
    latency: LatencySummary


@dataclass(frozen=True, slots=True)
class BenchmarkSummary:
    split: str
    dataset_version: str
    split_sha256: str
    defense_version: str
    trace_count: int
    attack_trace_count: int
    step_count: int
    attack_step_count: int
    benign_step_count: int
    tamper_seed: int
    clean_attack_block_rate: RateSummary
    clean_false_positive_rate: RateSummary
    combined_attack_block_rate: RateSummary
    tamper_detection: tuple[TamperMetric, ...]
    latency: LatencySummary
    evaluations: tuple[StepEvaluation, ...]
    ablation: tuple[AblationEntry, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ablation": [asdict(entry) for entry in self.ablation],
            "attack_trace_count": self.attack_trace_count,
            "clean_attack_block_rate": asdict(self.clean_attack_block_rate),
            "clean_false_positive_rate": asdict(self.clean_false_positive_rate),
            "combined_attack_block_rate": asdict(self.combined_attack_block_rate),
            "dataset_version": self.dataset_version,
            "defense_version": self.defense_version,
            "evaluations": [asdict(evaluation) for evaluation in self.evaluations],
            "latency": asdict(self.latency),
            "split": self.split,
            "split_sha256": self.split_sha256,
            "attack_step_count": self.attack_step_count,
            "benign_step_count": self.benign_step_count,
            "step_count": self.step_count,
            "tamper_detection": [asdict(metric) for metric in self.tamper_detection],
            "tamper_seed": self.tamper_seed,
            "trace_count": self.trace_count,
        }


def sibling_traces_path(repo_root: Path | None = None) -> Path | None:
    root = Path.cwd() if repo_root is None else repo_root
    candidate = root.parent / "zero-trust-agent-benchmark" / "traces"
    return candidate if candidate.exists() else None


def split_file(split: Literal["dev", "test"], traces_path: Path | None = None) -> Path:
    if traces_path is not None:
        return traces_path / f"{split}.jsonl"
    sibling = sibling_traces_path()
    if sibling is not None:
        return sibling / f"{split}.jsonl"
    package_root = importlib.resources.files("zero_trust_agent_benchmark")
    resource = package_root.joinpath("_data", "traces", f"{split}.jsonl")
    with importlib.resources.as_file(resource) as path:
        return path


def assert_split_hash(split: Literal["dev", "test"], traces_path: Path | None = None) -> str:
    expected = TEST_SPLIT_SHA256 if split == "test" else DEV_SPLIT_SHA256
    digest = hashlib.sha256(split_file(split, traces_path).read_bytes()).hexdigest()
    if digest != expected:
        msg = f"unexpected {split} split sha256 {digest}; expected {expected}"
        raise ValueError(msg)
    return digest


def load_benchmark_traces(
    split: Literal["dev", "test"], traces_path: Path | None = None
) -> list[Any]:
    assert_split_hash(split, traces_path)
    from zero_trust_agent_benchmark import load_traces
    from zero_trust_agent_benchmark.generator import DATASET_VERSION as upstream_version

    if upstream_version != DATASET_VERSION:
        raise ValueError("unexpected benchmark dataset version")
    source = traces_path or sibling_traces_path()
    return cast(list[Any], load_traces(split, source))


def wilson_interval(
    successes: int, total: int, confidence_z: float = 1.959963984540054
) -> tuple[float, float]:
    if total == 0:
        return (0.0, 0.0)
    proportion = successes / total
    z_squared = confidence_z * confidence_z
    denominator = 1 + z_squared / total
    center = proportion + z_squared / (2 * total)
    margin = confidence_z * math.sqrt(
        (proportion * (1 - proportion) + z_squared / (4 * total)) / total
    )
    return ((center - margin) / denominator, (center + margin) / denominator)


def runtime_conditions_for_step(_trace_id: str, _step_index: int) -> tuple[RuntimeCondition, ...]:
    return RUNTIME_CONDITIONS


def _version_one_tool_for_step(step: Any) -> str:
    tool = str(step.tool)
    if tool.startswith("fs.read") or tool in {"http.get", "search.query"}:
        return "read-only-file"
    if tool.startswith("fs.write"):
        return "write-file"
    if tool.startswith("http") or tool.startswith("email"):
        return "network"
    return "local-status"


def _version_one_policy(register_values: dict[int, str]) -> AppraisalPolicy:
    return AppraisalPolicy(
        golden=GoldenReference(
            register_values={index: register_values[index] for index in range(4)},
            required_labels=frozenset({"bootloader", "agent runtime", "tool manifest", "policy"}),
        ),
        degraded_allowed_tools=frozenset({"read-only-file", "local-status"}),
        trusted_allowed_tools=frozenset(
            {"read-only-file", "local-status", "network", "write-file"}
        ),
    )


def _call_from_step(step: Any) -> ToolCallContext:
    context = step.context if isinstance(step.context, dict) else {}
    origin = context.get("origin", "unknown")
    return ToolCallContext(
        tool_name=str(step.tool),
        arguments=cast(dict[str, Any], step.args),
        origin=str(origin),
        measurement_digest=runtime_measure_tool(str(step.tool)),
    )


def _tamper_backend_for_condition(condition: RuntimeCondition) -> Any:
    backend = make_reference_backend()
    if condition == RuntimeCondition.TAMPERED_RUNTIME:
        backend.measure(register_index=1, label="agent runtime", content=b"changed runtime")
    elif condition == RuntimeCondition.TAMPERED_TOOL_MANIFEST:
        backend.measure(register_index=2, label="tool manifest", content=b"changed tools")
    elif condition == RuntimeCondition.TAMPERED_POLICY:
        backend.measure(register_index=3, label="policy", content=b"changed policy")
    return backend


def _verify_step(
    *, step: Any, condition: RuntimeCondition, nonce: str, version: DefenseVersion
) -> tuple[bool, AppraisalOutcome, str]:
    clean_backend = make_reference_backend()
    backend = _tamper_backend_for_condition(condition)
    if version == "version_1":
        policy = _version_one_policy(clean_backend.log.bank.values)
        requested_tool = _version_one_tool_for_step(step)
    else:
        policy = final_reference_policy(clean_backend.log.bank.values)
        requested_tool = classify_tool_risk(_call_from_step(step)).value
    verifier = LocalVerifier(backend=backend, policy=policy)
    challenge = verifier.challenge(nonce)
    quote = backend.quote(challenge)
    now_seconds: int | None = None
    if condition == RuntimeCondition.STALE_OR_REPLAYED_QUOTE:
        now_seconds = challenge.expires_at_seconds + 1
    if condition == RuntimeCondition.ROLLED_BACK_MEASUREMENT:
        quote = replace(quote, event_log_hash="0" * 64)
    verification = verifier.verify(quote, requested_tool=requested_tool, now_seconds=now_seconds)
    if version in {"version_1", "per_tool_requirements"}:
        return (
            verification.accepted,
            verification.outcome,
            "allow" if verification.accepted else (verification.failure or "denied"),
        )
    call = _call_from_step(step)
    gate = ExecutionGate(
        token_signing_key=b"benchmark-appraisal-token-key",
        trusted_origins=frozenset({call.origin})
        if version == "fresh_appraisal_tokens"
        else frozenset({"user"}),
        enforce_context_controls=version == "taint_aware_final",
    )
    token = gate.issue_token(
        verification,
        quote_sequence_number=quote.sequence_number,
        quote_nonce=quote.nonce,
    )
    decision = gate.authorize(token=token, call=call)
    return (decision.allowed, verification.outcome, decision.reason)


def evaluate_traces(
    traces: Sequence[Any], version: DefenseVersion = "taint_aware_final"
) -> tuple[StepEvaluation, ...]:
    evaluations: list[StepEvaluation] = []
    for trace in traces:
        for step in trace.steps:
            for condition in runtime_conditions_for_step(str(trace.trace_id), int(step.step)):
                accepted, outcome, reason = _verify_step(
                    step=step,
                    condition=condition,
                    nonce=f"{trace.trace_id}-{step.step}-{condition.value}",
                    version=version,
                )
                evaluations.append(
                    StepEvaluation(
                        trace_id=str(trace.trace_id),
                        label=str(trace.label),
                        family=str(trace.family),
                        condition=condition.value,
                        blocked=not accepted,
                        degraded=outcome == AppraisalOutcome.DEGRADED,
                        outcome=outcome.value,
                        reason=str(reason),
                        is_attack_step=bool(step.malicious),
                    )
                )
    return tuple(evaluations)


@dataclass(frozen=True, slots=True)
class _SyntheticStep:
    tool: str
    args: dict[str, Any]
    context: dict[str, Any]
    malicious: bool
    step: int


def measure_latency(trials: int, version: DefenseVersion = "taint_aware_final") -> LatencySummary:
    import time

    latencies: list[float] = []
    step = _SyntheticStep("status.get", {}, {"origin": "user"}, False, 0)
    for index in range(trials):
        before = time.perf_counter()
        _verify_step(
            step=step,
            condition=RuntimeCondition.CLEAN,
            nonce=f"latency-{index}",
            version=version,
        )
        latencies.append((time.perf_counter() - before) * 1000)
    sorted_latencies = sorted(latencies)
    return LatencySummary(
        trials=trials,
        mean_ms=mean(latencies),
        p50_ms=_percentile(sorted_latencies, 0.50),
        p95_ms=_percentile(sorted_latencies, 0.95),
        p99_ms=_percentile(sorted_latencies, 0.99),
    )


def _percentile(sorted_values: Sequence[float], quantile: float) -> float:
    index = min(len(sorted_values) - 1, math.ceil(quantile * len(sorted_values)) - 1)
    return sorted_values[index]


def _rate(count: int, total: int) -> RateSummary:
    low, high = wilson_interval(count, total)
    return RateSummary(count, total, count / total if total else 0.0, low, high)


def _tamper_metrics(evaluations: Sequence[StepEvaluation]) -> tuple[TamperMetric, ...]:
    metrics: list[TamperMetric] = []
    for condition in TAMPERED_CONDITIONS:
        for label in ("benign", "attack"):
            subset = [
                evaluation
                for evaluation in evaluations
                if evaluation.condition == condition.value
                and ((label == "attack") == evaluation.is_attack_step)
            ]
            count = sum(1 for evaluation in subset if evaluation.blocked or evaluation.degraded)
            low, high = wilson_interval(count, len(subset))
            metrics.append(
                TamperMetric(
                    condition=condition.value,
                    label=label,
                    blocked_or_degraded_count=count,
                    total=len(subset),
                    rate=count / len(subset) if subset else 0.0,
                    wilson_low=low,
                    wilson_high=high,
                )
            )
    return tuple(metrics)


def _entry_from_evaluations(
    *, version: DefenseVersion, evaluations: Sequence[StepEvaluation], latency: LatencySummary
) -> AblationEntry:
    clean_attack = [
        evaluation
        for evaluation in evaluations
        if evaluation.condition == RuntimeCondition.CLEAN.value and evaluation.is_attack_step
    ]
    clean_benign = [
        evaluation
        for evaluation in evaluations
        if evaluation.condition == RuntimeCondition.CLEAN.value and not evaluation.is_attack_step
    ]
    combined_attack = [
        evaluation
        for evaluation in evaluations
        if evaluation.condition == RuntimeCondition.TAMPERED_RUNTIME.value
        and evaluation.is_attack_step
    ]
    return AblationEntry(
        version=version,
        clean_attack_block_rate=_rate(
            sum(1 for evaluation in clean_attack if evaluation.blocked), len(clean_attack)
        ),
        clean_false_positive_rate=_rate(
            sum(1 for evaluation in clean_benign if evaluation.blocked), len(clean_benign)
        ),
        combined_attack_block_rate=_rate(
            sum(1 for evaluation in combined_attack if evaluation.blocked), len(combined_attack)
        ),
        tamper_detection=_tamper_metrics(evaluations),
        latency=latency,
    )


def run_ablation(traces: Sequence[Any], *, trials: int) -> tuple[AblationEntry, ...]:
    versions: tuple[DefenseVersion, ...] = (
        "version_1",
        "per_tool_requirements",
        "fresh_appraisal_tokens",
        "taint_aware_final",
    )
    return tuple(
        _entry_from_evaluations(
            version=version,
            evaluations=evaluate_traces(traces, version),
            latency=measure_latency(trials, version),
        )
        for version in versions
    )


def run_benchmark(
    split: Literal["dev", "test"], *, trials: int, traces_path: Path | None = None
) -> BenchmarkSummary:
    split_hash = assert_split_hash(split, traces_path)
    traces = load_benchmark_traces(split, traces_path)
    evaluations = evaluate_traces(traces, "taint_aware_final")
    latency = measure_latency(trials, "taint_aware_final")
    entry = _entry_from_evaluations(
        version="taint_aware_final", evaluations=evaluations, latency=latency
    )
    return BenchmarkSummary(
        split=split,
        dataset_version=DATASET_VERSION,
        split_sha256=split_hash,
        defense_version="taint_aware_final",
        trace_count=len(traces),
        attack_trace_count=sum(1 for trace in traces if trace.label == "attack"),
        step_count=entry.clean_attack_block_rate.total + entry.clean_false_positive_rate.total,
        attack_step_count=entry.clean_attack_block_rate.total,
        benign_step_count=entry.clean_false_positive_rate.total,
        tamper_seed=0,
        clean_attack_block_rate=entry.clean_attack_block_rate,
        clean_false_positive_rate=entry.clean_false_positive_rate,
        combined_attack_block_rate=entry.combined_attack_block_rate,
        tamper_detection=entry.tamper_detection,
        latency=latency,
        evaluations=evaluations,
        ablation=run_ablation(traces, trials=trials),
    )


def write_summary(summary: BenchmarkSummary, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n"
    )
    rows = ["trace_id,label,family,condition,blocked,degraded,outcome,reason,is_attack_step"]
    for evaluation in summary.evaluations:
        rows.append(
            f"{evaluation.trace_id},{evaluation.label},{evaluation.family},{evaluation.condition},"
            f"{str(evaluation.blocked).lower()},{str(evaluation.degraded).lower()},"
            f"{evaluation.outcome},{evaluation.reason},{str(evaluation.is_attack_step).lower()}"
        )
    (out / "trials.csv").write_text("\n".join(rows) + "\n")
    (out / "ablation.json").write_text(
        json.dumps([asdict(entry) for entry in summary.ablation], indent=2, sort_keys=True) + "\n"
    )
    manifest = hashlib.sha256((out / "summary.json").read_bytes()).hexdigest()
    (out / "manifest.sha256").write_text(f"{manifest}  summary.json\n")
