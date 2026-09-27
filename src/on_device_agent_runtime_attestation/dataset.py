from __future__ import annotations

import importlib.resources
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from on_device_agent_runtime_attestation.policy import Policy, ToolRequest


def packaged_dataset_path() -> Path:
    files = importlib.resources.files("on_device_agent_runtime_attestation")
    return Path(str(files / "_data" / "zero-trust-agent-benchmark-v4.1"))


def load_json_lines(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                value = json.loads(line)
                if isinstance(value, dict):
                    yield value


def trace_requests(trace: dict[str, Any]) -> list[ToolRequest]:
    agent = trace.get("agent", {})
    agent_identifier = str(agent.get("agent_id", "unknown"))
    requests: list[ToolRequest] = []
    for step in trace.get("steps", []):
        if isinstance(step, dict):
            arguments = step.get("args", {})
            if isinstance(arguments, dict):
                requests.append(
                    ToolRequest(agent_identifier, str(step.get("tool", "unknown")), arguments)
                )
    return requests


def policy_blocks_malicious_steps(trace: dict[str, Any], policy: Policy) -> bool:
    role = str(trace.get("agent", {}).get("role", "assistant"))
    for step, request in zip(trace.get("steps", []), trace_requests(trace), strict=False):
        if (
            isinstance(step, dict)
            and step.get("malicious") is True
            and policy.tool_allowed(role, request)
            and policy.destination_allowed(request)
        ):
            return False
    return True


def leak_count(traces: list[dict[str, Any]], policy: Policy) -> int:
    count = 0
    for trace in traces:
        for request in trace_requests(trace):
            if policy.contains_secret_marker(request):
                count += 1
    return count
