from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AppraisalOutcome(StrEnum):
    TRUSTED = "trusted"
    DEGRADED = "degraded"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True, slots=True)
class GoldenReference:
    register_values: dict[int, str]
    required_labels: frozenset[str]


@dataclass(frozen=True, slots=True)
class AppraisalPolicy:
    golden: GoldenReference
    degraded_allowed_tools: frozenset[str]
    trusted_allowed_tools: frozenset[str]

    def appraise(self, register_values: dict[int, str], labels: set[str]) -> AppraisalOutcome:
        mismatches = [
            index
            for index, digest in self.golden.register_values.items()
            if register_values.get(index) != digest
        ]
        if not self.golden.required_labels.issubset(labels):
            return AppraisalOutcome.UNTRUSTED
        if not mismatches:
            return AppraisalOutcome.TRUSTED
        if len(mismatches) == 1:
            return AppraisalOutcome.DEGRADED
        return AppraisalOutcome.UNTRUSTED

    def tool_allowed(self, outcome: AppraisalOutcome, tool: str) -> bool:
        if outcome == AppraisalOutcome.TRUSTED:
            return tool in self.trusted_allowed_tools
        if outcome == AppraisalOutcome.DEGRADED:
            return tool in self.degraded_allowed_tools
        return False
