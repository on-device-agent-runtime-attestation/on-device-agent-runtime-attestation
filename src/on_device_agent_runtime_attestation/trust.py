from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass(slots=True)
class TrustState:
    successes: int = 0
    failures: int = 0
    exponentially_weighted_success: float = 0.5
    smoothing: float = 0.15
    action_successes: dict[str, int] = field(default_factory=dict)
    action_failures: dict[str, int] = field(default_factory=dict)

    def record(self, action: str, success: bool) -> None:
        if success:
            self.successes += 1
            self.action_successes[action] = self.action_successes.get(action, 0) + 1
            sample = 1.0
        else:
            self.failures += 1
            self.action_failures[action] = self.action_failures.get(action, 0) + 1
            sample = 0.0
        self.exponentially_weighted_success = (
            self.smoothing * sample + (1.0 - self.smoothing) * self.exponentially_weighted_success
        )

    @property
    def total(self) -> int:
        return self.successes + self.failures

    def wilson_lower_bound(self, z_value: float = 1.96) -> float:
        if self.total == 0:
            return 0.0
        proportion = self.successes / self.total
        denominator = 1.0 + z_value * z_value / self.total
        centre = proportion + z_value * z_value / (2.0 * self.total)
        spread = z_value * math.sqrt(
            proportion * (1.0 - proportion) / self.total
            + z_value * z_value / (4.0 * self.total * self.total)
        )
        return (centre - spread) / denominator

    def beta_binomial_mean(self, alpha_prior: float = 2.0, beta_prior: float = 2.0) -> float:
        return (alpha_prior + self.successes) / (
            alpha_prior + beta_prior + self.successes + self.failures
        )

    def dirichlet_action_mean(self, action: str, prior: float = 1.0) -> float:
        actions = set(self.action_successes) | set(self.action_failures) | {action}
        numerator = prior + self.action_successes.get(action, 0)
        denominator = sum(
            prior + self.action_successes.get(candidate, 0) + self.action_failures.get(candidate, 0)
            for candidate in actions
        )
        return numerator / denominator

    def combined_score(self, action: str) -> float:
        return (
            0.3 * self.wilson_lower_bound()
            + 0.2 * self.beta_binomial_mean()
            + 0.3 * self.exponentially_weighted_success
            + 0.2 * self.dirichlet_action_mean(action)
        )

    def verdict(self, action: str, *, allow_threshold: float = 0.75) -> bool:
        return self.combined_score(action) >= allow_threshold
