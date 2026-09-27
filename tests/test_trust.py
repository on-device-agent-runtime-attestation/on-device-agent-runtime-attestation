from __future__ import annotations

from on_device_agent_runtime_attestation.stats import wilson_interval
from on_device_agent_runtime_attestation.trust import TrustState


def test_wilson_interval_matches_registered_value() -> None:
    low, high = wilson_interval(100, 100)
    assert round(low, 3) == 0.963
    assert round(high, 3) == 1.0


def test_beta_binomial_cold_start_is_pessimistic() -> None:
    state = TrustState()
    assert state.beta_binomial_mean() == 0.5
    for _ in range(5):
        state.record("fs.read", True)
    assert round(state.beta_binomial_mean(), 2) == 0.78


def test_weighted_score_drops_after_recent_failures() -> None:
    state = TrustState(smoothing=0.3)
    for _ in range(20):
        state.record("shell.exec", True)
    before = state.exponentially_weighted_success
    for _ in range(5):
        state.record("shell.exec", False)
    assert before > 0.99
    assert state.exponentially_weighted_success < 0.5
    assert state.wilson_lower_bound() > 0.6


def test_dirichlet_action_mean_separates_actions() -> None:
    state = TrustState()
    for _ in range(20):
        state.record("fs.read", True)
    for _ in range(4):
        state.record("shell.exec", False)
    assert state.dirichlet_action_mean("fs.read") > state.dirichlet_action_mean("shell.exec")
