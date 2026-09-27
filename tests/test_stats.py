from __future__ import annotations

import pytest

from on_device_agent_runtime_attestation.stats import percentile, wilson_interval


def test_stats_wilson_interval_contains_rate() -> None:
    low, high = wilson_interval(50, 100)
    assert low < 0.5 < high


def test_stats_wilson_interval_rejects_zero_total() -> None:
    with pytest.raises(ValueError, match="positive"):
        wilson_interval(0, 0)


def test_stats_percentile_interpolates() -> None:
    assert percentile([0.0, 10.0], 0.5) == 5.0


def test_stats_percentile_rejects_empty_values() -> None:
    with pytest.raises(ValueError, match="empty"):
        percentile([], 0.5)
