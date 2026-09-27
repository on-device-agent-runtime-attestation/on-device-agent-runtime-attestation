from __future__ import annotations
import math

def wilson_interval(successes: int, total: int, z_value: float = 1.96) -> tuple[float, float]:
    if total <= 0: raise ValueError("total must be positive")
    proportion = successes / total; denominator = 1.0 + z_value * z_value / total; centre = proportion + z_value * z_value / (2.0 * total)
    spread = z_value * math.sqrt(proportion * (1.0 - proportion) / total + z_value * z_value / (4.0 * total * total))
    return ((centre - spread) / denominator, (centre + spread) / denominator)

def percentile(values: list[float], percentile_value: float) -> float:
    if not values: raise ValueError("values must not be empty")
    sorted_values = sorted(values); rank = (len(sorted_values) - 1) * percentile_value; lower = math.floor(rank); upper = math.ceil(rank)
    if lower == upper: return sorted_values[int(rank)]
    return sorted_values[lower] * (upper - rank) + sorted_values[upper] * (rank - lower)
