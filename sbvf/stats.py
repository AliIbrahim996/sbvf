"""Non-parametric statistical tests using the standard library only (no scipy).

- Mann-Whitney U with a normal approximation and a two-sided p-value.
- Vargha-Delaney A12 effect size.
"""
from __future__ import annotations

import math
import statistics


def _rank(values: list[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2 + 1  # average ranks for ties
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def mann_whitney_u(a: list[float], b: list[float]) -> tuple[float, float]:
    """Return (U, two-sided p-value) via a normal approximation."""
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0
    ranks = _rank(a + b)
    r1 = sum(ranks[:n1])
    u1 = r1 - n1 * (n1 + 1) / 2
    u2 = n1 * n2 - u1
    u = min(u1, u2)
    mu = n1 * n2 / 2
    sigma = math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12)
    if sigma == 0:
        return u, 1.0
    z = (u - mu) / sigma
    p = 2 * (1 - _norm_cdf(abs(z)))
    return u, max(0.0, min(1.0, p))


def _norm_cdf(x: float) -> float:
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))


def vargha_delaney_a12(a: list[float], b: list[float]) -> float:
    """Probability that a sample from A exceeds one from B (0.5 = no difference)."""
    n1, n2 = len(a), len(b)
    if n1 == 0 or n2 == 0:
        return 0.5
    ranks = _rank(a + b)
    r1 = sum(ranks[:n1])
    return (r1 / n1 - (n1 + 1) / 2) / n2


def effect_label(a12: float) -> str:
    d = abs(a12 - 0.5)
    if d < 0.06:
        return "negligible"
    if d < 0.14:
        return "small"
    if d < 0.21:
        return "medium"
    return "large"


def summary(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "stdev": statistics.pstdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "max": max(values),
    }
