"""Severity + 0-100 aggregate score (brief stage CLASSIFY).

Weights reflect exploitability + impact, not just detector count. The aggregate
score is the worst-case-dominant blend: a single Critical dominates the score
even if everything else is clean.
"""

from __future__ import annotations

from .models import Finding, Severity

# Per-severity weight in [0,1]. Critical >> High > Medium > Low > Info.
_SEV_WEIGHT = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.6,
    Severity.MEDIUM: 0.35,
    Severity.LOW: 0.15,
    Severity.INFO: 0.05,
}


def aggregate_score(findings: list[Finding]) -> int:
    """Return a 0-100 aggregate risk score.

    Formula: take the max-weight finding as the floor (worst-case dominance),
    then add a sub-linear contribution from the rest so volume still matters
    but can't inflate a clean-ish contract beyond its worst issue.
    """
    if not findings:
        return 0
    weights_list = sorted(
        [(_SEV_WEIGHT[f.severity] * f.confidence) for f in findings],
        reverse=True,
    )
    floor = weights_list[0] * 100
    rest = sum(w * 100 for w in weights_list[1:]) ** 0.7  # sub-linear volume term
    score = floor + min(rest, 30.0)  # cap the volume contribution
    return int(min(max(score, 0), 100))
