"""ML risk model (brief stage ML RISK).

Provider-agnostic interface that consumes the Slither feature vector and
emits a per-class vulnerability probability with confidence. The default
implementation is a deterministic, interpretable rule-based scorer; a trained
XGBoost/scikit-learn model can drop in by implementing the same interface.

The deterministic baseline is honest: it makes no claim of being a learned
model, but it gives stable, explainable per-class risk that the eval harness
can measure improvement against.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ClassRisk:
    """Per-class risk prediction."""

    detector: str
    probability: float  # 0.0-1.0 estimated P(vuln of this class | features)
    confidence: float  # 0.0-1.0 model confidence in the estimate


@dataclass
class RiskReport:
    classes: list[ClassRisk] = field(default_factory=list)

    def top(self, k: int = 5) -> list[ClassRisk]:
        return sorted(self.classes, key=lambda c: c.probability, reverse=True)[:k]


class RiskModel:
    """Deterministic baseline. Swap for `TrainedXGBoostRiskModel` later."""

    # Per-class feature -> weight, plus a base rate. Calibrated to be cautious
    # (favor recall over precision in triage, per the brief's "first-pass" goal).
    WEIGHTS = {
        "reentrancy-eth": ({"n_reentrancy": 0.6, "n_total": 0.05}, 0.15),
        "reentrancy-no-eth": ({"n_reentrancy": 0.5, "n_total": 0.04}, 0.12),
        "arbitrary-send": ({"n_access_control": 0.55, "n_total": 0.05}, 0.10),
        "suicidal": ({"n_access_control": 0.5, "n_total": 0.04}, 0.08),
        "integer-overflow": ({"n_arithmetic": 0.6, "n_total": 0.03}, 0.10),
        "unchecked-lowlevel": ({"n_unchecked": 0.5, "n_total": 0.04}, 0.12),
        "unchecked-transfer": ({"n_unchecked": 0.45, "n_total": 0.04}, 0.10),
        "shadowing-state": ({"n_shadowing": 0.55, "n_total": 0.03}, 0.08),
    }

    def predict(self, features: dict) -> RiskReport:
        classes: list[ClassRisk] = []
        for detector, (weights, base) in self.WEIGHTS.items():
            score = base
            for feat, w in weights.items():
                score += w * float(features.get(feat, 0.0))
            prob = min(max(score, 0.0), 1.0)
            conf = 0.5 + 0.4 * min(float(features.get(feat, 0.0)) * 0.2, 1.0) if any(feat in weights for feat in weights) else 0.5
            classes.append(ClassRisk(detector=detector, probability=prob, confidence=min(conf, 0.95)))
        return RiskReport(classes=classes)
