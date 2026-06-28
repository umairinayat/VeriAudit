"""Per-class metrics + exploit-confirmation rate.

For each detector class we compute precision / recall / FPR over the benchmark
set. Precision = TP/(TP+FP); recall = TP/(TP+FN); FPR = FP/(FP+TN). The
exploit-confirmation rate is the fraction of PROVEN findings that were on a
case whose expected class was supported_for_exploit.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class ClassMetrics:
    detector: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 1.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class EvalResult:
    per_class: dict[str, ClassMetrics] = field(default_factory=dict)
    exploit_confirmed: int = 0  # proven + on a supported case
    exploit_total_supported: int = 0  # cases that were supported_for_exploit
    macro_precision: float = 0.0
    macro_recall: float = 0.0
    macro_f1: float = 0.0
    exploit_rate: float = 0.0

    def summary(self) -> str:
        lines = ["Per-class metrics:"]
        for det, m in sorted(self.per_class.items()):
            if m.tp + m.fp + m.fn == 0:
                continue
            lines.append(
                f"  {det:24s} P={m.precision:.2f} R={m.recall:.2f} F1={m.f1():.2f} FPR={m.fpr:.2f} "
                f"(tp={m.tp} fp={m.fp} fn={m.fn})"
            )
        lines.append(f"Macro precision: {self.macro_precision:.3f}")
        lines.append(f"Macro recall:    {self.macro_recall:.3f}")
        lines.append(f"Macro F1:        {self.macro_f1:.3f}")
        lines.append(
            f"Exploit-confirmation rate: {self.exploit_rate:.2f} "
            f"({self.exploit_confirmed}/{self.exploit_total_supported} supported cases proven)"
        )
        return "\n".join(lines)


def evaluate(predictions: list[dict]) -> EvalResult:
    """`predictions` = list of {case_id, expected: set, predicted: set,
    exploit_proven: bool, supported_for_exploit: bool}."""
    # Build the universe of detector classes.
    classes: set[str] = set()
    for p in predictions:
        classes |= set(p["expected"])
        classes |= set(p["predicted"])

    per_class: dict[str, ClassMetrics] = {c: ClassMetrics(c) for c in classes}

    for p in predictions:
        expected = set(p["expected"])
        predicted = set(p["predicted"])
        for c in classes:
            e = c in expected
            pr = c in predicted
            m = per_class[c]
            if e and pr:
                m.tp += 1
            elif pr and not e:
                m.fp += 1
            elif e and not pr:
                m.fn += 1
            else:
                m.tn += 1

    res = EvalResult(per_class=per_class)
    active = [m for m in per_class.values() if m.tp + m.fp + m.fn > 0]
    if active:
        res.macro_precision = sum(m.precision for m in active) / len(active)
        res.macro_recall = sum(m.recall for m in active) / len(active)
        res.macro_f1 = sum(m.f1() for m in active) / len(active)

    for p in predictions:
        if p["supported_for_exploit"]:
            res.exploit_total_supported += 1
            if p["exploit_proven"]:
                res.exploit_confirmed += 1
    res.exploit_rate = (
        res.exploit_confirmed / res.exploit_total_supported if res.exploit_total_supported else 0.0
    )
    return res
