"""Markdown + CSV report writer."""

from __future__ import annotations

import csv
from pathlib import Path

from .metrics import EvalResult


def write_markdown(res: EvalResult, out: Path) -> None:
    lines = ["# VeriAudit Evaluation Report", "", "## Per-class metrics", ""]
    lines.append("| Detector | Precision | Recall | F1 | FPR | TP | FP | FN |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for det, m in sorted(res.per_class.items()):
        if m.tp + m.fp + m.fn == 0:
            continue
        lines.append(
            f"| {det} | {m.precision:.2f} | {m.recall:.2f} | {m.f1():.2f} | {m.fpr:.2f} | "
            f"{m.tp} | {m.fp} | {m.fn} |"
        )
    lines += [
        "",
        "## Aggregate",
        f"- Macro precision: **{res.macro_precision:.3f}**",
        f"- Macro recall: **{res.macro_recall:.3f}**",
        f"- Macro F1: **{res.macro_f1:.3f}**",
        f"- Exploit-confirmation rate: **{res.exploit_rate:.2f}** "
        f"({res.exploit_confirmed}/{res.exploit_total_supported})",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")


def write_csv(res: EvalResult, out: Path) -> None:
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["detector", "precision", "recall", "f1", "fpr", "tp", "fp", "fn"])
        for det, m in sorted(res.per_class.items()):
            if m.tp + m.fp + m.fn == 0:
                continue
            w.writerow([det, f"{m.precision:.3f}", f"{m.recall:.3f}", f"{m.f1():.3f}", f"{m.fpr:.3f}", m.tp, m.fp, m.fn])
