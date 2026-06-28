"""Eval entrypoint. Runs the worker pipeline against the benchmark set.

Usage:
    python -m eval.main [--out-dir ./eval-results]

Adds the repo root to sys.path so the worker package is importable.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make the sibling `worker` package importable.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from worker.pipeline import run as run_pipeline  # noqa: E402
from worker.models import AnalysisRequest  # noqa: E402

from . import datasets, metrics as metrics_mod, report as report_mod


def main() -> int:
    ap = argparse.ArgumentParser(description="VeriAudit benchmark harness")
    ap.add_argument("--out-dir", default=str(_REPO_ROOT / "eval-results"))
    args = ap.parse_args()

    cases = datasets.load()
    print(f"Loaded {len(cases)} benchmark cases")

    predictions: list[dict] = []
    for case in cases:
        print(f"  -> {case.id} ({case.label}) ...", end=" ", flush=True)
        try:
            resp = run_pipeline(AnalysisRequest(mode="source", source=case.source))
            predicted = {f.type for f in resp.findings}
            exploit_proven = resp.exploit_proven
        except Exception as e:  # pragma: no cover
            print(f"ERROR: {e}")
            predicted = set()
            exploit_proven = False
        hit = predicted == case.expected
        print(f"predicted={sorted(predicted) or '-'} expected={sorted(case.expected) or '-'} {'OK' if hit else 'MISS'}")
        predictions.append(
            {
                "case_id": case.id,
                "expected": case.expected,
                "predicted": predicted,
                "exploit_proven": exploit_proven,
                "supported_for_exploit": case.supported_for_exploit,
            }
        )

    res = metrics_mod.evaluate(predictions)
    print()
    print(res.summary())

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report_mod.write_markdown(res, out_dir / "report.md")
    report_mod.write_csv(res, out_dir / "metrics.csv")
    print(f"\nWrote {out_dir / 'report.md'} and {out_dir / 'metrics.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
