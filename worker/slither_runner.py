"""Slither integration (brief stage STATIC).

Runs the Slither CLI on the source, parses JSON output, and converts each
detection into a Finding-shaped record (no LLM yet). Also emits a feature
vector for the ML risk model.

Slither is the deterministic backbone (brief Section 2.3). When Slither is
unavailable or the source won't compile cleanly, we degrade gracefully and
return an empty detection set rather than crash the whole pipeline.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from .models import Finding, Location, Severity
from .taxonomy import lookup

# Slither severity label -> our Severity enum.
_SLITHER_SEV = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}


def _slither_cli_available() -> bool:
    try:
        subprocess.run(["slither", "--version"], capture_output=True, timeout=20, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def run_slither(source: str, contract_name: str = "Contract") -> tuple[list[dict], dict]:
    """Run Slither on `source`. Returns (raw_detections, feature_vector).

    `feature_vector` is a compact numeric summary the ML model consumes.
    """
    if not _slither_cli_available():
        return [], {"slither_available": 0}

    with tempfile.TemporaryDirectory(prefix="veriaudit_slither_") as tmp:
        src_path = Path(tmp) / f"{contract_name}.sol"
        src_path.write_text(source, encoding="utf-8")
        proc = subprocess.run(
            [
                "slither",
                str(src_path),
                "--solc-args=--via-ir",
                "--json",
                "-",
                "--exclude-informational",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        # Slither exits non-zero when it finds issues, but JSON is still on stdout.
        stdout = proc.stdout.strip()
        if not stdout:
            return [], {"slither_available": 1}
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            return [], {"slither_available": 1}

    detections = payload.get("results", {}).get("detectors", [])
    features = _extract_features(detections)
    features["slither_available"] = 1
    return detections, features


def _extract_features(detections: list[dict]) -> dict:
    """Compact feature vector: counts per severity + per detector class."""
    feats: dict[str, float] = {
        "n_total": float(len(detections)),
        "n_high": 0.0,
        "n_medium": 0.0,
        "n_low": 0.0,
        "n_info": 0.0,
        "n_reentrancy": 0.0,
        "n_access_control": 0.0,
        "n_arithmetic": 0.0,
        "n_unchecked": 0.0,
        "n_shadowing": 0.0,
    }
    sev_bucket = {"High": "n_high", "Medium": "n_medium", "Low": "n_low", "Informational": "n_info"}
    for d in detections:
        impact = d.get("impact", "Informational")
        if impact in sev_bucket:
            feats[sev_bucket[impact]] += 1.0
        check = (d.get("check_id") or d.get("check") or "").lower()
        if "reentr" in check:
            feats["n_reentrancy"] += 1.0
        elif any(k in check for k in ("access", "suicidal", "tx-origin", "protected")):
            feats["n_access_control"] += 1.0
        elif "integer" in check:
            feats["n_arithmetic"] += 1.0
        elif "unchecked" in check:
            feats["n_unchecked"] += 1.0
        elif "shadow" in check:
            feats["n_shadowing"] += 1.0
    return feats


def detections_to_findings(detections: list[dict]) -> list[Finding]:
    """Convert Slither JSON detections to Finding objects (pre-LLM).

    Confidence is derived from Slither's confidence label; the LLM pass may
    refine it later.
    """
    findings: list[Finding] = []
    conf_map = {"High": 0.9, "Medium": 0.7, "Low": 0.5}
    for i, d in enumerate(detections):
        check = (d.get("check_id") or d.get("check") or "unknown").strip()
        swc_id, extended_tax, base_sev, supported = lookup(check)
        impact = d.get("impact", "Informational")
        # Severity: pick the MORE severe of Slither's impact and taxonomy base.
        severity = _max_severity(_SLITHER_SEV.get(impact, Severity.LOW), _sev(base_sev))
        confidence = conf_map.get(d.get("confidence", "Medium"), 0.7)
        first_el = (d.get("elements") or [{}])[0]
        loc = first_el.get("source_mapping", {})
        findings.append(
            Finding(
                id=f"F-{i + 1:03d}",
                type=check,
                swc_id=swc_id,
                extended_tax=extended_tax,
                severity=severity,
                confidence=confidence,
                location=Location(
                    file=loc.get("filename_relative", "unknown"),
                    lines=_line_range(loc),
                ),
                explanation=d.get("description", "")[:500],
                suggested_fix="",  # filled in by the LLM pass
                exploit_status="not_supported" if not supported else "unconfirmed",
            )
        )
    return findings


def _sev(label: str) -> Severity:
    try:
        return Severity(label)
    except ValueError:
        return Severity.MEDIUM


def _max_severity(a: Severity, b: Severity) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return a if order.index(a) >= order.index(b) else b


def _line_range(loc: dict) -> list[int]:
    start = (loc.get("lines") or [0])[0]
    end = (loc.get("lines") or [start])[-1]
    return [start, end] if start and end else []
