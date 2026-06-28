"""Pipeline orchestrator: runs all stages in fixed order and returns the bundle.

Fixed order (brief Section 3):
  INGEST -> FINGERPRINT -> STATIC -> ML RISK -> LLM REASON
  -> EXPLOIT POC -> CLASSIFY -> ASSEMBLE (keccak256)

Each stage appends its name to `stages` so the orchestrator can stream
progress. No stage may short-circuit the others except on hard failure.
"""

from __future__ import annotations

import os
import time

from . import bundle as bundle_mod
from . import exploit_poc, fingerprint, ingest, llm_provider, ml_model, severity, slither_runner
from .models import AnalysisRequest, AnalysisResponse


def run(req: AnalysisRequest) -> AnalysisResponse:
    stages: list[str] = []
    auditor = os.getenv("AUDITOR_ADDRESS", "0x0000000000000000000000000000000000000000")

    # 1. INGEST
    artifact = ingest.ingest(req.source, req.address, req.repo, req.commit, req.rpc_url)
    stages.append("INGEST")

    # 2. FINGERPRINT
    if artifact.mode == "address" and artifact.address:
        fp = fingerprint.fingerprint_address(artifact.address, artifact.rpc_url or "http://127.0.0.1:8545")
    else:
        fp = fingerprint.fingerprint_source(artifact.source)
    stages.append("FINGERPRINT")

    # 3. STATIC (Slither)
    detections, features = slither_runner.run_slither(artifact.source, artifact.contract_name)
    findings = slither_runner.detections_to_findings(detections)
    stages.append("STATIC")

    # 4. ML RISK (informs confidence; the baseline doesn't add new findings)
    model = ml_model.RiskModel()
    risk = model.predict(features)
    # Boost confidence on findings whose detector has high model probability.
    prob_by_detector = {c.detector: c.probability for c in risk.classes}
    for f in findings:
        if f.type in prob_by_detector:
            f.confidence = round(max(f.confidence, prob_by_detector[f.type]), 3)
    stages.append("ML_RISK")

    # 5. LLM REASON (refine existing findings + optional logic-level discovery)
    provider = llm_provider.get_provider()
    findings = [provider.refine(artifact.source, f) for f in findings]
    findings.extend(provider.discover_logic_findings(artifact.source))
    stages.append("LLM_REASON")

    # 6. EXPLOIT POC (only for supported classes)
    findings = [exploit_poc.attempt_exploit(f, artifact.source) for f in findings]
    stages.append("EXPLOIT_POC")

    # 7. CLASSIFY (severity already set per-finding; compute aggregate)
    severity_score = severity.aggregate_score(findings)
    exploit_proven = any(f.exploit_status.value == "proven" for f in findings)
    stages.append("CLASSIFY")

    # 8. ASSEMBLE
    bundle, canonical, report_hash = bundle_mod.build_bundle(
        fingerprints=fp,
        findings=findings,
        severity_score=severity_score,
        exploit_proven=exploit_proven,
        auditor=auditor,
        contract_address=artifact.address or "0x" + "0" * 40,
        timestamp=int(time.time()),
    )
    stages.append("ASSEMBLE")

    return AnalysisResponse(
        fingerprints=fp,
        findings=findings,
        severity_score=severity_score,
        exploit_proven=exploit_proven,
        bundle_canonical=canonical,
        report_hash=report_hash,
        stages=stages,
    )
