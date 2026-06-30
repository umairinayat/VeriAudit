"""Debug runner: executes the worker pipeline stage-by-stage with verbose
output so you can SEE each AI layer's input and output. Run:

    python scripts/trace_pipeline.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from worker import bundle as bundle_mod  # noqa: E402
from worker import exploit_poc, fingerprint, llm_provider, ml_model, severity, slither_runner  # noqa: E402
from worker.models import AnalysisRequest  # noqa: E402

VULN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract VulnerableVault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""

def hr(t: str) -> None:
    print(f"\n{'='*70}\n {t}\n{'='*70}")

def main() -> None:
    req = AnalysisRequest(mode="source", source=VULN)
    print(f"INPUT: {req.mode} mode, {len(req.source)} chars of Solidity")

    hr("STAGE 1 — INGEST")
    from worker import ingest
    artifact = ingest.ingest(req.source, req.address, req.repo, req.commit, req.rpc_url)
    print(f"  normalized artifact: mode={artifact.mode}, contract={artifact.contract_name}")

    hr("STAGE 2 — FINGERPRINT (deterministic)")
    fp = fingerprint.fingerprint_source(artifact.source)
    print(f"  source_hash:    {fp.source_hash}")
    print(f"  bytecode_hash:  {fp.bytecode_hash}   <-- must equal EXTCODEHASH")
    print(f"  compiler:       {fp.compiler_version}")

    hr("STAGE 3 — STATIC (Slither, deterministic backbone)")
    detections, features = slither_runner.run_slither(artifact.source, artifact.contract_name)
    print(f"  slither detections: {len(detections)}")
    for d in detections:
        print(f"    - {d.get('check_id','?'):30s} impact={d.get('impact'):14s} conf={d.get('confidence')}")
    print(f"  feature vector extracted for ML: {features}")
    findings = slither_runner.detections_to_findings(detections)

    hr("STAGE 4 — AI LAYER #1: ML RISK MODEL")
    model = ml_model.RiskModel()
    risk = model.predict(features)
    print(f"  provider: {model.__class__.__name__} (deterministic baseline; XGBoost can drop in)")
    print("  per-class predictions (top 5 by probability):")
    for c in risk.top(5):
        print(f"    - {c.detector:24s} P={c.probability:.2f}  confidence={c.confidence:.2f}")
    prob_by_detector = {c.detector: c.probability for c in risk.classes}
    for f in findings:
        if f.type in prob_by_detector:
            print(f"  -> boosting '{f.type}' confidence {f.confidence} -> {round(max(f.confidence, prob_by_detector[f.type]),3)}")
            f.confidence = round(max(f.confidence, prob_by_detector[f.type]), 3)

    hr("STAGE 5 — AI LAYER #2: LLM REASONING (explanations + fixes)")
    provider = llm_provider.get_provider()
    print(f"  provider: {provider.__class__.__name__} (set LLM_PROVIDER=openai to swap)")
    print(f"  refining {len(findings)} finding(s)...")
    findings = [provider.refine(artifact.source, f) for f in findings]
    discovered = provider.discover_logic_findings(artifact.source)
    print(f"  additional logic-level findings discovered: {len(discovered)} (mock returns [] — never fabricates)")
    findings.extend(discovered)
    for f in findings:
        print(f"\n  [{f.id}] {f.type} ({f.severity}, conf={f.confidence})")
        print(f"    explanation: {f.explanation}")
        if f.suggested_fix:
            print(f"    suggested_fix: {f.suggested_fix[:120]}...")

    hr("STAGE 6 — AI LAYER #3: EXPLOIT PoC (Foundry, only supported classes)")
    print(f"  forge available: {exploit_poc._FORGE is not None}")
    findings = [exploit_poc.attempt_exploit(f, artifact.source) for f in findings]
    for f in findings:
        print(f"  [{f.id}] {f.type}: exploit_status = {f.exploit_status.value}")
        if f.exploit_status.value == "proven":
            print(f"        ^^ generated Foundry test compiled + PASSED -> proven")

    hr("STAGE 7 — CLASSIFY (severity + 0-100 score)")
    score = severity.aggregate_score(findings)
    exploit_proven = any(f.exploit_status.value == "proven" for f in findings)
    print(f"  aggregate severity score: {score}/100")
    print(f"  exploit_proven: {exploit_proven}")

    hr("STAGE 8 — ASSEMBLE (keccak256 reportHash)")
    bundle, canonical, report_hash = bundle_mod.build_bundle(
        fingerprints=fp, findings=findings, severity_score=score,
        exploit_proven=exploit_proven, auditor="0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
        contract_address="0x" + "0"*40, timestamp=int(time.time()),
    )
    print(f"  report_hash = keccak256(canonical bundle) = {report_hash}")
    print(f"  bundle size: {len(canonical)} bytes canonical JSON")

    hr("DONE — pipeline complete")
    print(f"  {len(findings)} finding(s), score {score}, exploit_proven={exploit_proven}")
    print(f"  This bundle would now be EIP-712 signed + submitted via recordAudit().")

if __name__ == "__main__":
    main()
