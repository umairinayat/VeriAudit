"""Bundle assembly + keccak256 reportHash (brief stage ASSEMBLE).

Builds the canonical audit bundle (brief Section 6) and computes
`reportHash = keccak256(canonical bundle JSON)`. Canonicalization = sorted keys,
no insignificant whitespace, so Python and TypeScript compute the SAME hash.
"""

from __future__ import annotations

import json

from eth_hash.auto import keccak

from .models import Finding, Fingerprints


def _canonical_json(obj: dict) -> str:
    """Stable serialization: sort_keys, separators with no spaces."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_bundle(
    fingerprints: Fingerprints,
    findings: list[Finding],
    severity_score: int,
    exploit_proven: bool,
    auditor: str,
    contract_address: str,
    timestamp: int,
) -> tuple[dict, str, str]:
    """Return (bundle_dict, canonical_json, report_hash)."""
    bundle = {
        "contractAddress": contract_address,
        "sourceHash": fingerprints.source_hash,
        "commitHash": fingerprints.commit_hash,
        "bytecodeHash": fingerprints.bytecode_hash,
        "compilerVersion": fingerprints.compiler_version,
        "findings": [f.model_dump(mode="json") for f in findings],
        "severityScore": severity_score,
        "exploitProven": exploit_proven,
        "timestamp": timestamp,
        "auditor": auditor,
    }
    canonical = _canonical_json(bundle)
    report_hash = "0x" + keccak(canonical.encode("utf-8")).hex()
    return bundle, canonical, report_hash
