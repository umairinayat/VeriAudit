"""VeriAudit AI analysis worker.

Single responsibility: artifact in -> audit bundle JSON out. No chain access,
no API serving, no persistence. The TypeScript orchestrator (../orchestrator)
calls `POST /analyze` and handles attestation on-chain.

Pipeline (fixed order, mirrors the implementation brief Section 3):
    INGEST -> FINGERPRINT -> STATIC (Slither) -> ML RISK -> LLM REASON
    -> EXPLOIT POC -> CLASSIFY -> ASSEMBLE (keccak256)

Honesty rules (CLAUDE.md) hold here:
  - AI = first-pass triage, never a human-auditor replacement.
  - Only supported vulnerability classes can be "proven"; everything else is
    "detected-but-not-auto-validated".
  - bytecodeHash == keccak256(runtime bytecode) so it matches EXTCODEHASH on-chain.
"""

__version__ = "0.1.0"
