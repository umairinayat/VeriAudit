"""LLM provider interface + deterministic Mock provider (brief Section 5).

The interface is provider-agnostic so OpenAI / Anthropic / HF can plug in
without touching call sites. Default is MockProvider (deterministic) so the
pipeline runs end-to-end with zero external dependencies and no API spend.

Set `LLM_PROVIDER=openai` (and `OPENAI_API_KEY`) to swap. The mock produces
concise, honest explanations keyed off the detector class — good enough for
triage and for benchmarking explanation quality.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

from .models import Finding, Severity


class LLMProvider(ABC):
    """Reasons over a contract and refines findings with explanation + fix."""

    @abstractmethod
    def refine(self, source: str, finding: Finding) -> Finding:
        """Fill in / improve `explanation` and `suggested_fix` for a finding."""

    @abstractmethod
    def discover_logic_findings(self, source: str) -> list[Finding]:
        """Catch logic-level issues the static + ML passes missed."""


# ---------------------------------------------------------------------------
# Deterministic mock provider
# ---------------------------------------------------------------------------

# Static explanation/fix templates keyed by detector. Honest and concise.
_EXPLAIN: dict[str, tuple[str, str]] = {
    "reentrancy-eth": (
        "An external call is made before state updates are committed, letting a "
        "malicious callee re-enter this function while state is inconsistent and "
        "drain Ether. Apply the Checks-Effects-Interactions pattern or use "
        "ReentrancyGuard.",
        "Move all state writes before the external call (Checks-Effects-"
        "Interactions). For defense in depth, add a nonReentrant modifier "
        "(OpenZeppelin ReentrancyGuard) on every function that calls untrusted "
        "code.",
    ),
    "reentrancy-no-eth": (
        "External call happens before state mutation, so a reentrant callee can "
        "observe or exploit inconsistent state even though no Ether is sent.",
        "Reorder so state is fully written before any external call, or guard "
        "with a reentrancy lock.",
    ),
    "arbitrary-send": (
        "An arbitrary user-controlled address receives Ether or tokens without "
        "authorization checks, allowing anyone to drain the contract's assets.",
        "Restrict the recipient with an access-control check (e.g. onlyOwner / "
        "role-based) or require the caller to prove ownership of the recipient.",
    ),
    "suicidal": (
        "selfdestruct is callable without authorization, letting anyone destroy "
        "the contract and force-send its balance anywhere.",
        "Remove selfdestruct, or gate it behind robust access control and a "
        "timelock. Note selfdestruct semantics changed after Cancun.",
    ),
    "integer-overflow": (
        "Pre-0.8.0 arithmetic can overflow silently. Although ^0.8 has built-in "
        "checked math, this detector flags any explicit `unchecked` block or "
        "unsafe cast.",
        "Avoid unchecked{} unless you've proven the bounds. Use SafeCast for "
        "downcasts (uint256 -> uint128).",
    ),
    "unchecked-lowlevel": (
        "The return value of a low-level .call() is ignored, so a failed call "
        "silently proceeds instead of reverting.",
        "Check the (bool ok, bytes ret) return and revert with a descriptive "
        "message on failure.",
    ),
    "unchecked-transfer": (
        "The boolean return of transfer()/transferFrom()/send() is not checked, "
        "so a failed transfer may go unnoticed.",
        "Require the transfer to return true, or use OpenZeppelin's "
        "SafeERC20.safeTransfer which reverts on false.",
    ),
    "shadowing-state": (
        "A state variable is shadowed by a local or inherited name, hiding "
        "unintended state and a common source of logic bugs.",
        "Rename the shadowing identifier, or use a distinct storage layout. "
        "Run slither --detect shadowing in CI to catch regressions.",
    ),
    "tx-origin": (
        "Authorization uses tx.origin, so a phishing intermediary can act as "
        "the victim.",
        "Use msg.sender for authorization; tx.origin is only safe for "
        "EOA-only invariant checks.",
    ),
    "timestamp-dependence": (
        "Logic depends on block.timestamp, which a validator can manipulate by "
        "a few seconds — exploitable in tight-condition contracts.",
        "Avoid timestamps for strict conditions or randomness. Prefer block.number "
        "deltas or commit-reveal for randomness.",
    ),
}


class MockProvider(LLMProvider):
    """Deterministic, dependency-free triage explanations."""

    def refine(self, source: str, finding: Finding) -> Finding:
        tpl = _EXPLAIN.get(finding.type)
        if tpl:
            finding.explanation = tpl[0]
            finding.suggested_fix = tpl[1]
        elif not finding.explanation:
            finding.explanation = (
                f"Static analysis flagged a {finding.type} issue at "
                f"{finding.location.file}:{finding.location.lines}. "
                "Review the flagged location manually."
            )
        return finding

    def discover_logic_findings(self, source: str) -> list[Finding]:
        # The mock does not hallucinate logic bugs. A real LLM provider scans
        # for business-logic issues (e.g. wrong invariant, missing access check
        # on a custom function) that detectors miss. Returning [] here is the
        # honest default — no fabricated findings.
        return []


def get_provider() -> LLMProvider:
    """Factory. Reads LLM_PROVIDER env. Default = MockProvider."""
    name = os.getenv("LLM_PROVIDER", "mock").lower().strip()
    if name == "openai":
        try:  # pragma: no cover - exercised only with a real key
            from .llm_openai import OpenAIProvider  # type: ignore

            return OpenAIProvider()
        except Exception:
            pass  # fall through to mock if openai isn't wired
    return MockProvider()
