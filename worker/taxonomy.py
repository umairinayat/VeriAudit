"""Vulnerability taxonomy: SWC Registry IDs + extended classes SWC misses.

SWC is old and incomplete, so we add an `extended_tax` code for classes SWC
doesn't cover well (per brief Section 2.3). This is a static lookup; detectors
emit a Slither detector key and we map it here.
"""

from __future__ import annotations

# Slither detector-class -> (swc_id, extended_tax, base_severity, supported_for_poc)
# `supported_for_poc` = True means the exploit harness can auto-validate it.
TAXONOMY: dict[str, tuple[str, str, str, bool]] = {
    # ---- Reentrancy family ----
    "reentrancy-eth": ("SWC-107", "REENT-EXTERNAL-CALL", "Critical", True),
    "reentrancy-no-eth": ("SWC-107", "REENT-STATE-MUTATION", "High", True),
    "reentrancy-benign": ("SWC-107", "REENT-BENIGN", "Medium", True),
    "reentrancy-events": ("SWC-107", "REENT-MISSING-EVENT", "Low", False),
    # ---- Access control ----
    "unprotected-upgrade": ("SWC-105", "ACCESS-UNPROXY-UPGRADE", "Critical", False),
    "suicidal": ("SWC-106", "ACCESS-SELFDESTRUCT", "Critical", True),
    "tx-origin": ("SWC-115", "ACCESS-TX-ORIGIN-AUTH", "Medium", False),
    "protected-vars": ("SWC-110", "ACCESS-PROTECTED-VAR", "Medium", False),
    "arbitrary-send": ("SWC-105", "ACCESS-ARBITRARY-SEND", "High", False),
    # ---- Arithmetic ----
    "integer-overflow": ("SWC-101", "ARITH-INTEGER-OVERFLOW", "High", False),
    "integer-underflow": ("SWC-101", "ARITH-INTEGER-UNDERFLOW", "High", False),
    "divide-before-multiply": ("SWC-116", "ARITH-DIV-BEFORE-MUL", "Low", False),
    # ---- unchecked calls / returns ----
    "unchecked-lowlevel": ("SWC-104", "CALL-UNCHECKED-LOWLEVEL", "Medium", False),
    "unchecked-transfer": ("SWC-104", "CALL-UNCHECKED-TRANSFER", "Medium", False),
    "unchecked-send": ("SWC-104", "CALL-UNCHECKED-SEND", "High", False),
    # ---- oracle / external ----
    "timestamp-dependence": ("SWC-116", "EXT-TIMESTAMP-DEPENDENCE", "Low", False),
    "block-number-dependence": ("SWC-116", "EXT-BLOCKNUMBER-DEPENDENCE", "Low", False),
    "dangerous-strict-equality": ("SWC-132", "EXT-STRICT-EQUALITY", "Medium", False),
    # ---- logic / state ----
    "shadowing-local": ("SWC-119", "STATE-LOCAL-SHADOWING", "Low", False),
    "shadowing-state": ("SWC-119", "STATE-VAR-SHADOWING", "Medium", False),
    "uninitialized-state": ("SWC-109", "STATE-UNINITIALIZED", "High", False),
    "constable-states": ("SWC-120", "STATE-SHOULD-BE-CONST", "Info", False),
    "dead-code": ("SWC-120", "STATE-DEAD-CODE", "Info", False),
    # ---- front-run / MEV (extended, SWC has weak coverage) ----
    "erc20-interface": ("SWC-116", "IFACE-ERC20-MISMATCH", "Medium", False),
    "erc721-interface": ("SWC-116", "IFACE-ERC721-MISMATCH", "Medium", False),
    "dangerous-enum-conversion": ("SWC-128", "LOGIC-ENUM-CONVERSION", "Low", False),
    "boolean-cast": ("SWC-136", "LOGIC-BOOL-CAST", "Medium", False),
    "delegatecall-loop": ("SWC-112", "DELEGATECALL-IN-LOOP", "High", False),
    # ---- default for unknown detectors ----
    "_unknown": ("SWC-111", "UNKNOWN-DETECTOR", "Medium", False),
}


def lookup(detector: str) -> tuple[str, str, str, bool]:
    """Return (swc_id, extended_tax, base_severity, supported_for_poc)."""
    return TAXONOMY.get(detector, TAXONOMY["_unknown"])


def supported_for_exploit(detector: str) -> bool:
    """Does the exploit harness support auto-validating this detector?"""
    return lookup(detector)[3]
