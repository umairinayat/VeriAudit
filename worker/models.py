"""Pydantic models = the data contracts from CLAUDE.md / brief Section 6.

These MUST stay in lock-step with the on-chain `AuditRegistry` structs and the
TS orchestrator types. Drift here breaks end-to-end integrity.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ExploitStatus(str, Enum):
    PROVEN = "proven"
    UNCONFIRMED = "unconfirmed"
    NOT_SUPPORTED = "not_supported"


class Location(BaseModel):
    file: str
    lines: list[int] = Field(default_factory=list)


class Finding(BaseModel):
    """Brief Section 6 Finding object. `exploit_status` is the honesty hinge."""

    id: str
    type: str
    swc_id: str
    extended_tax: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    location: Location
    explanation: str
    suggested_fix: str
    exploit_status: ExploitStatus


class Fingerprints(BaseModel):
    """The artifact identity committed on-chain.

    `bytecode_hash` MUST equal keccak256(runtime bytecode) so on-chain
    `verifyBytecode` (EXTCODEHASH) matches in one opcode.
    """

    source_hash: str
    commit_hash: str
    bytecode_hash: str
    compiler_version: str


class AnalysisRequest(BaseModel):
    mode: Literal["source", "address", "repo"]
    source: str | None = None  # mode="source": Solidity source text
    address: str | None = None  # mode="address": deployed contract address
    repo: str | None = None  # mode="repo": git URL
    commit: str | None = None  # mode="repo": commit hash
    rpc_url: str | None = None  # for mode="address": RPC to fetch bytecode


class AnalysisResponse(BaseModel):
    fingerprints: Fingerprints
    findings: list[Finding]
    severity_score: int = Field(ge=0, le=100)
    exploit_proven: bool
    bundle_canonical: str  # canonical JSON for keccak256 reportHash
    report_hash: str
    stages: list[str]  # completed pipeline stage names, in order
