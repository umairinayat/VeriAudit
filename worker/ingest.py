"""Ingestion (brief stage INGEST).

Accepts the three input modes (source / address / repo+commit) and returns a
normalized artifact: the Solidity source text + a contract name + optional
deployed address. Downstream stages only consume the normalized artifact.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Artifact:
    source: str
    contract_name: str
    mode: str
    address: str | None = None
    rpc_url: str | None = None


def ingest(source: str | None, address: str | None, repo: str | None, commit: str | None, rpc_url: str | None) -> Artifact:
    if source:
        return Artifact(source=source, contract_name="Contract", mode="source")
    if address:
        # For address mode we have no source; downstream stages that need source
        # (Slither, LLM) gracefully no-op. Fingerprinting handles it directly.
        return Artifact(source="", contract_name="Contract", mode="address", address=address, rpc_url=rpc_url)
    if repo:
        from .fingerprint import fingerprint_repo

        _, repo_path = fingerprint_repo(repo, commit)
        from pathlib import Path

        sols = sorted(Path(repo_path).rglob("*.sol"))
        combined = "\n".join(f.read_text(encoding="utf-8") for f in sols) if sols else ""
        return Artifact(source=combined, contract_name="Contract", mode="repo")
    raise ValueError("Must supply source | address | repo")
