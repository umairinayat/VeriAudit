"""Artifact fingerprinting (brief stage FINGERPRINT).

Computes the four identity hashes the on-chain registry commits to:
  - sourceHash    = keccak256(canonical source text)
  - commitHash    = keccak256(commit hash bytes) for repo mode, else keccak256(sourceHash)
  - bytecodeHash  = keccak256(runtime bytecode)  <-- MUST equal EXTCODEHASH
  - compilerVersion = parsed from pragma, default 0.8.20

Critical invariant: bytecodeHash MUST be keccak256 of the deployed RUNTIME
bytecode, because that's what EXTCODEHASH returns on-chain. We get the runtime
bytecode by:
  - source mode: compiling with solc --bin-runtime
  - address mode: eth_getCode at the deployed address (already runtime)
  - repo mode: clone -> compile -> bin-runtime
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

import solcx
from eth_hash.auto import keccak

from .models import Fingerprints

_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);", re.MULTILINE)
_DEFAULT_VERSION = "0.8.20"


def _keccak_hex(data: bytes) -> str:
    return "0x" + keccak(data).hex()


def parse_compiler_version(source: str) -> str:
    """Extract the highest pragma-fixed version, e.g. '^0.8.20' -> '0.8.20'."""
    m = _PRAGMA_RE.search(source)
    if not m:
        return _DEFAULT_VERSION
    spec = m.group(1).strip()
    # Take the first version-looking token and strip range operators.
    vm = re.search(r"(\d+\.\d+\.\d+)", spec)
    return vm.group(1) if vm else _DEFAULT_VERSION


def _install_if_needed(version: str) -> None:
    installed = [str(v) for v in solcx.get_installed_solc_versions()]
    if version not in installed:
        solcx.install_solc(version)


def compile_runtime_bytecode(source: str, version: str | None = None) -> tuple[str, str]:
    """Compile `source` and return (runtime_bytecode_hex, resolved_version).

    Returns the runtime bytecode (what gets deployed), NOT the creation
    bytecode. keccak256 of these bytes equals EXTCODEHASH after deployment.
    """
    version = version or parse_compiler_version(source)
    _install_if_needed(version)
    with tempfile.TemporaryDirectory(prefix="veriaudit_sol_") as tmp:
        src_path = Path(tmp) / "Contract.sol"
        src_path.write_text(source, encoding="utf-8")
        out = solcx.compile_files(
            [str(src_path)],
            output_values=["bin-runtime"],
            solc_version=version,
            optimize=True,
        )
        # output key is "<path>:<ContractName>" -> we take the first contract.
        first_key = next(iter(out))
        runtime_hex = out[first_key]["bin-runtime"]
    return runtime_hex, version


def fingerprint_source(source: str) -> Fingerprints:
    """mode='source': compile and hash."""
    version = parse_compiler_version(source)
    runtime_hex, resolved = compile_runtime_bytecode(source, version)
    source_hash = _keccak_hex(source.encode("utf-8"))
    bytecode_hash = _keccak_hex(bytes.fromhex(runtime_hex))
    commit_hash = _keccak_hex(source_hash.encode("utf-8"))  # no git -> derive from source
    return Fingerprints(
        source_hash=source_hash,
        commit_hash=commit_hash,
        bytecode_hash=bytecode_hash,
        compiler_version=resolved,
    )


def _validate_rpc_url(rpc_url: str) -> str:
    """SSRF defense: only http(s) URLs are accepted. Blocks file://, gopher://,
    ftp://, and other schemes httpx might otherwise honor."""
    from urllib.parse import urlparse

    parsed = urlparse(rpc_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"rpc_url must be http(s), got scheme {parsed.scheme!r}")
    if not parsed.hostname:
        raise ValueError("rpc_url has no hostname")
    return rpc_url


def fingerprint_address(address: str, rpc_url: str) -> Fingerprints:
    """mode='address': fetch deployed runtime bytecode via eth_getCode and hash.

    The deployed code IS runtime code, so keccak256(it) == EXTCODEHASH(address).
    Source/commit hashes are derived from the bytecode (best-effort identity).
    """
    import httpx

    rpc_url = _validate_rpc_url(rpc_url)
    resp = httpx.post(
        rpc_url,
        json={"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": [address, "latest"]},
        timeout=30.0,
    )
    resp.raise_for_status()
    code_hex = resp.json()["result"]
    if not code_hex or code_hex == "0x":
        raise ValueError(f"No bytecode at {address} (EOA or not deployed)")
    runtime_bytes = bytes.fromhex(code_hex[2:])
    bytecode_hash = _keccak_hex(runtime_bytes)
    return Fingerprints(
        source_hash=bytecode_hash,  # source unavailable for address mode
        commit_hash=_keccak_hex(bytecode_hash.encode("utf-8")),
        bytecode_hash=bytecode_hash,
        compiler_version=_DEFAULT_VERSION,  # best-effort; real value from metadata if present
    )


def _validate_repo_url(repo: str) -> str:
    """Only https:// git URLs are accepted. Blocks file://, ssh://, git://, and
    the dangerous `ext::` transport (a known GitPython/git RCE vector)."""
    lowered = repo.lower()
    if "ext::" in lowered or "file://" in lowered or "ssh://" in lowered or lowered.startswith("git@"):
        raise ValueError("repo URL must be https:// (file/ssh/ext transports blocked)")
    if not repo.lower().startswith("https://"):
        raise ValueError("repo URL must start with https://")
    return repo


def _git_sandbox_env() -> dict:
    """Harden the git subprocess env so a malicious repo can't escalate via
    hooks, fsmonitor, or interactive credential prompts."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"          # never prompt for credentials
    env["GIT_CONFIG_GLOBAL"] = os.devnull     # ignore attacker-influenced global config
    env["GIT_CONFIG_SYSTEM"] = os.devnull
    env["GIT_PROTOCOL"] = "version=2"
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "protocol.ext.allow"   # block the ext:: transport
    env["GIT_CONFIG_VALUE_0"] = "never"
    return env


def fingerprint_repo(repo: str, commit: str | None) -> tuple[Fingerprints, Path]:
    """mode='repo': shallow-clone, checkout commit, find .sol files, compile.

    Security: only https:// URLs, git env hardened, ext:: transport disabled.
    NOTE: still leaves the clone on disk under a temp dir for the caller to
    clean up (the orchestrator should rmtree when done)."""
    import shutil

    import git as gitpython

    repo = _validate_repo_url(repo)
    env = _git_sandbox_env()
    tmp = Path(tempfile.mkdtemp(prefix="veriaudit_repo_"))
    repo_path = tmp / "repo"
    try:
        gitpython.Repo.clone_from(
            repo, str(repo_path), depth=1, env=env, allow_unsafe_options=False, no_single_branch=True
        )
        real_commit = commit or "HEAD"
        try:
            subprocess.run(
                ["git", "fetch", "--depth", "1", "origin", real_commit],
                cwd=str(repo_path),
                check=True,
                capture_output=True,
                env=env,
            )
            subprocess.run(
                ["git", "checkout", real_commit], cwd=str(repo_path), check=True, capture_output=True, env=env
            )
        except subprocess.CalledProcessError:
            pass  # fall back to default checkout
        sol_files = sorted(repo_path.rglob("*.sol"))
        if not sol_files:
            raise ValueError(f"No .sol files in {repo}")
        combined = "\n".join(f.read_text(encoding="utf-8") for f in sol_files)
        fp = fingerprint_source(combined)
        fp.commit_hash = "0x" + keccak(real_commit.encode("utf-8")).hex()
        return fp, repo_path
    except Exception:
        # Always clean up the clone on failure so we don't leak disk.
        shutil.rmtree(tmp, ignore_errors=True)
        raise
