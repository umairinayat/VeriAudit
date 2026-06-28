# VeriAudit — Project Guide for Claude Code

Provable, AI-assisted smart-contract security platform. Paste a contract → layered AI audit →
on-chain attestation → trustless verification. Source of truth:
`VeriAudit_ClaudeCode_Implementation_Brief.md`. UI source of truth: `VeriAudit_screens/VeriAudit.dc.html`.

## The three pillars (all load-bearing — never drop one)
- **A — Blockchain:** `AuditRegistry.sol` (contracts/src/) — full on-chain registry with auditor
  registry + staking, EIP-712 signed attestations, trustless `verifyBytecode` (EXTCODEHASH), and
  full bundle stored via events + optional IPFS pin. Deployed to Sepolia (test on local Anvil).
- **B — AI:** layered = ML risk model → LLM reasoning → AI-assisted Foundry PoC. Provider-agnostic
  LLM interface (mock-first). First-pass triage, NOT a human-auditor replacement.
- **C — Cybersecurity:** Slither + custom detectors, SWC + extended taxonomy, severity + 0–100
  score, exploit validation only for supported classes (reentrancy-eth, suicidal in v1).

## Pipeline (order is fixed)
INGEST → FINGERPRINT → STATIC → ML RISK → LLM REASON → EXPLOIT POC → CLASSIFY → ASSEMBLE
(keccak256) → ATTEST → VERIFY.

## Layout
- `contracts/` — Foundry (src/test/script). `AuditRegistry.sol` = the on-chain registry +
  trustless `verifyBytecode` (EXTCODEHASH). `foundry.toml` uses via_ir.
- `worker/` — **the ONLY Python.** AI analysis worker: ingest → fingerprint → Slither → ML →
  LLM (mock-first) → exploit PoC (Foundry) → classify → assemble (keccak256). FastAPI on :8001,
  single endpoint `POST /analyze`. `bytecodeHash` == keccak256(runtime bytecode) == EXTCODEHASH.
- `orchestrator/` — TypeScript (Fastify on :8000). EIP-712 signs attestations, submits
  `recordAudit` on-chain via ethers, IPFS pin stub, in-memory job store. The 6 REST endpoints.
- `frontend/` — Vite + React + TS + wagmi/viem. Matches the mockup (dark theme tokens, 7-stage
  stepper). `/verify` reads the contract directly via wagmi (decentralized; no backend needed).
- `eval/` — Python benchmark harness (per-class P/R/FPR, exploit-confirmation rate). Built-in
  dataset; append SmartBugs/DeFiHackLabs cases in `eval/datasets.py`.
- `backend/` — **removed** (replaced by `worker/` + `orchestrator/`).

## Honesty / scope rules (must hold in code AND UI)
- AI = first-pass triage + monitoring, never "replaces human auditors."
- Only supported classes can be "proven"; others = "detected-but-not-auto-validated."
- Benchmark clean set = "no known labeled vulnerabilities in the benchmark context," not "safe."
- Hashes on-chain; full bundle emitted via events + optional IPFS pin (event calldata is gas-cheap
  and immutable; storage stays compact). Heavy compute off-chain.

## Data contracts (do not drift)
- **Finding:** `{id, type, swc_id, extended_tax, severity, confidence, location{file,lines},
  explanation, suggested_fix, exploit_status}` (exploit_status ∈ proven|unconfirmed|not_supported).
- **Audit bundle:** `{contractAddress, sourceHash, commitHash, bytecodeHash, compilerVersion,
  findings, severityScore, exploitProven, timestamp, auditor}`.
  `reportHash = keccak256(canonical bundle)`.

## API surface (orchestrator = Fastify on :8000)
`POST /audit` · `GET /audit/{id}/status` · `GET /audit/{id}/report` · `POST /attest/{id}` ·
`GET /verify/{address}` · `GET /history/{address}`.

## API surface (worker = FastAPI on :8001, internal)
`POST /analyze` (source | address | repo+commit → audit bundle JSON). Called only by the orchestrator.

## Conventions
- Solidity ^0.8.20, Foundry (forge/anvil/cast). ethers + viem for chain access (TS orchestrator);
  web3.py NOT used (Python reduced to the AI worker only). Python 3.11+ (dev box runs 3.13),
  FastAPI (worker), Fastify (orchestrator), async jobs. keccak256 everywhere hashes are compared
  on-chain.
- Secrets in `.env` (never commit); see `.env.example`.
- Frontend: match the mockup exactly (themes, colors, fonts, 7-stage stepper, screen set).
  Do not invent UI.

## Build order & review gate
Follow brief Section 9 (steps 1→8). **STOP after each module for user review before continuing.**

## Current status
- **Phases 1–5 implemented and verified end-to-end on local Anvil.**
- `contracts/` — AuditRegistry.sol deployed to Anvil; 19 Foundry tests pass; record/verify
  round-trip proven live (verifyBytecodeAgainst true/false/EOA cases).
- `worker/` — full 8-stage pipeline (Slither + ML + LLM mock + Foundry PoC). Reentrancy PoC
  PROVEN on the sample vulnerable vault.
- `orchestrator/` — Fastify :8000, EIP-712 signing via ethers `signTypedData`, on-chain
  `recordAudit` + `verifyBytecode`. End-to-end on Anvil: source-mode audit → proven exploit →
  attested on-chain → verify (mismatch correctly detected; address-mode verify → match:true).
- `frontend/` — Vite + React + TS, typecheck + production build clean; mockup design tokens.
- `eval/` — 4-case built-in benchmark; per-class P/R/FPR + exploit-confirmation rate.
- Foundry v1.7.1 installed at `~/.foundry/bin` (forge/anvil/cast). OZ v5.1.0 vendored.
- LLM provider: deterministic mock behind the interface; real provider wired later via
  `worker/llm_provider.py` + `LLM_PROVIDER=openai`.
- Sepolia: build + test on local Anvil first; live deploy deferred until funded key + RPC provided.
