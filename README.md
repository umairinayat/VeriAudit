# VeriAudit

A provable, AI-assisted smart-contract security platform. Submit a Solidity contract (pasted
source, a deployed address, or a repo + commit); VeriAudit fingerprints the exact artifact, runs a
layered security engine, validates exploitability for supported vulnerability classes, and writes a
verifiable attestation **on-chain**. Anyone can later paste a contract address and confirm, on-chain,
whether the deployed bytecode matches the audited code and what the audit found.

> First-pass triage and continuous monitoring — **not** a replacement for a manual audit by
> experienced human reviewers.

## The three pillars
- **A — Smart Contract / Blockchain:** the Solidity under audit, plus an on-chain `AuditRegistry`
  with auditor registry + staking, EIP-712 signed attestations, trustless `verifyBytecode`
  (EXTCODEHASH), and full bundle stored via events + optional IPFS pin.
- **B — AI:** a layered engine — ML risk model → LLM reasoning (explanations + fixes) →
  AI-assisted Foundry PoC synthesis — behind a provider-agnostic interface (mock-first).
- **C — Cybersecurity:** Slither + custom detectors, SWC + extended taxonomy, severity scoring,
  and Foundry-based exploit validation for supported classes (reentrancy-eth, suicidal in v1).

## Pipeline
`INGEST → FINGERPRINT → STATIC → ML RISK → LLM REASON → EXPLOIT POC → CLASSIFY → ASSEMBLE
(keccak256) → ATTEST → VERIFY`

## Repo layout
```
veriaudit/
├── contracts/      # Pillar A — Solidity (Foundry): AuditRegistry.sol, 19 tests, deploy script
├── worker/         # the ONLY Python — AI analysis (FastAPI :8001, POST /analyze)
├── orchestrator/   # TypeScript (Fastify :8000) — API + EIP-712 sign + on-chain recordAudit
├── frontend/       # Vite + React + TS + wagmi/viem — matches the mockup; /verify reads chain directly
├── eval/           # Python benchmark harness (per-class P/R/FPR + exploit-confirmation rate)
└── README.md
```

## Getting started

### Prerequisites
- [Foundry](https://book.getfoundry.sh/) `forge`/`anvil`/`cast` (v1.7.1+)
- Node.js 20+ and npm
- Python 3.11+

### 1. Contracts (Pillar A)
```bash
cd contracts
./setup.sh            # or: pwsh ./setup.ps1   — vendors OZ v5.1.0 + forge-std v1.9.4 (run once)
forge build                       # compiles with via_ir (needed for the 11-field struct)
forge test --via-ir               # 19 tests
anvil                             # local chain in another terminal
forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 \
  --private-key <anvil-acct-0> --broadcast --via-ir
```
Register an auditor (the address that will sign attestations):
```bash
cast send --rpc-url http://127.0.0.1:8545 --private-key <anvil-acct-1> \
  <REGISTRY_ADDRESS> "registerAuditor()" --value 0.1ether
```

### 2. Worker (Pillar B + C, the only Python)
```bash
cd worker
pip install -r requirements.txt
# Slither + py-solc-x install solc 0.8.20 automatically on first run.
uvicorn worker.main:app --port 8001 --reload    # run from repo root
```

### 3. Orchestrator (API + on-chain attestation)
```bash
cd orchestrator
cp ../.env.example .env   # fill RPC_URL, AUDIT_REGISTRY_ADDRESS, AUDITOR_PRIVATE_KEY, AUDITOR_ADDRESS
npm install
npm run dev               # Fastify on :8000
```

### 4. Frontend
```bash
cd frontend
npm install
npm run dev               # Vite on :5173, proxies /audit /attest /verify /history to :8000
```

### 5. Eval
```bash
python -m eval.main       # runs the built-in 4-case benchmark, writes eval-results/
```

## End-to-end on local Anvil (verified)
1. `POST /audit {mode:"source", source:"<vulnerable vault>"}` → job id
2. poll `GET /audit/{id}/status` → 8 stages complete, `exploit_proven:true`
3. `GET /audit/{id}/report` → findings (reentrancy-eth, Critical, **proven**)
4. `POST /attest/{id} {contractAddress:"0x…"}` → on-chain tx hash (EIP-712 signed)
5. `GET /verify/{address}` → `matches:true` (address mode) or `matches:false` (source mode,
   correctly detecting bytecodeHash ≠ deployed EXTCODEHASH)

See `CLAUDE.md` for the project conventions and build order, and
`VeriAudit_ClaudeCode_Implementation_Brief.md` for the full specification.

## Status
Phases 1–5 implemented and verified end-to-end on local Anvil. Sepolia deploy deferred until a
funded key + RPC are provided.
