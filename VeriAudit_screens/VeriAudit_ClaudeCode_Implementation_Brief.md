# VeriAudit — Implementation Brief for Claude Code

> **Build target:** A provable, AI-assisted smart contract security platform that detects vulnerabilities, validates exploitability for supported classes, explains findings in plain language, and writes a verifiable attestation **on-chain** bound to the exact audited artifact.

This brief is written to be handed directly to Claude Code. It describes what to build, how the three pillars (**Smart Contract / Blockchain**, **AI**, **Cybersecurity**) work together, the exact components, the tech stack, the data contracts between modules, and the build order. Read the whole brief before starting; build in the order given in Section 9.

---

## 1. What You Are Building (one paragraph)

VeriAudit is a full-stack platform where a developer submits a Solidity contract (as pasted source, a deployed address, or a git repo + commit). The backend computes a cryptographic fingerprint of the exact artifact (source hash, commit hash, compiler version, deployed bytecode hash), then runs a **layered security engine**: Slither static analysis → an ML risk model → an LLM reasoning/explanation pass → an automated exploit proof-of-concept generator for supported vulnerability classes. Findings are mapped to a security taxonomy (SWC + extended) and scored by severity. The full report is hashed, and an **on-chain `AuditRegistry` smart contract** records the artifact fingerprints, severity, and an `exploitProven` flag, producing a trustless, verifiable attestation. Anyone can later paste a contract address and confirm, on-chain, whether the deployed bytecode matches the audited code and what the audit found.

The three pillars are **load-bearing**: remove any one and the product collapses.

---

## 2. The Three Pillars (explicit)

### 2.1 Pillar A — Smart Contract / Blockchain (REQUIRED, dual role)

The blockchain pillar appears in **two distinct ways**, and both must be implemented:

**(a) As the subject of analysis.** The thing being audited is itself a smart contract. The system ingests Solidity source / deployed bytecode and analyzes it.

**(b) As the verification infrastructure.** You will write, test, and deploy a Solidity smart contract called `AuditRegistry` to a testnet (Sepolia). It:
- Stores per-contract audit records on-chain: `sourceHash`, `commitHash`, `bytecodeHash`, `reportHash`, `compilerVersion`, `severityScore`, `exploitProven`, `timestamp`, `auditor`.
- Keeps an **audit history** (array per contract address), not just the latest.
- Exposes `recordAudit(...)`, `latestAudit(address)`, `auditCount(address)`, and the key function `verifyBytecode(address, bytes32 currentBytecodeHash)` which returns whether the live deployed bytecode matches the audited code, plus severity and `exploitProven`.

**Production note to respect in the design:** store only **hashes/commitments on-chain** for gas efficiency; keep the detailed signed report bundle **off-chain** (IPFS / Arweave / server) with the on-chain hash proving integrity. Optionally support **EIP-712** typed signatures for attestations and add access control / staking on `recordAudit` so only registered auditors can attest.

> Deliverable for this pillar: a tested Solidity `AuditRegistry` contract, deployment scripts (Foundry or Hardhat), and a Python web3 client in the backend that writes audits and reads verifications.

### 2.2 Pillar B — AI (REQUIRED, layered, not single-model)

AI is **not** a single model call. It is a layered engine:

1. **ML risk model** — takes features extracted from static analysis + AST/bytecode and predicts a per-class vulnerability probability with a confidence score. (XGBoost or a small transformer over features.)
2. **LLM reasoning layer** — reasons over the source to catch logic-level issues the classifier misses, and generates **plain-language explanations** and **suggested fixes** for every finding. (OpenAI or a Hugging Face model behind a clean interface so the provider is swappable.)
3. **AI-assisted exploit synthesis** — for supported vulnerability classes, the LLM helps generate a Foundry proof-of-concept test that the system then actually runs to confirm exploitability.

The honest scope, which must be reflected in code and UI: **AI is first-pass triage + continuous monitoring, not a replacement for human auditors.**

> Deliverable for this pillar: a `detection/` package with a clean interface — input = compiled contract + static features, output = a structured list of findings each with `{type, swc_id, severity, confidence, location, explanation, suggested_fix, exploit_status}`.

### 2.3 Pillar C — Cybersecurity (REQUIRED, the domain logic)

Cybersecurity is the domain expertise layer that turns raw detections into a professional, structured security report:

- **Vulnerability taxonomy:** map every finding to an **SWC Registry** ID plus an **extended taxonomy** for classes SWC misses (SWC is old and incomplete).
- **Static analysis:** integrate **Slither** and any custom detectors as the deterministic backbone of detection.
- **Exploit validation:** generate and execute **Foundry / fork-based proof-of-concept** tests for supported vulnerability classes (e.g. reentrancy, access control, unchecked external calls, certain arithmetic bugs). Classes outside support are reported as **detected-but-not-auto-validated**, never as "proven."
- **Severity scoring:** assign Critical / High / Medium / Low based on exploitability + impact, and compute an aggregate 0–100 risk score.

> Deliverable for this pillar: a `security/` package handling Slither integration, taxonomy mapping, severity scoring, and the Foundry PoC generation + execution harness.

---

## 3. End-to-End Flow (what the code must do, in order)

```
1. INGEST          accept source | address | repo+commit
2. FINGERPRINT     compute sourceHash, commitHash, compilerVersion, deployed bytecodeHash   [Pillar A]
3. STATIC          run Slither + custom detectors, extract features                          [Pillar C]
4. ML RISK         per-class vulnerability probability + confidence                          [Pillar B]
5. LLM REASON      logic bugs + plain-language explanations + suggested fixes                [Pillar B]
6. EXPLOIT POC     for supported classes: generate Foundry PoC → run → confirmed/unconfirmed  [Pillar B+C]
7. CLASSIFY        map to SWC + extended taxonomy, assign severity, compute risk score        [Pillar C]
8. ASSEMBLE        build report bundle, compute reportHash (keccak256)
9. ATTEST          write artifact hashes + severity + exploitProven to AuditRegistry on-chain [Pillar A]
10. VERIFY         anyone: paste address → verifyBytecode → trustless result                  [Pillar A]
```

---

## 4. Architecture & Repo Structure

A monorepo with clear separation:

```
veriaudit/
├── contracts/                  # Pillar A — Solidity
│   ├── src/AuditRegistry.sol
│   ├── test/AuditRegistry.t.sol
│   ├── script/Deploy.s.sol
│   └── foundry.toml
├── backend/                    # Python / FastAPI orchestration
│   ├── app/
│   │   ├── main.py             # FastAPI app + routes
│   │   ├── ingest/             # source/address/repo intake
│   │   ├── fingerprint/        # Pillar A — artifact hashing
│   │   ├── security/           # Pillar C — Slither, taxonomy, severity, PoC harness
│   │   ├── detection/          # Pillar B — ML model + LLM reasoning
│   │   ├── exploit/            # Pillar B+C — Foundry PoC generation + execution
│   │   ├── report/             # bundle assembly + keccak256 hashing
│   │   ├── chain/              # Pillar A — web3 client for AuditRegistry
│   │   └── eval/               # Pillar B/C — benchmark harness + metrics
│   └── requirements.txt
├── frontend/                   # React (separate design brief exists)
└── README.md
```

---

## 5. Tech Stack

| Layer | Technology |
|---|---|
| Smart contract | Solidity ^0.8.20, Foundry (forge/anvil/cast) for build, test, deploy |
| Network | Sepolia testnet |
| Blockchain client | web3.py |
| Backend | Python 3.11+, FastAPI, async job handling |
| Static analysis | Slither |
| ML risk model | scikit-learn / XGBoost (or small transformer); features from Slither + AST |
| LLM | OpenAI or Hugging Face, behind a provider-agnostic interface |
| Exploit PoC | Foundry forge tests, fork testing via Anvil |
| Hashing | keccak256 (match Solidity) |
| Off-chain storage | IPFS or server for full report bundles (only hash goes on-chain) |
| Frontend | React (see separate frontend design brief) |
| Evaluation | scikit-learn metrics, pandas |

---

## 6. Key Data Contracts (between modules)

**Finding object** (produced by detection + security layers):
```json
{
  "id": "F-001",
  "type": "reentrancy",
  "swc_id": "SWC-107",
  "extended_tax": "REENT-EXTERNAL-CALL",
  "severity": "Critical",
  "confidence": 0.94,
  "location": { "file": "Vault.sol", "lines": [42, 58] },
  "explanation": "plain-language description of the issue and why it is dangerous",
  "suggested_fix": "diff-style remediation",
  "exploit_status": "proven | unconfirmed | not_supported"
}
```

**Audit bundle** (assembled before hashing + attestation):
```json
{
  "contractAddress": "0x...",
  "sourceHash": "0x...",
  "commitHash": "0x...",
  "bytecodeHash": "0x...",
  "compilerVersion": "0.8.20",
  "findings": [ /* Finding objects */ ],
  "severityScore": 0,
  "exploitProven": false,
  "timestamp": 0,
  "auditor": "0x..."
}
```

The `reportHash` = keccak256 of the canonicalized bundle. Only the hashes (`sourceHash`, `commitHash`, `bytecodeHash`, `reportHash`) + `severityScore` + `exploitProven` go on-chain; the full bundle is stored off-chain.

---

## 7. The `AuditRegistry` Smart Contract (Pillar A — build & deploy this)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AuditRegistry {
    struct Audit {
        bytes32 sourceHash;
        bytes32 commitHash;
        bytes32 bytecodeHash;
        bytes32 reportHash;
        string  compilerVersion;
        uint8   severityScore;   // 0-100 aggregate risk
        bool    exploitProven;
        uint256 timestamp;
        address auditor;
        bool    exists;
    }

    mapping(address => Audit[]) public auditHistory;

    event AuditRecorded(
        address indexed contractAddress,
        bytes32 bytecodeHash,
        uint8 severityScore,
        bool exploitProven,
        address indexed auditor
    );

    function recordAudit(
        address contractAddress,
        bytes32 sourceHash,
        bytes32 commitHash,
        bytes32 bytecodeHash,
        bytes32 reportHash,
        string calldata compilerVersion,
        uint8 severityScore,
        bool exploitProven
    ) external {
        auditHistory[contractAddress].push(Audit({
            sourceHash: sourceHash,
            commitHash: commitHash,
            bytecodeHash: bytecodeHash,
            reportHash: reportHash,
            compilerVersion: compilerVersion,
            severityScore: severityScore,
            exploitProven: exploitProven,
            timestamp: block.timestamp,
            auditor: msg.sender,
            exists: true
        }));
        emit AuditRecorded(contractAddress, bytecodeHash, severityScore, exploitProven, msg.sender);
    }

    function latestAudit(address contractAddress) external view returns (Audit memory) {
        uint256 n = auditHistory[contractAddress].length;
        require(n > 0, "No audit found");
        return auditHistory[contractAddress][n - 1];
    }

    function auditCount(address contractAddress) external view returns (uint256) {
        return auditHistory[contractAddress].length;
    }

    function verifyBytecode(address contractAddress, bytes32 currentBytecodeHash)
        external view returns (bool matches, uint8 severityScore, bool exploitProven)
    {
        uint256 n = auditHistory[contractAddress].length;
        require(n > 0, "No audit found");
        Audit memory a = auditHistory[contractAddress][n - 1];
        return (a.bytecodeHash == currentBytecodeHash, a.severityScore, a.exploitProven);
    }
}
```

Write Foundry tests for: recording an audit, reading latest, history count, bytecode match true/false, and the no-audit revert. Then a deploy script targeting Sepolia. For a production pass, add access control (only registered auditors) and consider EIP-712 signed attestations.

---

## 8. API Surface (FastAPI)

| Endpoint | Method | Purpose |
|---|---|---|
| `/audit` | POST | Submit source/address/repo; returns a job id |
| `/audit/{id}/status` | GET | Stream/poll layered-engine progress per stage |
| `/audit/{id}/report` | GET | Full report bundle + findings |
| `/attest/{id}` | POST | Hash bundle + call `recordAudit` on-chain; return tx hash |
| `/verify/{address}` | GET | Read live bytecode, hash it, call `verifyBytecode`; return match + severity + exploitProven |
| `/history/{address}` | GET | Audit history for diff view |

---

## 9. Build Order (follow this)

1. **Pillar A spine:** scaffold `contracts/`, write `AuditRegistry.sol`, Foundry tests, deploy to Sepolia, and the `chain/` web3 client. Prove on-chain write + `verifyBytecode` read end to end first.
2. **Ingestion + fingerprinting (`ingest/`, `fingerprint/`):** accept the three input modes; compute source/commit/compiler/bytecode hashes.
3. **Static analysis (`security/`):** integrate Slither; extract features; map to SWC + extended taxonomy; severity scoring.
4. **AI detection (`detection/`):** ML risk model + LLM reasoning behind a clean interface; emit Finding objects.
5. **Report assembly + attestation (`report/`, `chain/`):** canonicalize bundle, keccak256, store off-chain, write hashes on-chain.
6. **Exploit validation (`exploit/`):** Foundry PoC generation + execution for supported classes; set `exploit_status` and `exploitProven`. (Highest-value differentiator — build once the spine is stable.)
7. **API + frontend wiring (`main.py`, frontend):** expose endpoints; connect the React UI (separate design brief).
8. **Evaluation harness (`eval/`):** labeled benchmark set (SmartBugs, Damn Vulnerable DeFi, DeFiHackLabs, plus a reference set of contracts with no known labeled vulnerabilities in the benchmark context); report precision, recall, false-positive rate, exploit-confirmation rate, and explanation quality per class.

**Minimum demoable slice:** steps 1–5 give a working "paste contract → AI report → on-chain certificate → verify" demo. Steps 6 and 8 take it to the full 10/10 (proven exploits + benchmark numbers).

---

## 10. Honesty / Scope Rules (must hold in code and UI)

- AI is **first-pass triage + continuous monitoring**, never marketed as a human-auditor replacement.
- Exploit validation is **only for supported vulnerability classes**; everything else is "detected-but-not-auto-validated," never "proven."
- The reference benchmark set is "**no known labeled vulnerabilities in the benchmark context**," not "safe."
- **Hashes on-chain, full bundles off-chain** for cost efficiency; the on-chain hash proves integrity; optionally EIP-712 for signed attestations.
- Heavy compute stays **off-chain**; the blockchain does immutable storage, verification, and attestation only.

---

## 11. Definition of Done

- `AuditRegistry` deployed to Sepolia with passing Foundry tests and a verified contract address.
- Backend runs the full layered pipeline on a pasted vulnerable contract and returns structured findings with explanations.
- At least one supported-class finding produces a **confirmed Foundry PoC** with `exploitProven = true` recorded on-chain.
- `/verify/{address}` correctly returns match / mismatch against deployed bytecode.
- Evaluation harness outputs per-class metrics on the benchmark set.
- Frontend (per the separate design brief) renders submit → in-progress → report → verify.
