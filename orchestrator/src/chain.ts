// On-chain client for AuditRegistry. Wraps viem for reads and ethers for the
// signed write (recordAudit). The EIP-712 signing is done with ethers' signer
// so we keep one private-key wallet for the auditor.

import { ethers } from "ethers";
import { createPublicClient, http, parseAbiItem, type Address, type Hash } from "viem";
import { config } from "./config.js";
import { type Attestation, type Eip712Domain } from "./eip712.js";
import ABI from "./abi/AuditRegistry.abi.json" with { type: "json" };
import type { WorkerResponse } from "./workerClient.js";

// Ethers contract instance (write path).
const provider = new ethers.JsonRpcProvider(config.rpcUrl);
const auditorWallet = new ethers.Wallet(config.auditorKey, provider);
const registryWrite = new ethers.Contract(config.registryAddress, ABI, auditorWallet);

// Viem public client (read path — typed, fast).
const publicClient = createPublicClient({
  transport: http(config.rpcUrl),
});

export const eip712Domain: Eip712Domain = {
  name: config.eip712.name,
  version: config.eip712.version,
  chainId: config.chainId,
  verifyingContract: config.registryAddress,
};

export interface VerifyResult {
  matches: boolean;
  severityScore: number;
  exploitProven: boolean;
  auditor: Address;
  timestamp: bigint;
  auditIndex: bigint;
}

export interface AuditRecord {
  sourceHash: Hash;
  commitHash: Hash;
  bytecodeHash: Hash;
  reportHash: Hash;
  compilerVersionHash: Hash;
  ipfsCidCommitment: Hash;
  severityScore: number;
  exploitProven: boolean;
  timestamp: bigint;
  auditor: Address;
}

// A module-level async mutex around recordAudit. Two concurrent /attest calls
// would both read the same nonce, sign, and submit — one tx would revert (or
// worse, race the contract's checked-nonce logic). Serializing keeps the
// sequential nonce model correct under concurrent requests.
let _recordChain: Promise<unknown> = Promise.resolve();
function withRecordLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = _recordChain.then(fn, fn);
  // Swallow rejections on the chain so a failed tx doesn't break the next call.
  _recordChain = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

/** Sign + submit a recordAudit tx. Returns the tx hash. */
export async function recordAudit(
  bundle: WorkerResponse,
  contractAddress: Address,
  ipfsCid: string,
): Promise<{ txHash: Hash; att: Attestation }> {
  return withRecordLock(() => _recordAudit(bundle, contractAddress, ipfsCid));
}

async function _recordAudit(
  bundle: WorkerResponse,
  contractAddress: Address,
  ipfsCid: string,
): Promise<{ txHash: Hash; att: Attestation }> {
  // 1. Read the auditor's next nonce from the registry (sequential model).
  const nonce: bigint = await registryWrite.nonces(config.auditorAddress);

  // 2. Build the EIP-712 attestation. compilerVersionHash + ipfsCidCommitment
  //    are committed to so a relayer can't swap them.
  const compilerVersionBytes = ethers.toUtf8Bytes(bundle.fingerprints.compiler_version);
  const compilerVersionHash = ethers.keccak256(compilerVersionBytes) as Hash;
  const ipfsCidCommitment = (ipfsCid
    ? ethers.keccak256(ethers.toUtf8Bytes(ipfsCid))
    : ethers.ZeroHash) as Hash;

  const deadline = BigInt(Math.floor(Date.now() / 1000) + 60 * 60); // +1h

  const att: Attestation = {
    contractAddress,
    sourceHash: bundle.fingerprints.source_hash as Hash,
    commitHash: bundle.fingerprints.commit_hash as Hash,
    bytecodeHash: bundle.fingerprints.bytecode_hash as Hash,
    reportHash: bundle.report_hash as Hash,
    compilerVersionHash,
    ipfsCidCommitment,
    severityScore: bundle.severity_score,
    exploitProven: bundle.exploit_proven,
    nonce,
    deadline,
  };

  // 3. Sign the EIP-712 typed data with the auditor key. ethers v6's
  //    signTypedData produces exactly the digest `_hashTypedDataV4(...)` and
  //    a 65-byte secp256k1 signature the contract recovers via ECDSA.recover.
  const types = {
    Attestation: [
      { name: "contractAddress", type: "address" },
      { name: "sourceHash", type: "bytes32" },
      { name: "commitHash", type: "bytes32" },
      { name: "bytecodeHash", type: "bytes32" },
      { name: "reportHash", type: "bytes32" },
      { name: "compilerVersionHash", type: "bytes32" },
      { name: "ipfsCidCommitment", type: "bytes32" },
      { name: "severityScore", type: "uint8" },
      { name: "exploitProven", type: "bool" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };
  const domain = {
    name: eip712Domain.name,
    version: eip712Domain.version,
    chainId: eip712Domain.chainId,
    verifyingContract: eip712Domain.verifyingContract,
  };
  const value = {
    contractAddress: att.contractAddress,
    sourceHash: att.sourceHash,
    commitHash: att.commitHash,
    bytecodeHash: att.bytecodeHash,
    reportHash: att.reportHash,
    compilerVersionHash: att.compilerVersionHash,
    ipfsCidCommitment: att.ipfsCidCommitment,
    severityScore: att.severityScore,
    exploitProven: att.exploitProven,
    nonce: att.nonce,
    deadline: att.deadline,
  };
  const signature = (await auditorWallet.signTypedData(domain, types, value)) as `0x${string}`;

  // 4. Submit. recordAudit(Attestation, bytes, string compilerVersion, bytes bundle, string ipfsCid)
  const bundleBytes = ethers.toUtf8Bytes(bundle.bundle_canonical);
  const tx = await registryWrite.recordAudit(
    attToTuple(att),
    signature,
    bundle.fingerprints.compiler_version,
    bundleBytes,
    ipfsCid,
  );
  await tx.wait();
  return { txHash: tx.hash as Hash, att };
}

/** Trustless on-chain verify. Anyone can call this; we expose it for the API. */
export async function verifyBytecode(target: Address): Promise<VerifyResult> {
  const res = (await publicClient.readContract({
    address: config.registryAddress,
    abi: ABI,
    functionName: "verifyBytecode",
    args: [target],
  })) as readonly [boolean, number, boolean, Address, bigint, bigint];
  return {
    matches: res[0],
    severityScore: res[1],
    exploitProven: res[2],
    auditor: res[3],
    timestamp: res[4],
    auditIndex: res[5],
  };
}

export async function auditCount(target: Address): Promise<bigint> {
  return (await publicClient.readContract({
    address: config.registryAddress,
    abi: ABI,
    functionName: "auditCount",
    args: [target],
  })) as bigint;
}

export async function getAudit(target: Address, index: bigint): Promise<AuditRecord> {
  const r = (await publicClient.readContract({
    address: config.registryAddress,
    abi: ABI,
    functionName: "getAudit",
    args: [target, index],
  })) as readonly [
    Hash, Hash, Hash, Hash, Hash, Hash, number, boolean, bigint, Address,
  ];
  return {
    sourceHash: r[0],
    commitHash: r[1],
    bytecodeHash: r[2],
    reportHash: r[3],
    compilerVersionHash: r[4],
    ipfsCidCommitment: r[5],
    severityScore: r[6],
    exploitProven: r[7],
    timestamp: r[8],
    auditor: r[9],
  };
}

export async function getHistory(target: Address): Promise<AuditRecord[]> {
  const count = await auditCount(target);
  const out: AuditRecord[] = [];
  for (let i = 0n; i < count; i++) {
    out.push(await getAudit(target, i));
  }
  return out;
}

/** Register the configured auditor on-chain (stakes ETH). Idempotent. */
export async function ensureAuditorRegistered(): Promise<void> {
  const aud = (await registryWrite.getAuditor(config.auditorAddress)) as {
    registered: boolean;
    staked: bigint;
    enrolledAt: bigint;
  };
  if (aud.registered) return;
  const minStake: bigint = await registryWrite.minStake();
  const tx = await registryWrite.registerAuditor({ value: minStake });
  await tx.wait();
}

// Convert the typed attestation to the tuple ordering the ABI expects.
function attToTuple(att: Attestation): readonly [
  Address, Hash, Hash, Hash, Hash, Hash, Hash, number, boolean, bigint, bigint,
] {
  return [
    att.contractAddress,
    att.sourceHash,
    att.commitHash,
    att.bytecodeHash,
    att.reportHash,
    att.compilerVersionHash,
    att.ipfsCidCommitment,
    att.severityScore,
    att.exploitProven,
    att.nonce,
    att.deadline,
  ];
}
