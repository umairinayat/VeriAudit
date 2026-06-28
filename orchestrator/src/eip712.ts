// EIP-712 typed-data encoding for the AuditRegistry attestation.
//
// The contract's ATTESTATION_TYPEHASH and struct field order MUST match this
// exactly (see contracts/src/AuditRegistry.sol). Drift here = bad signatures.
//
// We use viem's typed-data utilities so the digest computed here matches
// `_hashTypedDataV4(keccak256(abi.encode(TYPEHASH, ...)))` on-chain.

import {
  hashTypedData,
  type Hex,
  type Address,
} from "viem";

// The EIP-712 type string. MUST match ATTESTATION_TYPEHASH in the contract.
export const ATTESTATION_TYPE = `[
  { "name": "contractAddress",      "type": "address" },
  { "name": "sourceHash",           "type": "bytes32" },
  { "name": "commitHash",           "type": "bytes32" },
  { "name": "bytecodeHash",         "type": "bytes32" },
  { "name": "reportHash",           "type": "bytes32" },
  { "name": "compilerVersionHash",  "type": "bytes32" },
  { "name": "ipfsCidCommitment",    "type": "bytes32" },
  { "name": "severityScore",        "type": "uint8" },
  { "name": "exploitProven",        "type": "bool" },
  { "name": "nonce",                "type": "uint256" },
  { "name": "deadline",             "type": "uint256" }
]`;

export interface Attestation {
  contractAddress: Address;
  sourceHash: Hex;
  commitHash: Hex;
  bytecodeHash: Hex;
  reportHash: Hex;
  compilerVersionHash: Hex;
  ipfsCidCommitment: Hex;
  severityScore: number;
  exploitProven: boolean;
  nonce: bigint;
  deadline: bigint;
}

export interface Eip712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: Address;
}

/** Compute the exact digest the auditor must sign for a given attestation. */
export function attestationDigest(att: Attestation, domain: Eip712Domain): Hex {
  return hashTypedData({
    domain: {
      name: domain.name,
      version: domain.version,
      chainId: domain.chainId,
      verifyingContract: domain.verifyingContract,
    },
    types: {
      Attestation: JSON.parse(ATTESTATION_TYPE),
    },
    primaryType: "Attestation",
    message: {
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
    },
  });
}
