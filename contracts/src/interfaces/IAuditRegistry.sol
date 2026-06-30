// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IAuditRegistry
/// @notice Interface for the VeriAudit on-chain audit registry. Defines the
///         public surface consumed by the TS orchestrator and the React frontend
///         (via wagmi/viem). Keeping it in its own file means the ABI is stable
///         even if the implementation evolves.
interface IAuditRegistry {
    // ---------- Structs (mirror the on-disk data contracts in CLAUDE.md) ----------

    /// @dev Compact record stored on-chain per audit. Full bundle is emitted as an
    ///      event and pinned to IPFS; only hashes + scores live in storage.
    struct Audit {
        bytes32 sourceHash;
        bytes32 commitHash;
        bytes32 bytecodeHash;
        bytes32 reportHash;
        bytes32 compilerVersionHash;
        bytes32 ipfsCidCommitment;
        uint8 severityScore; // 0-100 aggregate risk
        bool exploitProven;
        uint256 timestamp;
        address auditor;
    }

    /// @dev EIP-712 typed struct that the auditor signs OFF-CHAIN. All fields are
    ///      fixed-size so encoding is identical on the TS signer and in-contract.
    struct Attestation {
        address contractAddress;
        bytes32 sourceHash;
        bytes32 commitHash;
        bytes32 bytecodeHash;
        bytes32 reportHash;
        bytes32 compilerVersionHash; // keccak256(bytes(compilerVersion))
        bytes32 ipfsCidCommitment; // keccak256(bytes(ipfsCid)) or bytes32(0)
        uint8 severityScore;
        bool exploitProven;
        uint256 nonce; // per-auditor replay guard
        uint256 deadline;
    }

    struct Auditor {
        bool registered;
        uint256 staked;
        uint256 enrolledAt;
    }

    // Events are declared in the concrete `AuditRegistry` contract (see src/).
    // Emitting interface-inherited events via qualified name is not supported in
    // 0.8.20, so the canonical declarations live in the implementation.

    // ---------- Events (mirrored here for documentation / ABI consumers) ----------
    // event AuditorRegistered(address indexed auditor, uint256 stake);
    // event AuditorUnregistered(address indexed auditor, uint256 refund);
    // event AuditorSlashed(address indexed auditor, uint256 amountSlashed, string reason);
    // event AuditRecorded(...);
    // event BundleStored(...);

    // ---------- Auditor registry / staking ----------
    function registerAuditor() external payable;
    function unregisterAuditor() external;
    function slashAuditor(address auditor, string calldata reason) external;
    function sweep(address payable to) external;

    // ---------- Attestation (write path) ----------
    function recordAudit(
        Attestation calldata att,
        bytes calldata signature,
        string calldata compilerVersion,
        bytes calldata bundle,
        string calldata ipfsCid
    ) external;

    // ---------- Verification / reads (trustless) ----------
    function verifyBytecode(address contractAddress)
        external
        view
        returns (bool matches, uint8 severityScore, bool exploitProven, address auditor, uint256 timestamp, uint256 auditIndex);

    function verifyBytecodeAgainst(address contractAddress, bytes32 expectedHash) external view returns (bool);

    function latestAudit(address contractAddress) external view returns (Audit memory);
    function auditCount(address contractAddress) external view returns (uint256);
    function getAudit(address contractAddress, uint256 index) external view returns (Audit memory);
    function nonceUsed(address auditor, uint256 nonce) external view returns (bool);
    function getAuditor(address auditor) external view returns (Auditor memory);
    function minStake() external view returns (uint256);
    function unstakeDelay() external view returns (uint256);
}
