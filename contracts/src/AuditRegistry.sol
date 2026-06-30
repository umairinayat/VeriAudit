// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAuditRegistry} from "./interfaces/IAuditRegistry.sol";
import {BytecodeVerifier} from "./lib/BytecodeVerifier.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Nonces} from "@openzeppelin/contracts/utils/Nonces.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title AuditRegistry
/// @author VeriAudit
/// @notice On-chain registry for AI-assisted smart-contract audits.
///
/// @dev Design invariants (must hold — see CLAUDE.md and the implementation
///      brief Section 7):
///        1. `bytecodeHash` MUST equal keccak256(runtime bytecode) so it matches
///           EXTCODEHASH on-chain (single-opcode verification).
///        2. Only hashes + scores live in storage. The full bundle is emitted as
///           an event (`BundleStored`) and optionally pinned to IPFS; only the
///           IPFS-CID commitment is stored on-chain.
///        3. Attestations are EIP-712 signed off-chain; the contract recovers the
///           signer and requires them to be a registered, staked auditor.
///        4. Heavy compute (Slither / ML / LLM / Foundry PoC) stays OFF-CHAIN.
///           The contract only does immutable storage, verification, attestation.
contract AuditRegistry is IAuditRegistry, EIP712, Nonces, ReentrancyGuard, Ownable {
    using BytecodeVerifier for address;

    // ---------- Events ----------
    event AuditorRegistered(address indexed auditor, uint256 stake);
    event AuditorUnregistered(address indexed auditor, uint256 refund);
    event AuditorSlashed(address indexed auditor, uint256 amountSlashed, string reason);
    event AuditRecorded(
        address indexed contractAddress,
        bytes32 indexed reportHash,
        bytes32 bytecodeHash,
        bytes32 ipfsCidCommitment,
        uint8 severityScore,
        bool exploitProven,
        address indexed auditor
    );
    /// @dev Full bundle lives in event calldata (gas-cheap, immutable, retrievable
    ///      via eth_getLogs). Optional IPFS pin via `ipfsCid`.
    event BundleStored(address indexed contractAddress, bytes32 indexed reportHash, bytes bundle, string ipfsCid);

    // ---------- Constants ----------
    /// @dev EIP-712 typehash for the `Attestation` struct. Field order MUST match
    ///      the struct definition and the TS signer exactly.
    bytes32 public constant ATTESTATION_TYPEHASH =
        keccak256(
            "Attestation(address contractAddress,bytes32 sourceHash,bytes32 commitHash,bytes32 bytecodeHash,bytes32 reportHash,bytes32 compilerVersionHash,bytes32 ipfsCidCommitment,uint8 severityScore,bool exploitProven,uint256 nonce,uint256 deadline)"
        );

    uint256 public immutable minStake;
    uint256 public immutable unstakeDelay;

    // ---------- Storage ----------
    mapping(address => Audit[]) private _auditHistory;
    mapping(address => Auditor) private _auditors;

    constructor(uint256 _minStake, uint256 _unstakeDelay, address owner_)
        EIP712("VeriAudit", "1")
        Ownable(owner_)
    {
        require(_minStake > 0, "minStake=0");
        minStake = _minStake;
        unstakeDelay = _unstakeDelay;
    }

    // ============================================================
    //                       Auditor registry
    // ============================================================

    /// @inheritdoc IAuditRegistry
    function registerAuditor() external payable override {
        require(msg.value >= minStake, "Insufficient stake");
        Auditor storage a = _auditors[msg.sender];
        require(!a.registered, "Already registered");
        a.registered = true;
        a.staked = msg.value;
        a.enrolledAt = block.timestamp;
        emit AuditorRegistered(msg.sender, msg.value);
    }

    /// @inheritdoc IAuditRegistry
    function unregisterAuditor() external override nonReentrant {
        Auditor storage a = _auditors[msg.sender];
        require(a.registered, "Not registered");
        require(block.timestamp >= a.enrolledAt + unstakeDelay, "Timelock active");
        uint256 refund = a.staked;
        delete _auditors[msg.sender];
        (bool ok,) = payable(msg.sender).call{value: refund}("");
        require(ok, "Refund failed");
        emit AuditorUnregistered(msg.sender, refund);
    }

    /// @inheritdoc IAuditRegistry
    /// @dev v1 stub: owner-only. A full governance / challenge module can replace
    ///      this without changing the ABI. Slashing ALSO deregisters the auditor
    ///      (sets registered=false) so they cannot keep attesting after a slash —
    ///      a zeroed bond must revoke attestation rights. The slashed ETH stays
    ///      in the contract for the owner to recover via `sweep()`.
    function slashAuditor(address auditor, string calldata reason) external override onlyOwner {
        Auditor storage a = _auditors[auditor];
        require(a.registered, "Not registered");
        uint256 amount = a.staked;
        a.staked = 0;
        a.registered = false; // revoke attestation rights immediately
        emit AuditorSlashed(auditor, amount, reason);
    }

    /// @notice Owner-only recovery of ETH that lands in the contract via
    ///         slashing, direct sends (`receive()`), or refunds to deleted
    ///         auditors. Without this, slashed/donated ETH would be stranded.
    function sweep(address payable to) external onlyOwner nonReentrant {
        require(to != address(0), "sweep to zero");
        uint256 amount = address(this).balance;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "sweep failed");
    }

    // ============================================================
    //                        Attestation
    // ============================================================

    /// @inheritdoc IAuditRegistry
    /// @dev Anyone can relay a pre-signed attestation, but the *signer* must be a
    ///      registered auditor. This keeps the door open for gasless submits while
    ///      preserving "auditor accountability".
    function recordAudit(
        Attestation calldata att,
        bytes calldata signature,
        string calldata compilerVersion,
        bytes calldata bundle,
        string calldata ipfsCid
    ) external override nonReentrant {
        // 1. Signature lifetime.
        require(block.timestamp <= att.deadline, "Signature expired");

        // 2. Recover signer via EIP-712 and require an ACTIVE auditor (registered
        //    AND still carrying stake). A slashed auditor (registered=false,
        //    staked=0) must not be able to attest — the bond is the slashing
        //    surface, so a zeroed bond revokes attestation rights.
        address signer = _recoverSigner(att, signature);
        Auditor storage signerAuditor = _auditors[signer];
        require(signerAuditor.registered, "Signer not registered");
        require(signerAuditor.staked > 0, "Auditor stake slashed");

        // 3. Replay protection (sequential per-auditor nonce). The signed
        //    att.nonce MUST equal the auditor's next-expected nonce; OZ reverts
        //    otherwise. The TS signer reads nonces(auditor) before signing.
        _useCheckedNonce(signer, att.nonce);

        // 4. Integrity: the calldata `compilerVersion` and `ipfsCid` must match the
        //    signed commitments. Prevents a relayer from swapping the version
        //    string while keeping the hashes. A bytes32(0) IPFS commitment means
        //    "no IPFS pin" and requires an empty cid string.
        require(keccak256(bytes(compilerVersion)) == att.compilerVersionHash, "Compiler version mismatch");
        if (att.ipfsCidCommitment == bytes32(0)) {
            require(bytes(ipfsCid).length == 0, "IPFS cid not expected");
        } else {
            require(keccak256(bytes(ipfsCid)) == att.ipfsCidCommitment, "IPFS CID mismatch");
        }

        // 4b. Bundle integrity: any emitted bundle MUST hash to the signed
        //     `reportHash`. Without this a relayer could swap the `bundle` bytes
        //     in the calldata while the on-chain reportHash stays correct, so the
        //     on-chain "full bundle via event" would not match the signed report.
        if (bundle.length > 0) {
            require(keccak256(bundle) == att.reportHash, "Bundle hash mismatch");
        }

        // 5. Store compact record.
        Audit memory rec = Audit({
            sourceHash: att.sourceHash,
            commitHash: att.commitHash,
            bytecodeHash: att.bytecodeHash,
            reportHash: att.reportHash,
            compilerVersionHash: att.compilerVersionHash,
            ipfsCidCommitment: att.ipfsCidCommitment,
            severityScore: att.severityScore,
            exploitProven: att.exploitProven,
            timestamp: block.timestamp,
            auditor: signer
        });
        _auditHistory[att.contractAddress].push(rec);

        // 6. Emit events. AuditRecorded is the canonical record; BundleStored
        //    carries the full off-chain bundle (and optional IPFS CID) so the
        //    "full bundle on-chain" requirement is met without storage cost.
        emit AuditRecorded(
            att.contractAddress,
            att.reportHash,
            att.bytecodeHash,
            att.ipfsCidCommitment,
            att.severityScore,
            att.exploitProven,
            signer
        );
        if (bundle.length > 0 || bytes(ipfsCid).length > 0) {
            emit BundleStored(att.contractAddress, att.reportHash, bundle, ipfsCid);
        }
    }

    // ============================================================
    //                     Verification / reads
    // ============================================================

    /// @inheritdoc IAuditRegistry
    /// @notice Trustless: uses EXTCODEHASH (no off-chain data fetch).
    function verifyBytecode(address contractAddress)
        external
        view
        override
        returns (bool matches, uint8 severityScore, bool exploitProven, address auditor, uint256 timestamp, uint256 auditIndex)
    {
        uint256 n = _auditHistory[contractAddress].length;
        require(n > 0, "No audit found");
        Audit storage a = _auditHistory[contractAddress][n - 1];
        return (contractAddress.matches(a.bytecodeHash), a.severityScore, a.exploitProven, a.auditor, a.timestamp, n - 1);
    }

    /// @inheritdoc IAuditRegistry
    function verifyBytecodeAgainst(address contractAddress, bytes32 expectedHash) external view override returns (bool) {
        return contractAddress.matches(expectedHash);
    }

    /// @inheritdoc IAuditRegistry
    function latestAudit(address contractAddress) external view override returns (Audit memory) {
        uint256 n = _auditHistory[contractAddress].length;
        require(n > 0, "No audit found");
        return _auditHistory[contractAddress][n - 1];
    }

    /// @inheritdoc IAuditRegistry
    function auditCount(address contractAddress) external view override returns (uint256) {
        return _auditHistory[contractAddress].length;
    }

    /// @inheritdoc IAuditRegistry
    function getAudit(address contractAddress, uint256 index) external view override returns (Audit memory) {
        require(index < _auditHistory[contractAddress].length, "Index out of bounds");
        return _auditHistory[contractAddress][index];
    }

    // ============================================================
    //                       EIP-712 plumbing
    // ============================================================

    /// @dev Hashes the `Attestation` per EIP-712 struct-encoding rules. Field
    ///      order MUST match ATTESTATION_TYPEHASH.
    function _hashAttestation(Attestation calldata att) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ATTESTATION_TYPEHASH,
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
                att.deadline
            )
        );
    }

    function _recoverSigner(Attestation calldata att, bytes calldata signature) internal view returns (address) {
        bytes32 structHash = _hashAttestation(att);
        bytes32 digest = _hashTypedDataV4(structHash);
        return ECDSA.recover(digest, signature);
    }

    // ---------- Public helpers (used by off-chain clients) ----------

    /// @notice EIP-712 domain separator — used by the TS signer to build the digest.
    function domainSeparatorV4() public view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Builds the digest the auditor is expected to sign. Convenience for
    ///         clients and tests.
    function attestationDigest(Attestation calldata att) external view returns (bytes32) {
        return _hashTypedDataV4(_hashAttestation(att));
    }

    // ============================================================
    //                    IAuditRegistry view getters
    // ============================================================

    function nonceUsed(address auditor, uint256 nonce) external view override returns (bool) {
        // Sequential nonce model: a nonce is "used" once the auditor's
        // next-expected counter has advanced past it.
        return nonces(auditor) > nonce;
    }

    function getAuditor(address auditor) external view override returns (Auditor memory) {
        return _auditors[auditor];
    }

    // ============================================================
    //                         Receive
    // ============================================================
    receive() external payable {}
}
