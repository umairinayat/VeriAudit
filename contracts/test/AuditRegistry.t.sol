// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {AuditRegistry, IAuditRegistry} from "../src/AuditRegistry.sol";
import {SampleTarget, SampleTargetVariant} from "./mocks/SampleTarget.sol";

/// @notice Full coverage for AuditRegistry. Mirrors the 11-case plan from the
///         build brief. Each test exercises one contract behavior and asserts on
///         return values, events, and storage reads.
contract AuditRegistryTest is Test {
    AuditRegistry public registry;

    // Three labeled accounts (foundry default mnemonics, deterministic).
    uint256 internal constant AUDITOR_PK = 0xA11; // arbitrary
    address internal auditor; // derived
    address internal other = address(0xBEEF);
    address internal owner = address(0xCE0);

    uint256 internal constant MIN_STAKE = 0.1 ether;
    uint256 internal constant UNSTAKE_DELAY = 1 days;

    // Local event mirrors — Foundry matches expected events by topic0 (signature
    // hash), so mirroring the exact signatures here lets us emit expectations
    // for events defined in AuditRegistry. (0.8.20 doesn't allow
    // `ExternalContract.EventName` emit syntax.)
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
    event BundleStored(address indexed contractAddress, bytes32 indexed reportHash, bytes bundle, string ipfsCid);

    function setUp() public {
        auditor = vm.addr(AUDITOR_PK);
        registry = new AuditRegistry(MIN_STAKE, UNSTAKE_DELAY, owner);
        vm.deal(auditor, 100 ether);
        vm.deal(owner, 100 ether);
        vm.deal(other, 100 ether);
    }

    // ---------- helpers ----------

    function _registerAuditor(address who) internal {
        vm.prank(who);
        registry.registerAuditor{value: MIN_STAKE}();
    }

    function _liveCodehash(address target) internal view returns (bytes32 h) {
        assembly {
            h := extcodehash(target)
        }
    }

    /// @dev Builds a default attestation pointing at `target` with the CORRECT
    ///      live bytecode hash, then signs it with the auditor key. Returns the
    ///      attestation + signature ready for recordAudit.
    function _signAttestation(address target, bytes32 reportHash, uint8 severity, bool proven, uint256 nonce)
        internal
        view
        returns (IAuditRegistry.Attestation memory att, bytes memory sig)
    {
        att = IAuditRegistry.Attestation({
            contractAddress: target,
            sourceHash: keccak256("src"),
            commitHash: keccak256("commit"),
            bytecodeHash: _liveCodehash(target),
            reportHash: reportHash,
            compilerVersionHash: keccak256(bytes("0.8.20")),
            ipfsCidCommitment: bytes32(0),
            severityScore: severity,
            exploitProven: proven,
            nonce: nonce,
            deadline: block.timestamp + 1 hours
        });
        bytes32 digest = registry.attestationDigest(att);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AUDITOR_PK, digest);
        sig = abi.encodePacked(r, s, v);
    }

    // ============================================================
    //                    1. Auditor registration
    // ============================================================

    function test_RegisterAuditor_StakesAndEnrolls() public {
        vm.expectEmit(true, true, true, true);
        emit AuditorRegistered(auditor, MIN_STAKE);
        _registerAuditor(auditor);

        IAuditRegistry.Auditor memory a = registry.getAuditor(auditor);
        assertTrue(a.registered, "registered");
        assertEq(a.staked, MIN_STAKE, "staked");
        assertEq(a.enrolledAt, block.timestamp, "enrolledAt");
    }

    function test_RegisterAuditor_Reverts_InsufficientStake() public {
        vm.prank(auditor);
        vm.expectRevert(bytes("Insufficient stake"));
        registry.registerAuditor{value: MIN_STAKE - 1}();
    }

    function test_RegisterAuditor_Reverts_AlreadyRegistered() public {
        _registerAuditor(auditor);
        vm.prank(auditor);
        vm.expectRevert(bytes("Already registered"));
        registry.registerAuditor{value: MIN_STAKE}();
    }

    function test_UnregisterAuditor_RefundsAfterTimelock() public {
        _registerAuditor(auditor);
        uint256 balBefore = auditor.balance;

        // Timelock still active.
        vm.prank(auditor);
        vm.expectRevert(bytes("Timelock active"));
        registry.unregisterAuditor();

        vm.warp(block.timestamp + UNSTAKE_DELAY);

        vm.expectEmit(true, true, true, true);
        emit AuditorUnregistered(auditor, MIN_STAKE);
        vm.prank(auditor);
        registry.unregisterAuditor();

        assertEq(auditor.balance, balBefore + MIN_STAKE, "refund");
        IAuditRegistry.Auditor memory a = registry.getAuditor(auditor);
        assertFalse(a.registered, "still registered");
    }

    // ============================================================
    //                    2. recordAudit happy path
    // ============================================================

    function test_RecordAudit_StoresRecord_AndEmits() public {
        _registerAuditor(auditor);

        SampleTarget target = new SampleTarget();
        // The bundle's keccak256 MUST equal the signed reportHash (enforced
        // on-chain). Compute them together so the test stays honest.
        bytes memory bundle = bytes('{"findings":[]}');
        bytes32 reportHash = keccak256(bundle);
        (IAuditRegistry.Attestation memory att, bytes memory sig) =
            _signAttestation(address(target), reportHash, 42, true, 0);

        vm.expectEmit(true, true, true, true);
        emit AuditRecorded(
            address(target), att.reportHash, att.bytecodeHash, bytes32(0), 42, true, auditor
        );
        vm.expectEmit(true, true, false, false);
        emit BundleStored(address(target), att.reportHash, bundle, "");

        registry.recordAudit(att, sig, "0.8.20", bundle, "");

        assertEq(registry.auditCount(address(target)), 1, "count");
        IAuditRegistry.Audit memory a = registry.latestAudit(address(target));
        assertEq(a.severityScore, 42, "severity");
        assertTrue(a.exploitProven, "exploitProven");
        assertEq(a.auditor, auditor, "auditor");
        assertEq(a.bytecodeHash, att.bytecodeHash, "bytecodeHash");
    }

    // ============================================================
    //                  3. recordAudit reverts
    // ============================================================

    function test_RecordAudit_RevertsOn_BadSignature() public {
        _registerAuditor(auditor);
        SampleTarget target = new SampleTarget();
        (IAuditRegistry.Attestation memory att,) = _signAttestation(address(target), keccak256("r"), 1, false, 0);

        // Signature from a DIFFERENT key.
        uint256 otherPk = 0xDEAD;
        bytes32 digest = registry.attestationDigest(att);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(otherPk, digest);
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.expectRevert(bytes("Signer not registered"));
        registry.recordAudit(att, badSig, "0.8.20", "", "");
    }

    function test_RecordAudit_RevertsOn_UnregisteredAuditor() public {
        // Auditor NOT registered. The recovered signer (auditor) won't be in the
        // registry, so this must revert.
        SampleTarget target = new SampleTarget();
        (IAuditRegistry.Attestation memory att, bytes memory sig) =
            _signAttestation(address(target), keccak256("r"), 1, false, 0);

        vm.expectRevert(bytes("Signer not registered"));
        registry.recordAudit(att, sig, "0.8.20", "", "");
    }

    function test_RecordAudit_RevertsOn_CompilerVersionMismatch() public {
        _registerAuditor(auditor);
        SampleTarget target = new SampleTarget();
        (IAuditRegistry.Attestation memory att, bytes memory sig) =
            _signAttestation(address(target), keccak256("r"), 1, false, 0);

        vm.expectRevert(bytes("Compiler version mismatch"));
        registry.recordAudit(att, sig, "0.8.19", "", "");
    }

    function test_RecordAudit_RevertsOn_ReplayedNonce() public {
        _registerAuditor(auditor);
        SampleTarget target = new SampleTarget();
        (IAuditRegistry.Attestation memory att, bytes memory sig) =
            _signAttestation(address(target), keccak256("r"), 1, false, 0);

        registry.recordAudit(att, sig, "0.8.20", "", "");

        // Reuse the SAME attestation (same nonce=0). Auditor's next nonce is now 1.
        vm.expectRevert();
        registry.recordAudit(att, sig, "0.8.20", "", "");
    }

    function test_RecordAudit_RevertsOn_ExpiredDeadline() public {
        _registerAuditor(auditor);
        SampleTarget target = new SampleTarget();
        (IAuditRegistry.Attestation memory att, bytes memory sig) =
            _signAttestation(address(target), keccak256("r"), 1, false, 0);
        att.deadline = block.timestamp - 1; // expired

        vm.expectRevert(bytes("Signature expired"));
        registry.recordAudit(att, sig, "0.8.20", "", "");
    }

    // ============================================================
    //                    4. History / reads
    // ============================================================

    function test_LatestAudit_ReturnsNewest() public {
        _registerAuditor(auditor);
        SampleTarget target = new SampleTarget();
        for (uint8 i = 0; i < 3; i++) {
            (IAuditRegistry.Attestation memory att, bytes memory sig) =
                _signAttestation(address(target), keccak256(abi.encode("r", i)), i * 10, false, i);
            registry.recordAudit(att, sig, "0.8.20", "", "");
        }
        assertEq(registry.auditCount(address(target)), 3, "count");
        IAuditRegistry.Audit memory latest = registry.latestAudit(address(target));
        assertEq(latest.severityScore, 20, "latest severity");
    }

    function test_AuditCount_Increments() public {
        _registerAuditor(auditor);
        SampleTarget target = new SampleTarget();
        assertEq(registry.auditCount(address(target)), 0, "initial");
        (IAuditRegistry.Attestation memory att1, bytes memory sig1) =
            _signAttestation(address(target), keccak256("a"), 5, false, 0);
        registry.recordAudit(att1, sig1, "0.8.20", "", "");
        assertEq(registry.auditCount(address(target)), 1, "after 1");
    }

    function test_GetAudit_ByIndex() public {
        _registerAuditor(auditor);
        SampleTarget target = new SampleTarget();
        (IAuditRegistry.Attestation memory att, bytes memory sig) =
            _signAttestation(address(target), keccak256("idx"), 7, false, 0);
        registry.recordAudit(att, sig, "0.8.20", "", "");

        IAuditRegistry.Audit memory a = registry.getAudit(address(target), 0);
        assertEq(a.severityScore, 7, "severity");

        vm.expectRevert(bytes("Index out of bounds"));
        registry.getAudit(address(target), 99);
    }

    // ============================================================
    //            5. Trustless bytecode verification
    // ============================================================

    function test_VerifyBytecode_Matches() public {
        _registerAuditor(auditor);
        SampleTarget target = new SampleTarget();
        (IAuditRegistry.Attestation memory att, bytes memory sig) =
            _signAttestation(address(target), keccak256("m"), 55, true, 0);
        registry.recordAudit(att, sig, "0.8.20", "", "");

        (bool matches, uint8 severity, bool proven,,,) = registry.verifyBytecode(address(target));
        assertTrue(matches, "should match live code");
        assertEq(severity, 55, "severity");
        assertTrue(proven, "proven");
    }

    function test_VerifyBytecode_DoesNotMatch_AfterCodeChange() public {
        _registerAuditor(auditor);
        SampleTarget target = new SampleTarget();
        // Record an attestation committed to the VARIANT's codehash but pointing
        // at the SampleTarget address → live codehash differs → no match.
        SampleTargetVariant variant = new SampleTargetVariant();
        bytes32 wrongHash = _liveCodehash(address(variant));

        IAuditRegistry.Attestation memory att = IAuditRegistry.Attestation({
            contractAddress: address(target),
            sourceHash: keccak256("s"),
            commitHash: keccak256("c"),
            bytecodeHash: wrongHash,
            reportHash: keccak256("rep"),
            compilerVersionHash: keccak256(bytes("0.8.20")),
            ipfsCidCommitment: bytes32(0),
            severityScore: 30,
            exploitProven: false,
            nonce: 0,
            deadline: block.timestamp + 1 hours
        });
        bytes32 digest = registry.attestationDigest(att);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(AUDITOR_PK, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        registry.recordAudit(att, sig, "0.8.20", "", "");

        (bool matches,,,,,) = registry.verifyBytecode(address(target));
        assertFalse(matches, "must not match");
    }

    function test_VerifyBytecode_Reverts_WhenNoAudit() public {
        SampleTarget target = new SampleTarget();
        vm.expectRevert(bytes("No audit found"));
        registry.verifyBytecode(address(target));
    }

    function test_VerifyBytecodeAgainst_Pure() public {
        SampleTarget target = new SampleTarget();
        bytes32 live = _liveCodehash(address(target));
        assertTrue(registry.verifyBytecodeAgainst(address(target), live), "matches itself");
        assertFalse(registry.verifyBytecodeAgainst(address(target), bytes32(uint256(1))), "wrong hash");
        assertFalse(registry.verifyBytecodeAgainst(address(0xDEAD), live), "eoa never matches");
    }

    function test_NonceUsed_TracksSequentialCounter() public {
        _registerAuditor(auditor);
        assertFalse(registry.nonceUsed(auditor, 0), "0 unused initially");
        SampleTarget target = new SampleTarget();
        (IAuditRegistry.Attestation memory att, bytes memory sig) =
            _signAttestation(address(target), keccak256("n"), 1, false, 0);
        registry.recordAudit(att, sig, "0.8.20", "", "");
        assertTrue(registry.nonceUsed(auditor, 0), "0 used after record");
        assertFalse(registry.nonceUsed(auditor, 1), "1 still unused");
    }

    // ============================================================
    //                  6. Slashing hook (owner-only stub)
    // ============================================================

    function test_SlashAuditor_HookCallable_ByOwnerOnly() public {
        _registerAuditor(auditor);
        IAuditRegistry.Auditor memory a = registry.getAuditor(auditor);
        assertEq(a.staked, MIN_STAKE, "staked before");

        // Non-owner reverts (onlyOwner).
        vm.prank(other);
        vm.expectRevert();
        registry.slashAuditor(auditor, "bad audit");

        // Owner succeeds, emits, zeroes stake.
        vm.expectEmit(true, true, true, true);
        emit AuditorSlashed(auditor, MIN_STAKE, "bad audit");
        vm.prank(owner);
        registry.slashAuditor(auditor, "bad audit");

        IAuditRegistry.Auditor memory a2 = registry.getAuditor(auditor);
        assertEq(a2.staked, 0, "staked zeroed");
        assertFalse(a2.registered, "deregistered after slash");
    }

    // Regression for the slash-doesn't-stop-attestation bug: a slashed auditor
    // (zeroed bond) must NOT be able to record a new audit.
    function test_SlashedAuditor_CannotAttest() public {
        _registerAuditor(auditor);
        SampleTarget target = new SampleTarget();
        (IAuditRegistry.Attestation memory att, bytes memory sig) =
            _signAttestation(address(target), keccak256("first"), 1, false, 0);
        registry.recordAudit(att, sig, "0.8.20", "", "");

        // Slashed.
        vm.prank(owner);
        registry.slashAuditor(auditor, "bad faith");

        // A fresh attestation signed by the slashed auditor must revert. The
        // contract checks `registered` first (false after slash).
        (IAuditRegistry.Attestation memory att2, bytes memory sig2) =
            _signAttestation(address(target), keccak256("second"), 2, false, 1);
        vm.expectRevert(bytes("Signer not registered"));
        registry.recordAudit(att2, sig2, "0.8.20", "", "");
    }

    // Regression for the unbound-bundle bug: a relayer cannot attach a bundle
    // whose hash differs from the signed reportHash.
    function test_RecordAudit_RevertsOn_BundleHashMismatch() public {
        _registerAuditor(auditor);
        SampleTarget target = new SampleTarget();
        (IAuditRegistry.Attestation memory att, bytes memory sig) =
            _signAttestation(address(target), keccak256("real-report"), 1, false, 0);
        bytes memory tamperedBundle = bytes("this is not the real bundle");
        vm.expectRevert(bytes("Bundle hash mismatch"));
        registry.recordAudit(att, sig, "0.8.20", tamperedBundle, "");
    }

    function test_Sweep_RecoversStrandedETH() public {
        // Strand some ETH via receive().
        (bool ok,) = payable(address(registry)).call{value: 0.5 ether}("");
        require(ok);
        assertEq(address(registry).balance, 0.5 ether, "strand");

        uint256 ownerBefore = owner.balance;
        vm.prank(owner);
        registry.sweep(payable(owner));
        assertEq(address(registry).balance, 0, "swept clean");
        assertEq(owner.balance, ownerBefore + 0.5 ether, "owner received");

        // Non-owner cannot sweep.
        vm.expectRevert();
        vm.prank(other);
        registry.sweep(payable(other));
    }
}
