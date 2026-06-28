// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BytecodeVerifier
/// @notice Pure helper that wraps the EXTCODEHASH opcode (`address.codehash`).
///         The audited `bytecodeHash` MUST equal keccak256(runtime bytecode),
///         which is exactly what EXTCODEHASH returns. This makes on-chain
///         verification a single opcode and fully decentralized: anyone can call
///         it, no backend required.
///
/// @dev Caveats documented for honesty (CLAUDE.md honesty rules):
///      - EXTCODEHASH returns bytes32(0) for EOAs and precompiles. We treat 0 as
///        "no contract / not a match" to avoid a false-positive against an
///        empty-code audit.
///      - CREATE2 + selfdestruct can redeploy different code at the same address.
///        `liveCodehash(target)` will then reflect the NEW code. This is a known
///        trust assumption surfaced in the README.
library BytecodeVerifier {
    /// @return hash keccak256 of the deployed runtime bytecode at `target`, or
    ///         bytes32(0) if `target` is an EOA / precompile / empty.
    function liveCodehash(address target) internal view returns (bytes32 hash) {
        assembly {
            hash := extcodehash(target)
        }
    }

    /// @return true iff `target` has code AND its live codehash equals `expected`.
    function matches(address target, bytes32 expected) internal view returns (bool) {
        bytes32 live = liveCodehash(target);
        return live != bytes32(0) && live == expected;
    }
}
