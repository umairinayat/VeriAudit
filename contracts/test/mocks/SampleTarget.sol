// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Trivial target contract deployed in tests so we can compute a real
///         EXTCODEHASH and exercise verifyBytecode end-to-end. Lives under test/
///         so it never ships in the production build.
contract SampleTarget {
    uint256 public value;

    function set(uint256 v) external {
        value = v;
    }

    function get() external view returns (uint256) {
        return value;
    }
}

/// @notice A second target with different runtime bytecode, used to test the
///         "bytecode does not match" path of verifyBytecode.
contract SampleTargetVariant {
    bool public flag;

    function toggle() external {
        flag = !flag;
    }
}
