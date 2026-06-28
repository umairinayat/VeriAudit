// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {AuditRegistry} from "../src/AuditRegistry.sol";

/// @notice Deploys AuditRegistry. Defaults are reasonable for a local Anvil run;
///         override via env vars for Sepolia.
///         Defaults:
///           minStake     = 0.1 ether
///           unstakeDelay = 1 days
///           owner        = msg.sender (deployer)
contract DeployScript is Script {
    function run() external {
        uint256 minStake = vm.envOr("MIN_STAKE_WEI", uint256(0.1 ether));
        uint256 unstakeDelay = vm.envOr("UNSTAKE_DELAY_SECONDS", uint256(1 days));
        address owner = vm.envOr("REGISTRY_OWNER", address(msg.sender));

        vm.startBroadcast();
        AuditRegistry registry = new AuditRegistry(minStake, unstakeDelay, owner);
        vm.stopBroadcast();

        console2.log("AuditRegistry deployed at:", address(registry));
        console2.log("  minStake (wei):", minStake);
        console2.log("  unstakeDelay (s):", unstakeDelay);
        console2.log("  owner:", owner);
    }
}
