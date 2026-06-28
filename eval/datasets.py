"""Built-in benchmark dataset.

Each case is (source, expected_detectors) where expected_detectors is the set
of worker `type` strings that SHOULD fire. Empty set = clean (no known labeled
vulns in the benchmark context).

A small built-in set ships here so the harness runs without cloning SmartBugs
or DeFiHackLabs. Wire those in by appending cases (same shape) in `load_extra`.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BenchmarkCase:
    id: str
    label: str  # human label
    source: str
    expected: set[str]  # worker detector types expected to fire; empty = clean
    supported_for_exploit: bool  # is the expected class one we can auto-prove?


# Each case's expected detector matches a key in worker.taxonomy.TAXONOMY.
VULN_REENTRANCY = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 b = bal[msg.sender];
        (bool ok,) = msg.sender.call{value: b}("");
        require(ok);
        bal[msg.sender] = 0;
    }
}
"""

VULN_UNCHECKED = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Sender {
    function pay(address to) external payable {
        to.call{value: msg.value}("");  // return value ignored
    }
}
"""

# "Clean" — no known labeled vulnerabilities in the benchmark context.
# NOT claimed to be safe in general. Self-contained (no imports) so the
# worker's solcx compile resolves without remappings.
CLEAN_TOKEN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract FlatCoin {
    string public name = "FlatCoin";
    string public symbol = "FLAT";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) private _bal;
    mapping(address => mapping(address => uint256)) private _allow;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 supply) {
        totalSupply = supply;
        _bal[msg.sender] = supply;
        emit Transfer(address(0), msg.sender, supply);
    }

    function balanceOf(address a) external view returns (uint256) { return _bal[a]; }
    function allowance(address o, address s) external view returns (uint256) { return _allow[o][s]; }

    function transfer(address to, uint256 v) external returns (bool) {
        require(_bal[msg.sender] >= v, "insufficient");
        _bal[msg.sender] -= v;
        _bal[to] += v;
        emit Transfer(msg.sender, to, v);
        return true;
    }

    function approve(address spender, uint256 v) external returns (bool) {
        _allow[msg.sender][spender] = v;
        emit Approval(msg.sender, spender, v);
        return true;
    }

    function transferFrom(address from, address to, uint256 v) external returns (bool) {
        uint256 a = _allow[from][msg.sender];
        require(_bal[from] >= v, "insufficient");
        require(a >= v, "allowance");
        if (a != type(uint256).max) { _allow[from][msg.sender] = a - v; }
        _bal[from] -= v;
        _bal[to] += v;
        emit Transfer(from, to, v);
        return true;
    }
}
"""

CLEAN_COUNTER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Counter {
    uint256 public count;
    function increment() external { count += 1; }
    function decrement() external { count -= 1; }
}
"""


BUILTIN: list[BenchmarkCase] = [
    BenchmarkCase("VB-REENT-01", "reentrancy-eth vault", VULN_REENTRANCY, {"reentrancy-eth"}, True),
    BenchmarkCase("VB-UNCHECK-01", "unchecked low-level call", VULN_UNCHECKED, {"unchecked-lowlevel"}, False),
    BenchmarkCase("CLEAN-01", "erc20 token (no known labeled vuln)", CLEAN_TOKEN, set(), False),
    BenchmarkCase("CLEAN-02", "counter (no known labeled vuln)", CLEAN_COUNTER, set(), False),
]


def load() -> list[BenchmarkCase]:
    """Return the benchmark set. Append external datasets here (SmartBugs /
    DeFiHackLabs) by translating them to BenchmarkCase shape."""
    return list(BUILTIN)
