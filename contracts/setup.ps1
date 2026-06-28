# Vendors the Solidity dependencies the contracts project needs.
# Run once after a fresh clone, before `forge build`.
#
# OZ v5.1.0 and forge-std v1.9.4 are pinned for reproducibility.
# (Foundry submodules would also work via `forge install`, but vendoring
# without submodules keeps the repo dependency-free.)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$libDir = Join-Path $PSScriptRoot "lib"
New-Item -ItemType Directory -Force -Path $libDir | Out-Null

function Vendor($name, $url, $tag) {
    $dest = Join-Path $libDir $name
    if (Test-Path (Join-Path $dest $name)) {
        # forge-std clone puts its own dir; OZ clone puts contracts/ at top.
    }
    if ((Test-Path (Join-Path $dest "src")) -or (Test-Path (Join-Path $dest "contracts"))) {
        Write-Output "$name already vendored at $dest"
        return
    }
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    Write-Output "Vendoring $name@$tag ..."
    & git clone --depth 1 --branch $tag --single-branch $url $dest 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "git clone failed for $name@$tag" }
    Remove-Item -Recurse -Force (Join-Path $dest ".git") -ErrorAction SilentlyContinue
    Write-Output "  -> $dest"
}

Vendor "openzeppelin-contracts" "https://github.com/OpenZeppelin/openzeppelin-contracts.git" "v5.1.0"
Vendor "forge-std" "https://github.com/foundry-rs/forge-std.git" "v1.9.4"

Write-Output ""
Write-Output "Done. You can now run:  forge build"
