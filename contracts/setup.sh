#!/usr/bin/env bash
# Vendors the Solidity dependencies the contracts project needs.
# Run once after a fresh clone, before `forge build`.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p lib

vendor() {
    local name="$1" url="$2" tag="$3"
    local dest="lib/$name"
    if [[ -d "$dest/src" || -d "$dest/contracts" ]]; then
        echo "$name already vendored at $dest"
        return
    fi
    rm -rf "$dest"
    echo "Vendoring $name@$tag ..."
    git clone --depth 1 --branch "$tag" --single-branch "$url" "$dest" >/dev/null 2>&1
    rm -rf "$dest/.git"
    echo "  -> $dest"
}

vendor openzeppelin-contracts https://github.com/OpenZeppelin/openzeppelin-contracts.git v5.1.0
vendor forge-std https://github.com/foundry-rs/forge-std.git v1.9.4

echo ""
echo "Done. You can now run:  forge build"
