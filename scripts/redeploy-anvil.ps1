# Run this ONLY if Anvil was restarted (registry address returns "no code" / errors).
# It redeploys the registry and re-registers the auditor. Leaves a fresh .env.

$ErrorActionPreference = "Stop"
# Run from the contracts/ dir so the relative `src/...` paths resolve.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $scriptDir "..\contracts")
$rpc = "http://127.0.0.1:8545"
$forge = "$env:USERPROFILE\.foundry\bin\forge.exe"
$cast = "$env:USERPROFILE\.foundry\bin\cast.exe"

# Anvil default accounts (account 0 deploys, account 1 is the auditor).
$deployerPk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
$deployerAddr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
$auditorPk = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
$auditorAddr = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

Write-Output "Deploying AuditRegistry..."
$raw = & $forge create --via-ir src/AuditRegistry.sol:AuditRegistry --rpc-url $rpc --private-key $deployerPk --broadcast --constructor-args 100000000000000000 86400 $deployerAddr 2>&1 | Out-String
$m = [regex]::Match($raw, "Deployed to:\s*(0x[0-9a-fA-F]{40})")
if (-not $m.Success) { throw "deploy failed:`n$raw" }
$reg = $m.Groups[1].Value
Write-Output "Registry: $reg"

Write-Output "Registering auditor..."
& $cast send --rpc-url $rpc --private-key $auditorPk $reg "registerAuditor()" --value 0.1ether | Out-Null

# Rewrite orchestrator/.env
$envPath = "D:\VeriAudit\orchestrator\.env"
@"
ORCH_PORT=8000
WORKER_URL=http://127.0.0.1:8001
RPC_URL=$rpc
CHAIN_ID=31337
AUDIT_REGISTRY_ADDRESS=$reg
AUDITOR_PRIVATE_KEY=$auditorPk
AUDITOR_ADDRESS=$auditorAddr
REPORT_STORAGE=./.reports
IPFS_API=
"@ | Set-Content -Path $envPath -Encoding ascii -NoNewline
Add-Content -Path $envPath -Value ""

Write-Output ""
Write-Output "DONE. Restart the orchestrator (Terminal 2) so it picks up the new .env."
Write-Output "Registry:  $reg"
Write-Output "Auditor:   $auditorAddr"
