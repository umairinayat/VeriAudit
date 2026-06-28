// AuditRegistry ABI + wagmi config. /verify can read the contract DIRECTLY via
// wagmi (no backend needed) — that's the "decentralized verifier" deliverable.
// For simplicity we also expose the orchestrator-proxied verify in api.ts.

import ABI from "./AuditRegistry.abi.json" with { type: "json" };
export { ABI };

// Config is injected at build/runtime via Vite env vars. Defaults point at a
// local Anvil; override with VITE_* in a .env to target Sepolia.
export const CHAIN_ID = Number(import.meta.env.VITE_CHAIN_ID ?? 31337);
export const REGISTRY_ADDRESS = (import.meta.env.VITE_REGISTRY_ADDRESS ??
  "0x0000000000000000000000000000000000000000") as `0x${string}`;
export const RPC_URL = String(import.meta.env.VITE_RPC_URL ?? "http://127.0.0.1:8545");
