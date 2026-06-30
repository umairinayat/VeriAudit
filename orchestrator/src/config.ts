// Centralized config. All values come from .env (see repo .env.example).
// Fails fast on missing critical values so we never run misconfigured.

import "dotenv/config";

function required(key: string, fallback?: string): string {
  const v = process.env[key] ?? fallback;
  if (v === undefined || v === "") {
    throw new Error(`Missing required env var: ${key}`);
  }
  return v;
}

function optional(key: string, fallback = ""): string {
  return process.env[key] ?? fallback;
}

export const config = {
  port: Number(process.env.ORCH_PORT ?? 8000),
  workerUrl: required("WORKER_URL", "http://127.0.0.1:8001"),
  rpcUrl: required("RPC_URL", "http://127.0.0.1:8545"),
  chainId: Number(process.env.CHAIN_ID ?? 31337), // 31337=anvil, 11155111=sepolia
  registryAddress: required("AUDIT_REGISTRY_ADDRESS") as `0x${string}`,
  // Auditor key: the private key that signs EIP-712 attestations and is
  // registered on-chain. MUST correspond to a registered, staked auditor.
  auditorKey: required("AUDITOR_PRIVATE_KEY") as `0x${string}`,
  auditorAddress: required("AUDITOR_ADDRESS") as `0x${string}`,
  reportStorage: optional("REPORT_STORAGE", "./.reports"),
  ipfsApi: optional("IPFS_API", ""), // empty = no IPFS pinning; bundle stored as event + local
  // Optional bearer-token auth on mutating endpoints (POST /audit, POST /attest).
  // If unset, the server runs in permissive DEV mode and logs a loud warning.
  // NEVER leave unset on a deployed orchestrator: /attest signs + submits
  // on-chain transactions with the auditor key.
  apiKey: optional("ORCH_API_KEY", ""),
  // CORS allowlist (comma-separated origins). Empty = allow all (dev only).
  corsOrigins: optional("ORCH_CORS_ORIGINS", ""),
  eip712: {
    name: "VeriAudit",
    version: "1",
  },
} as const;
