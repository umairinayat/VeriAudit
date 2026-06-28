// HTTP client for the Python AI worker (../worker). The worker is the ONLY
// Python in the platform; it produces the audit bundle, this layer submits it.

import { config } from "./config.js";

export interface WorkerFingerprints {
  source_hash: string;
  commit_hash: string;
  bytecode_hash: string;
  compiler_version: string;
}

export interface WorkerFinding {
  id: string;
  type: string;
  swc_id: string;
  extended_tax: string;
  severity: string;
  confidence: number;
  location: { file: string; lines: number[] };
  explanation: string;
  suggested_fix: string;
  exploit_status: "proven" | "unconfirmed" | "not_supported";
}

export interface WorkerResponse {
  fingerprints: WorkerFingerprints;
  findings: WorkerFinding[];
  severity_score: number;
  exploit_proven: boolean;
  bundle_canonical: string;
  report_hash: string;
  stages: string[];
}

export interface AnalyzeRequest {
  mode: "source" | "address" | "repo";
  source?: string;
  address?: string;
  repo?: string;
  commit?: string;
  rpc_url?: string;
}

/** Call the worker's POST /analyze. Throws on non-2xx or network error. */
export async function analyze(req: AnalyzeRequest, signal?: AbortSignal): Promise<WorkerResponse> {
  const resp = await fetch(`${config.workerUrl}/analyze`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(req),
    signal,
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`worker /analyze failed: ${resp.status} ${text}`);
  }
  return (await resp.json()) as WorkerResponse;
}
