// Client for the TS orchestrator REST API. Mirrors workerClient.ts types.
// In dev, Vite proxies these to :8000 (see vite.config.ts).

export interface Finding {
  id: string;
  type: string;
  swc_id: string;
  extended_tax: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  confidence: number;
  location: { file: string; lines: number[] };
  explanation: string;
  suggested_fix: string;
  exploit_status: "proven" | "unconfirmed" | "not_supported";
}

export interface Fingerprints {
  source_hash: string;
  commit_hash: string;
  bytecode_hash: string;
  compiler_version: string;
}

export interface Report {
  fingerprints: Fingerprints;
  findings: Finding[];
  severity_score: number;
  exploit_proven: boolean;
  bundle_canonical: string;
  report_hash: string;
  stages: string[];
}

export interface Status {
  id: string;
  status: "pending" | "running" | "done" | "failed";
  stage: string;
  stages: string[];
  reportHash: string | null;
  error: string | null;
}

export interface VerifyResult {
  address: string;
  matches: boolean;
  severityScore: number;
  exploitProven: boolean;
  auditor: string;
  timestamp: number;
  auditIndex: number;
}

export interface HistoryAudit {
  index: number;
  reportHash: string;
  bytecodeHash: string;
  severityScore: number;
  exploitProven: boolean;
  auditor: string;
  timestamp: number;
}

export interface History {
  address: string;
  count: number;
  audits: HistoryAudit[];
}

async function jfetch<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, init);
  if (!r.ok) throw new Error(`${r.status} ${await r.text().catch(() => "")}`);
  return (await r.json()) as T;
}

export function submitAudit(body: {
  mode: "source" | "address" | "repo";
  source?: string;
  address?: string;
  repo?: string;
  commit?: string;
}) {
  return jfetch<{ id: string; status: string }>("/audit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

export const getStatus = (id: string) => jfetch<Status>(`/audit/${id}/status`);
export const getReport = (id: string) => jfetch<Report>(`/audit/${id}/report`);

export function attest(id: string, contractAddress: string) {
  return jfetch<{ txHash: string; reportHash: string; ipfsCid: string; pinned: boolean }>(
    `/attest/${id}`,
    { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ contractAddress }) },
  );
}

export const verify = (addr: string) => jfetch<VerifyResult>(`/verify/${addr}`);
export const history = (addr: string) => jfetch<History>(`/history/${addr}`);
