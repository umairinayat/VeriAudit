// In-memory job store. Maps job id -> { status, stage, bundle, error, createdAt }.
// v1 keeps it in-process; swap for Redis/Postgres when scaling.

import { randomUUID } from "node:crypto";
import type { WorkerResponse } from "./workerClient.js";

export type JobStatus = "pending" | "running" | "done" | "failed";

export interface Job {
  id: string;
  status: JobStatus;
  stage: string; // last completed worker stage
  stages: string[]; // all stages (filled when done)
  bundle: WorkerResponse | null;
  contractAddress: string | null;
  txHash: string | null;
  reportHash: string | null;
  error: string | null;
  createdAt: number;
  updatedAt: number;
}

const jobs = new Map<string, Job>();

export function newJob(): Job {
  const id = randomUUID();
  const now = Date.now();
  const job: Job = {
    id,
    status: "pending",
    stage: "",
    stages: [],
    bundle: null,
    contractAddress: null,
    txHash: null,
    reportHash: null,
    error: null,
    createdAt: now,
    updatedAt: now,
  };
  jobs.set(id, job);
  return job;
}

export function getJob(id: string): Job | undefined {
  return jobs.get(id);
}

export function updateJob(id: string, patch: Partial<Job>): Job {
  const cur = jobs.get(id);
  if (!cur) throw new Error(`unknown job ${id}`);
  const next = { ...cur, ...patch, updatedAt: Date.now() };
  jobs.set(id, next);
  return next;
}

export function listJobs(): Job[] {
  return [...jobs.values()].sort((a, b) => b.createdAt - a.createdAt);
}
