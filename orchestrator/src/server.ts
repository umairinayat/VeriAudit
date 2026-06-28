// Fastify server exposing the 6 API endpoints from the brief (Section 8):
//   POST /audit              submit source/address/repo -> job id
//   GET  /audit/:id/status   poll layered-engine progress
//   GET  /audit/:id/report   full report bundle + findings
//   POST /attest/:id         hash bundle + recordAudit on-chain -> tx hash
//   GET  /verify/:address    read live bytecode + verifyBytecode
//   GET  /history/:address   audit history for diff view

import Fastify from "fastify";
import cors from "@fastify/cors";
import { z } from "zod";
import { config } from "./config.js";
import { analyze } from "./workerClient.js";
import { ensureAuditorRegistered, recordAudit, verifyBytecode, getHistory } from "./chain.js";
import { pinBundle } from "./ipfs.js";
import { newJob, getJob, updateJob } from "./jobs.js";
import type { Address } from "viem";

const auditBody = z.object({
  mode: z.enum(["source", "address", "repo"]),
  source: z.string().optional(),
  address: z.string().regex(/^0x[a-fA-F0-9]{40}$/).optional(),
  repo: z.string().optional(),
  commit: z.string().optional(),
});

export async function buildServer() {
  const app = Fastify({ logger: true });
  await app.register(cors, { origin: true });

  app.get("/health", async () => ({ status: "ok", registry: config.registryAddress }));

  // ---------- POST /audit ----------
  app.post("/audit", async (req, reply) => {
    const parsed = auditBody.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: parsed.error.flatten() });
    }
    const b = parsed.data;
    if (!b.source && !b.address && !b.repo) {
      return reply.code(400).send({ error: "supply source | address | repo" });
    }
    const job = newJob();

    // Fire-and-forget the worker call; client polls /status.
    void (async () => {
      try {
        updateJob(job.id, { status: "running", stage: "INGEST" });
        const bundle = await analyze({
          mode: b.mode,
          source: b.source,
          address: b.address,
          repo: b.repo,
          commit: b.commit,
          rpc_url: config.rpcUrl,
        });
        updateJob(job.id, {
          status: "done",
          stage: "ASSEMBLE",
          stages: bundle.stages,
          bundle,
          contractAddress: b.address ?? null,
          reportHash: bundle.report_hash,
        });
      } catch (e) {
        updateJob(job.id, { status: "failed", error: e instanceof Error ? e.message : String(e) });
      }
    })();

    return reply.code(202).send({ id: job.id, status: job.status });
  });

  // ---------- GET /audit/:id/status ----------
  app.get("/audit/:id/status", async (req, reply) => {
    const job = getJob((req.params as { id: string }).id);
    if (!job) return reply.code(404).send({ error: "job not found" });
    return {
      id: job.id,
      status: job.status,
      stage: job.stage,
      stages: job.stages,
      reportHash: job.reportHash,
      error: job.error,
    };
  });

  // ---------- GET /audit/:id/report ----------
  app.get("/audit/:id/report", async (req, reply) => {
    const job = getJob((req.params as { id: string }).id);
    if (!job) return reply.code(404).send({ error: "job not found" });
    if (job.status !== "done" || !job.bundle) {
      return reply.code(409).send({ error: `job is ${job.status}` });
    }
    return job.bundle;
  });

  // ---------- POST /attest/:id ----------
  app.post("/attest/:id", async (req, reply) => {
    const job = getJob((req.params as { id: string }).id);
    if (!job) return reply.code(404).send({ error: "job not found" });
    if (job.status !== "done" || !job.bundle) {
      return reply.code(409).send({ error: `job is ${job.status}` });
    }
    // Need a contract address: require one in the body OR from the job.
    const body = (req.body ?? {}) as { contractAddress?: string };
    const contractAddress = (body.contractAddress ?? job.contractAddress) as Address | undefined;
    if (!contractAddress) {
      return reply.code(400).send({
        error: "contractAddress required (job had none; pass it in the body)",
      });
    }
    try {
      await ensureAuditorRegistered();
      const pinned = await pinBundle(job.bundle.bundle_canonical);
      const { txHash } = await recordAudit(job.bundle, contractAddress, pinned.cid);
      updateJob(job.id, { txHash });
      return { txHash, reportHash: job.reportHash, ipfsCid: pinned.cid, pinned: pinned.pinned };
    } catch (e) {
      req.log.error({ err: e }, "attest failed");
      return reply.code(500).send({ error: e instanceof Error ? e.message : String(e) });
    }
  });

  // ---------- GET /verify/:address ----------
  app.get("/verify/:address", async (req, reply) => {
    const addr = (req.params as { address: string }).address as Address;
    try {
      const v = await verifyBytecode(addr);
      return {
        address: addr,
        matches: v.matches,
        severityScore: v.severityScore,
        exploitProven: v.exploitProven,
        auditor: v.auditor,
        timestamp: Number(v.timestamp),
        auditIndex: Number(v.auditIndex),
      };
    } catch (e) {
      // Contract reverts "No audit found" -> map to 404.
      const msg = e instanceof Error ? e.message : String(e);
      if (/No audit/i.test(msg)) return reply.code(404).send({ error: msg, address: addr });
      return reply.code(500).send({ error: msg, address: addr });
    }
  });

  // ---------- GET /history/:address ----------
  app.get("/history/:address", async (req, reply) => {
    const addr = (req.params as { address: string }).address as Address;
    try {
      const history = await getHistory(addr);
      return {
        address: addr,
        count: history.length,
        audits: history.map((h, i) => ({
          index: i,
          reportHash: h.reportHash,
          bytecodeHash: h.bytecodeHash,
          severityScore: h.severityScore,
          exploitProven: h.exploitProven,
          auditor: h.auditor,
          timestamp: Number(h.timestamp),
        })),
      };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/No audit/i.test(msg)) return reply.code(404).send({ error: msg, address: addr });
      return reply.code(500).send({ error: msg, address: addr });
    }
  });

  return app;
}

// Entrypoint when run directly.
const isMain = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"));
if (isMain) {
  buildServer().then(async (app) => {
    try {
      await app.listen({ port: config.port, host: "0.0.0.0" });
    } catch (e) {
      app.log.error(e);
      process.exit(1);
    }
  });
}
