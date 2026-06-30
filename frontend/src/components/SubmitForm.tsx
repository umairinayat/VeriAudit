import { useEffect, useState } from "react";
import { submitAudit, getStatus, getReport, attest, type Report, type Status } from "../lib/api.js";

type Mode = "source" | "address" | "repo";

const PIPELINE_STAGES = ["INGEST", "FINGERPRINT", "STATIC", "ML_RISK", "LLM_REASON", "EXPLOIT_POC", "CLASSIFY", "ASSEMBLE"];

export function SubmitForm() {
  const [mode, setMode] = useState<Mode>("source");
  const [source, setSource] = useState(SAMPLE_VULN);
  const [address, setAddress] = useState("");
  const [repo, setRepo] = useState("");
  const [commit, setCommit] = useState("");
  const [contractAddress, setContractAddress] = useState("");

  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [attestTx, setAttestTx] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setError(null);
    setReport(null);
    setAttestTx(null);
    setStatus(null);
    setBusy(true);
    try {
      const body =
        mode === "source" ? { mode, source } : mode === "address" ? { mode, address } : { mode, repo, commit };
      const { id } = await submitAudit(body);
      setJobId(id);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  // Poll status while a job is running.
  useEffect(() => {
    if (!jobId) return;
    let stop = false;
    const poll = async () => {
      while (!stop) {
        try {
          const st = await getStatus(jobId);
          setStatus(st);
          if (st.status === "done") {
            setReport(await getReport(jobId));
            setBusy(false);
            return;
          }
          if (st.status === "failed") {
            setError(st.error ?? "analysis failed");
            setBusy(false);
            return;
          }
        } catch (e) {
          if (!stop) setError(e instanceof Error ? e.message : String(e));
          setBusy(false);
          return;
        }
        await new Promise((r) => setTimeout(r, 1200));
      }
    };
    void poll();
    return () => {
      stop = true;
    };
  }, [jobId]);

  async function doAttest() {
    if (!jobId || !contractAddress) return;
    setError(null);
    try {
      const r = await attest(jobId, contractAddress);
      setAttestTx(r.txHash);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="col">
      <div className="card framed reveal reveal-1">
        <h2>Submit contract for audit</h2>
        <div className="tabs">
          {(["source", "address", "repo"] as Mode[]).map((m) => (
            <button key={m} className={mode === m ? "active" : ""} onClick={() => setMode(m)}>
              {m === "source" ? "Paste source" : m === "address" ? "Deployed address" : "Git repo + commit"}
            </button>
          ))}
        </div>

        {mode === "source" && (
          <div>
            <label>Solidity source</label>
            <textarea rows={9} value={source} onChange={(e) => setSource(e.target.value)} spellCheck={false} />
          </div>
        )}
        {mode === "address" && (
          <div>
            <label>Contract address (0x…)</label>
            <input type="text" placeholder="0x9fE4…" value={address} onChange={(e) => setAddress(e.target.value)} spellCheck={false} />
          </div>
        )}
        {mode === "repo" && (
          <div className="row">
            <div style={{ flex: 2 }}>
              <label>Git URL</label>
              <input type="text" placeholder="https://github.com/…/repo.git" value={repo} onChange={(e) => setRepo(e.target.value)} spellCheck={false} />
            </div>
            <div style={{ flex: 1 }}>
              <label>Commit (optional)</label>
              <input type="text" placeholder="HEAD or 0xabc…" value={commit} onChange={(e) => setCommit(e.target.value)} spellCheck={false} />
            </div>
          </div>
        )}

        <div style={{ marginTop: 18 }}>
          <button className="btn" onClick={submit} disabled={busy}>
            {busy ? "Analyzing…" : "▸ Run audit"}
          </button>
        </div>
      </div>

      {status && (
        <div className="card reveal reveal-2">
          <h2>Pipeline progress</h2>
          <PipelineRail stages={status.stages} running={status.status === "running"} />
          {status.error && <p className="muted" style={{ marginTop: 14 }}>Error: {status.error}</p>}
        </div>
      )}

      {report && (
        <>
          <SummaryCard report={report} />
          <FindingsCard report={report} />
          <AttestCard
            contractAddress={contractAddress}
            setContractAddress={setContractAddress}
            onAttest={doAttest}
            attestTx={attestTx}
            disabled={!report}
          />
        </>
      )}

      {error && (
        <div className="card reveal" style={{ borderColor: "var(--crit)" }}>
          <p className="mono" style={{ color: "var(--crit)", margin: 0, fontSize: 13 }}>! {error}</p>
        </div>
      )}

      <p className="honesty">
        <strong>Honesty note —</strong> AI = first-pass triage + monitoring, not a human-auditor replacement. Only
        supported vulnerability classes can be marked “proven”; everything else is “detected-but-not-auto-validated.”
      </p>
    </div>
  );
}

/** Instrument-style horizontal rail. The signature visualization of the pipeline. */
function PipelineRail({ stages, running }: { stages: string[]; running: boolean }) {
  const done = new Set(stages);
  const runningStage = running && stages.length < PIPELINE_STAGES.length ? PIPELINE_STAGES[stages.length] : null;
  return (
    <div className="rail-wrap">
      <div className="rail">
        {PIPELINE_STAGES.map((s) => {
          const state = done.has(s) ? "done" : s === runningStage ? "running" : "";
          const glyph = done.has(s) ? "✓" : s === runningStage ? "" : String(PIPELINE_STAGES.indexOf(s) + 1).padStart(2, "0");
          return (
            <div key={s} className={`rail-node ${state}`}>
              <div className="rail-bubble">{glyph}</div>
              <div className="rail-label">{s}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SummaryCard({ report }: { report: Report }) {
  const tone = report.severity_score >= 70 ? "var(--crit)" : report.severity_score >= 40 ? "var(--med)" : "var(--low)";
  const offset = 226 - (226 * report.severity_score) / 100;
  const verdict =
    report.severity_score >= 70 ? "HIGH RISK" : report.severity_score >= 40 ? "ELEVATED" : report.severity_score > 0 ? "LOW RISK" : "CLEAN";
  return (
    <div className="card framed reveal reveal-2">
      <h2>Audit summary · {verdict}</h2>
      <div className="gauge-wrap">
        <div className="gauge">
          <svg width="120" height="120" viewBox="0 0 84 84">
            <circle className="track" cx="42" cy="42" r="36" />
            <circle className="arc" cx="42" cy="42" r="36" stroke={tone} strokeDashoffset={offset} />
          </svg>
          <div className="gauge-center">
            <span className="score" style={{ color: tone }}>{report.severity_score}</span>
            <span className="unit">risk / 100</span>
          </div>
        </div>
        <div className="stat-grid">
          <div className="stat">
            <div className="k">exploit</div>
            <div className="v" style={{ color: report.exploit_proven ? "var(--crit)" : "var(--text2)" }}>
              {report.exploit_proven ? "PROVEN" : "none"}
            </div>
          </div>
          <div className="stat">
            <div className="k">findings</div>
            <div className="v">{report.findings.length}</div>
          </div>
          <div className="stat">
            <div className="k">solc</div>
            <div className="v">{report.fingerprints.compiler_version}</div>
          </div>
          <div className="stat">
            <div className="k">report hash</div>
            <div className="v small mono">{report.report_hash.slice(0, 20)}…</div>
          </div>
          <div className="stat">
            <div className="k">bytecode hash</div>
            <div className="v small mono">{report.fingerprints.bytecode_hash.slice(0, 20)}…</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function FindingsCard({ report }: { report: Report }) {
  if (report.findings.length === 0) {
    return (
      <div className="card reveal reveal-3">
        <h2>Findings</h2>
        <div className="empty">
          <div className="glyph">○</div>
          <div>No findings from the static + ML + LLM passes.</div>
        </div>
      </div>
    );
  }
  return (
    <div className="card reveal reveal-3">
      <h2>Findings · {report.findings.length}</h2>
      <div className="findings-list">
        {report.findings.map((f, i) => (
          <div key={f.id} className={`finding sev-${f.severity}`} style={{ animationDelay: `${0.3 + i * 0.06}s` }}>
            <div className="finding-head">
              <span className="finding-id">{f.id}</span>
              <span className="finding-type">{f.type}</span>
              <span className={`badge ${f.severity}`}>{f.severity}</span>
              <span className={`exploit ${f.exploit_status}`}>{f.exploit_status.replace("_", " ")}</span>
              <span className="finding-swc">{f.swc_id}</span>
              <span className="spacer" />
              <span className="loc">
                {f.location.file}:{f.location.lines.join("-")}
              </span>
            </div>
            <p>{f.explanation}</p>
            {f.suggested_fix && (
              <div className="fix">
                <div className="fix-head">▸ Suggested fix</div>
                {f.suggested_fix}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function AttestCard({
  contractAddress,
  setContractAddress,
  onAttest,
  attestTx,
  disabled,
}: {
  contractAddress: string;
  setContractAddress: (v: string) => void;
  onAttest: () => void;
  attestTx: string | null;
  disabled: boolean;
}) {
  return (
    <div className="card framed reveal reveal-4">
      <h2>Attest on-chain</h2>
      <p className="muted" style={{ fontSize: 13, margin: "0 0 14px" }}>
        EIP-712 signs the report hash + fingerprints, then submits <span className="mono">recordAudit()</span> to the
        registry. Required for trustless <span className="mono">/verify</span>.
      </p>
      <label>Contract address to attest against</label>
      <input type="text" placeholder="0x…" value={contractAddress} onChange={(e) => setContractAddress(e.target.value)} spellCheck={false} />
      <div style={{ marginTop: 14 }}>
        <button className="btn" onClick={onAttest} disabled={disabled || !contractAddress}>
          ⚡ Sign + submit attestation
        </button>
      </div>
      {attestTx && <div className="tx-pill">✓ tx {attestTx}</div>}
    </div>
  );
}

const SAMPLE_VULN = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}`;
