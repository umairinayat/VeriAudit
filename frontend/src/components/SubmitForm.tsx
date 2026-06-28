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
        await new Promise((r) => setTimeout(r, 1500));
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
      <div className="card">
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
            <textarea rows={10} value={source} onChange={(e) => setSource(e.target.value)} />
          </div>
        )}
        {mode === "address" && (
          <div>
            <label>Contract address (0x…)</label>
            <input type="text" placeholder="0x9fE4…" value={address} onChange={(e) => setAddress(e.target.value)} />
          </div>
        )}
        {mode === "repo" && (
          <div className="row">
            <div style={{ flex: 2 }}>
              <label>Git URL</label>
              <input type="text" placeholder="https://github.com/…/repo.git" value={repo} onChange={(e) => setRepo(e.target.value)} />
            </div>
            <div style={{ flex: 1 }}>
              <label>Commit hash (optional)</label>
              <input type="text" placeholder="HEAD or 0xabc…" value={commit} onChange={(e) => setCommit(e.target.value)} />
            </div>
          </div>
        )}

        <div style={{ marginTop: 16 }}>
          <button className="btn" onClick={submit} disabled={busy}>
            {busy ? "Analyzing…" : "Run audit"}
          </button>
        </div>
      </div>

      {status && (
        <div className="card">
          <h2>Pipeline progress</h2>
          <Stepper stages={status.stages} running={status.status === "running"} />
          {status.error && <p className="muted">Error: {status.error}</p>}
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
        <div className="card" style={{ borderColor: "var(--crit)" }}>
          <p style={{ color: "var(--crit)", margin: 0 }}>{error}</p>
        </div>
      )}

      <p className="honesty">
        <strong>Honesty note:</strong> AI = first-pass triage + monitoring, not a human-auditor replacement. Only
        supported vulnerability classes can be marked “proven”; everything else is “detected-but-not-auto-validated.”
      </p>
    </div>
  );
}

function Stepper({ stages, running }: { stages: string[]; running: boolean }) {
  const done = new Set(stages);
  const runningStage = running && stages.length < PIPELINE_STAGES.length ? PIPELINE_STAGES[stages.length] : null;
  return (
    <div className="stepper">
      {PIPELINE_STAGES.map((s) => {
        const cls = done.has(s) ? "done" : s === runningStage ? "running" : "";
        return (
          <div key={s} className={`stage ${cls}`}>
            <span className="check">{done.has(s) ? "✓" : s === runningStage ? "↻" : "·"}</span>
            {s}
          </div>
        );
      })}
    </div>
  );
}

function SummaryCard({ report }: { report: Report }) {
  const counts: Record<string, number> = {};
  for (const f of report.findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const tone = report.severity_score >= 70 ? "var(--crit)" : report.severity_score >= 40 ? "var(--med)" : "var(--low)";
  const circ = 226;
  const offset = circ - (circ * report.severity_score) / 100;
  return (
    <div className="card">
      <div className="row" style={{ alignItems: "center" }}>
        <div className="gauge">
          <svg width="84" height="84" viewBox="0 0 84 84" style={{ transform: "rotate(-90deg)" }}>
            <circle cx="42" cy="42" r="36" fill="none" stroke="var(--border)" strokeWidth="7" />
            <circle cx="42" cy="42" r="36" fill="none" stroke={tone} strokeWidth="7" strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={offset} />
          </svg>
          <div>
            <div className="score" style={{ color: tone }}>
              {report.severity_score}
            </div>
            <div className="dim" style={{ fontSize: 11 }}>RISK / 100</div>
          </div>
        </div>
        <div className="spacer" />
        <div className="col">
          {(["Critical", "High", "Medium", "Low", "Info"] as const).map((sev) => (
            <div key={sev} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13 }}>
              <span className={`badge ${sev}`} style={{ padding: "2px 6px" }}>{counts[sev] ?? 0}</span>
              <span className="muted">{sev}</span>
            </div>
          ))}
        </div>
        <div className="col">
          <div style={{ fontSize: 12, color: "var(--text2)" }}>
            exploit:{" "}
            {report.exploit_proven ? <span className="exploit proven">proven</span> : <span className="exploit not_supported">none proven</span>}
          </div>
          <div className="mono dim" style={{ fontSize: 11 }}>reportHash: {report.report_hash.slice(0, 18)}…</div>
          <div className="mono dim" style={{ fontSize: 11 }}>bytecode: {report.fingerprints.bytecode_hash.slice(0, 18)}…</div>
          <div className="mono dim" style={{ fontSize: 11 }}>solc: {report.fingerprints.compiler_version}</div>
        </div>
      </div>
    </div>
  );
}

function FindingsCard({ report }: { report: Report }) {
  if (report.findings.length === 0) {
    return (
      <div className="card">
        <h2>Findings</h2>
        <p className="muted">No findings from the static + ML + LLM passes.</p>
      </div>
    );
  }
  return (
    <div className="card">
      <h2>Findings ({report.findings.length})</h2>
      {report.findings.map((f) => (
        <div key={f.id} className="finding">
          <div className="finding-head">
            <span className="finding-id">{f.id}</span>
            <span className="finding-type">{f.type}</span>
            <span className={`badge ${f.severity}`}>{f.severity}</span>
            <span className="exploit">{f.exploit_status}</span>
            <span className="finding-swc">{f.swc_id}</span>
            <span className="spacer" />
            <span className="loc">
              {f.location.file}:{f.location.lines.join("-")}
            </span>
          </div>
          <p>{f.explanation}</p>
          {f.suggested_fix && <div className="fix">Suggested fix: {f.suggested_fix}</div>}
        </div>
      ))}
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
    <div className="card">
      <h2>Attest on-chain</h2>
      <p className="muted" style={{ fontSize: 13 }}>
        Records the report hash + fingerprints on AuditRegistry. Required for trustless /verify.
      </p>
      <label>Contract address to attest against</label>
      <input type="text" placeholder="0x…" value={contractAddress} onChange={(e) => setContractAddress(e.target.value)} />
      <div style={{ marginTop: 12 }}>
        <button className="btn" onClick={onAttest} disabled={disabled || !contractAddress}>
          Sign + submit attestation
        </button>
      </div>
      {attestTx && (
        <p className="mono" style={{ fontSize: 12, color: "var(--low)", marginTop: 12 }}>
          ✓ tx: {attestTx}
        </p>
      )}
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
