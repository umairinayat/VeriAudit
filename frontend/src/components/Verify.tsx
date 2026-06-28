import { useState } from "react";
import { verify, history, type VerifyResult, type History } from "../lib/api.js";

export function Verify() {
  const [addr, setAddr] = useState("");
  const [v, setV] = useState<VerifyResult | null>(null);
  const [h, setH] = useState<History | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setError(null);
    setV(null);
    setH(null);
    setBusy(true);
    try {
      setV(await verify(addr));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/No audit/i.test(msg)) setError(`No audit recorded for ${addr}`);
      else setError(msg);
    }
    try {
      setH(await history(addr));
    } catch {
      /* history optional */
    }
    setBusy(false);
  }

  return (
    <div className="col">
      <div className="card">
        <h2>Trustless verify</h2>
        <p className="muted" style={{ fontSize: 13 }}>
          Reads the deployed bytecode hash (EXTCODEHASH) on-chain and compares to the latest audit record. Anyone can
          run this — no backend trust required.
        </p>
        <label>Contract address (0x…)</label>
        <input type="text" placeholder="0x9fE4…" value={addr} onChange={(e) => setAddr(e.target.value)} />
        <div style={{ marginTop: 12 }}>
          <button className="btn" onClick={run} disabled={busy || !addr}>
            {busy ? "Verifying…" : "Verify"}
          </button>
        </div>
      </div>

      {error && (
        <div className="card" style={{ borderColor: "var(--crit)" }}>
          <p style={{ color: "var(--crit)", margin: 0 }}>{error}</p>
        </div>
      )}

      {v && (
        <div className="card">
          <div className={`verify-result ${v.matches ? "match" : "mismatch"}`}>
            {v.matches
              ? `✓ MATCH — deployed bytecode equals the audited code (audit #${v.auditIndex})`
              : `✗ MISMATCH — deployed code differs from the latest audit (audit #${v.auditIndex})`}
          </div>
          <div className="row" style={{ marginTop: 16 }}>
            <Field label="Severity score" value={String(v.severityScore)} />
            <Field label="Exploit proven" value={v.exploitProven ? "yes" : "no"} />
            <Field label="Auditor" value={`${v.auditor.slice(0, 10)}…`} mono />
            <Field label="Timestamp" value={new Date(v.timestamp * 1000).toISOString()} mono />
          </div>
        </div>
      )}

      {h && h.count > 0 && (
        <div className="card">
          <h2>Audit history ({h.count})</h2>
          {h.audits.map((a) => (
            <div key={a.index} className="finding">
              <div className="finding-head">
                <span className="finding-id">#{a.index}</span>
                <span className={`badge ${a.severityScore >= 70 ? "Critical" : a.severityScore >= 40 ? "Medium" : "Low"}`}>
                  score {a.severityScore}
                </span>
                <span className={`exploit ${a.exploitProven ? "proven" : "not_supported"}`}>
                  {a.exploitProven ? "proven" : "not proven"}
                </span>
                <span className="spacer" />
                <span className="loc">{new Date(a.timestamp * 1000).toISOString()}</span>
              </div>
              <div className="loc">reportHash: {a.reportHash}</div>
              <div className="loc">bytecode: {a.bytecodeHash}</div>
              <div className="loc">auditor: {a.auditor}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="dim" style={{ fontSize: 11 }}>{label}</div>
      <div className={mono ? "mono" : ""} style={{ fontSize: 13 }}>{value}</div>
    </div>
  );
}
