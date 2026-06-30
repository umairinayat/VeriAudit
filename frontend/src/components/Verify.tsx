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
      <div className="card framed reveal reveal-1">
        <h2>Trustless verify</h2>
        <p className="muted" style={{ fontSize: 13, margin: "0 0 16px" }}>
          Reads the live bytecode hash (EXTCODEHASH) on-chain and compares to the latest audit record. Anyone can run
          this — no backend trust required.
        </p>
        <label>Contract address (0x…)</label>
        <input type="text" placeholder="0x9fE4…" value={addr} onChange={(e) => setAddr(e.target.value)} spellCheck={false} />
        <div style={{ marginTop: 14 }}>
          <button className="btn" onClick={run} disabled={busy || !addr}>
            {busy ? "Verifying…" : "▸ Verify"}
          </button>
        </div>
      </div>

      {error && (
        <div className="card reveal" style={{ borderColor: "var(--crit)" }}>
          <p className="mono" style={{ color: "var(--crit)", margin: 0, fontSize: 13 }}>! {error}</p>
        </div>
      )}

      {v && (
        <div className="card reveal reveal-2">
          <h2>Verification result</h2>
          <div className={`verify-banner ${v.matches ? "match" : "mismatch"}`}>
            <span className="glyph">{v.matches ? "✓" : "✗"}</span>
            <div>
              <div className="txt">{v.matches ? "BYTECODE MATCHES THE AUDITED CODE" : "BYTECODE DOES NOT MATCH"}</div>
              <div className="sub">
                {v.matches
                  ? `Live EXTCODEHASH equals the latest audit record (audit #${v.auditIndex})`
                  : `Deployed code differs from audit #${v.auditIndex} — re-audit required`}
              </div>
            </div>
          </div>
          <div className="stat-grid" style={{ marginTop: 18 }}>
            <div className="stat">
              <div className="k">severity</div>
              <div className="v">{v.severityScore}/100</div>
            </div>
            <div className="stat">
              <div className="k">exploit</div>
              <div className="v" style={{ color: v.exploitProven ? "var(--crit)" : "var(--text2)" }}>
                {v.exploitProven ? "PROVEN" : "none"}
              </div>
            </div>
            <div className="stat">
              <div className="k">auditor</div>
              <div className="v small mono">{v.auditor.slice(0, 10)}…</div>
            </div>
            <div className="stat">
              <div className="k">timestamp</div>
              <div className="v small mono">{new Date(v.timestamp * 1000).toISOString().slice(0, 19).replace("T", " ")}Z</div>
            </div>
          </div>
        </div>
      )}

      {h && h.count > 0 && (
        <div className="card reveal reveal-3">
          <h2>Audit history · {h.count}</h2>
          <div className="findings-list">
            {h.audits.map((a) => (
              <div key={a.index} className={`finding sev-${a.severityScore >= 70 ? "Critical" : a.severityScore >= 40 ? "Medium" : "Low"}`}>
                <div className="finding-head">
                  <span className="finding-id">#{a.index}</span>
                  <span className="finding-type">score {a.severityScore}/100</span>
                  <span className={`exploit ${a.exploitProven ? "proven" : "not_supported"}`}>
                    {a.exploitProven ? "proven" : "not proven"}
                  </span>
                  <span className="spacer" />
                  <span className="loc">{new Date(a.timestamp * 1000).toISOString().slice(0, 19).replace("T", " ")}Z</span>
                </div>
                <div className="loc" style={{ marginTop: 6 }}>reportHash {a.reportHash}</div>
                <div className="loc">bytecode {a.bytecodeHash}</div>
                <div className="loc">auditor {a.auditor}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
