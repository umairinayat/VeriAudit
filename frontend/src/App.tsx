import { useEffect, useState } from "react";
import { SubmitForm } from "./components/SubmitForm.js";
import { Verify } from "./components/Verify.js";
import { RPC_URL, REGISTRY_ADDRESS } from "./lib/config.js";
import "./styles.css";

type Tab = "audit" | "verify";

/** Polls the chain for a live block height. Degrades silently if the RPC
 *  rejects browser CORS (the chip just hides the number). */
function useChainStatus() {
  const [block, setBlock] = useState<number | null>(null);
  useEffect(() => {
    let stop = false;
    const tick = async () => {
      try {
        const r = await fetch(RPC_URL, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
        });
        const j = await r.json();
        if (!stop && typeof j?.result === "string") setBlock(parseInt(j.result, 16));
      } catch {
        /* CORS or offline — keep chip minimal */
      }
    };
    void tick();
    const h = setInterval(tick, 4000);
    return () => {
      stop = true;
      clearInterval(h);
    };
  }, []);
  return block;
}

function short(addr: string) {
  return addr.length === 42 ? `${addr.slice(0, 6)}…${addr.slice(-4)}` : addr;
}

export default function App() {
  const [tab, setTab] = useState<Tab>("audit");
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const block = useChainStatus();

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
  }

  return (
    <>
      <header className="header">
        <div className="brand" onClick={() => setTab("audit")}>
          <svg className="logo" width="22" height="22" viewBox="0 0 24 24" fill="none">
            <path d="M12 2.5 4.5 5.5v5.4c0 4.6 3.2 8.5 7.5 10.1 4.3-1.6 7.5-5.5 7.5-10.1V5.5L12 2.5Z" fill="var(--accent-weak)" stroke="var(--accent)" strokeWidth="1.4" />
            <path d="m8.5 12 2.5 2.5 4.5-5" stroke="var(--accent)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span>Veri<span className="v">Audit</span></span>
        </div>
        <nav className="nav">
          <button className={tab === "audit" ? "active" : ""} onClick={() => setTab("audit")}>
            Audit
          </button>
          <button className={tab === "verify" ? "active" : ""} onClick={() => setTab("verify")}>
            Verify
          </button>
        </nav>
        <div className="header-right">
          <span className="chip" title={REGISTRY_ADDRESS}>
            <span className="dot" />
            <span className="label">registry</span>
            <span className="val mono">{short(REGISTRY_ADDRESS)}</span>
            {block !== null && <span className="label" style={{ marginLeft: 4 }}>· blk {block.toLocaleString()}</span>}
          </span>
          <button className="icon-btn" onClick={toggleTheme} title="Toggle theme" aria-label="Toggle theme">
            {theme === "dark" ? "☀" : "☾"}
          </button>
        </div>
      </header>

      <main>{tab === "audit" ? <SubmitForm /> : <Verify />}</main>
    </>
  );
}
