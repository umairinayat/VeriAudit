import { useState } from "react";
import { SubmitForm } from "./components/SubmitForm.js";
import { Verify } from "./components/Verify.js";
import "./styles.css";

type Tab = "audit" | "verify";

export default function App() {
  const [tab, setTab] = useState<Tab>("audit");
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
  }

  return (
    <>
      <header className="header">
        <div className="brand" onClick={() => setTab("audit")}>
          <svg className="logo" width="24" height="24" viewBox="0 0 24 24" fill="none">
            <path d="M12 2.5 4.5 5.5v5.4c0 4.6 3.2 8.5 7.5 10.1 4.3-1.6 7.5-5.5 7.5-10.1V5.5L12 2.5Z" fill="var(--accent-weak)" stroke="var(--accent)" strokeWidth="1.4" />
            <path d="m8.5 12 2.5 2.5 4.5-5" stroke="var(--accent)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          VeriAudit
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
          <span className="chip">
            <span className="dot" />
            <span>VeriAudit Registry</span>
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
