"use client";
import { useEffect, useRef, useState } from "react";
import { FindingCard } from "@/components/FindingCard";
import { exportPdf } from "@/lib/pdf";
import { SAMPLES, type Finding, type ScanResult, type ScanStep } from "@/lib/types";

const STEP_BADGE: Record<string, { cls: string; label: string }> = {
  clone: { cls: "b-detect", label: "CLONE" },
  detect: { cls: "b-detect", label: "DETECT" },
  file: { cls: "b-file", label: "FILE" },
  source: { cls: "b-src", label: "SOURCE" },
  finding: { cls: "b-find", label: "FINDING" },
  summary: { cls: "b-sum", label: "DONE" },
  error: { cls: "b-find", label: "ERROR" },
};

type Phase = "idle" | "live" | "done" | "err";

export default function Page() {
  const [sample, setSample] = useState("php_native");
  const [path, setPath] = useState("");
  const [steps, setSteps] = useState<{ kind: string; text: string }[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [status, setStatus] = useState("Idle — choose a project and press Scan");
  const [phase, setPhase] = useState<Phase>("idle");
  const [scanning, setScanning] = useState(false);
  const [stack, setStack] = useState("—");
  const [files, setFiles] = useState(0);
  const [theme, setTheme] = useState<"light" | "dark" | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const logRef = useRef<HTMLDivElement | null>(null);

  const highCount = findings.filter((f) => f.severity === "high" || f.severity === "critical").length;

  // Close the stream if the component unmounts mid-scan.
  useEffect(() => () => esRef.current?.close(), []);

  // Hydrate the theme toggle from the value the inline <head> script applied.
  useEffect(() => {
    const cur = document.documentElement.getAttribute("data-theme");
    if (cur === "light" || cur === "dark") setTheme(cur);
    else setTheme("dark");
  }, []);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("sbvf-theme", next);
    } catch {
      /* storage blocked — in-memory toggle still works */
    }
  }

  function pushStep(s: { kind: string; text: string }) {
    setSteps((prev) => [...prev, s]);
    requestAnimationFrame(() => {
      if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
    });
  }

  function parse<T>(e: Event): T | null {
    try {
      return JSON.parse((e as MessageEvent).data) as T;
    } catch {
      return null;
    }
  }

  function scan() {
    esRef.current?.close();
    setSteps([]);
    setFindings([]);
    setResult(null);
    setStack("…");
    setFiles(0);
    const live: Finding[] = [];
    const remote = /^(https?:\/\/|git@|(www\.)?(github\.com|gitlab\.com|bitbucket\.org)\/)/i.test(path.trim());
    setStatus(remote ? "Cloning repository…" : "Scanning…");
    setPhase("live");
    setScanning(true);
    const qs = path.trim() ? `path=${encodeURIComponent(path.trim())}` : `sample=${sample}`;
    const es = new EventSource(`/api/scan?${qs}`);
    esRef.current = es;

    es.addEventListener("scan_step", (e) => {
      const d = parse<ScanStep>(e);
      if (!d) return;
      pushStep({ kind: d.kind, text: d.text });
      if (d.kind === "detect") {
        setStatus("Scanning…");
        const fw = d.data?.frameworks as Record<string, string> | undefined;
        if (fw) setStack(Object.values(fw).filter(Boolean).join(", ") || "none");
        if (typeof d.data?.file_count === "number") setFiles(d.data.file_count as number);
      }
      if (d.kind === "finding" && d.data?.finding) {
        live.push(d.data.finding as Finding);
        setFindings([...live]);
      }
    });
    es.addEventListener("scan_done", (e) => {
      const r = parse<ScanResult>(e);
      if (r) {
        setResult(r);
        setFindings(r.findings);
        setFiles(r.files_scanned);
        setStatus("Completed");
        setPhase("done");
      } else {
        pushStep({ kind: "error", text: "malformed scan_done from backend" });
        setStatus("Error");
        setPhase("err");
      }
      setScanning(false);
      es.close();
    });
    es.addEventListener("scan_error", (e) => {
      const d = parse<{ message: string }>(e);
      pushStep({ kind: "error", text: d?.message || "scan error" });
      setStatus("Error");
      setPhase("err");
      setScanning(false);
      es.close();
    });
    es.onerror = () => {
      setStatus((s) => (s === "Completed" ? s : "Stream ended"));
      setPhase((p) => (p === "done" ? p : "err"));
      setScanning(false);
      es.close();
    };
  }

  const chipCls = phase === "live" ? "live" : phase === "done" ? "done" : phase === "err" ? "err" : "";

  return (
    <div className="shell">
      <nav className="nav">
        <span className="mark" aria-hidden>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2 4 5v6c0 5 3.4 8.3 8 11 4.6-2.7 8-6 8-11V5l-8-3Z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
        </span>
        <span className="wordmark">
          <b>SBVF</b>
          <small>Search-Based Vulnerability Framework</small>
        </span>
        <span className="nav-right">
          <button className="theme-btn" onClick={toggleTheme} aria-label="Toggle colour theme" title="Toggle theme">
            {theme === "dark" ? (
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="4" />
                <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
              </svg>
            ) : (
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z" />
              </svg>
            )}
          </button>
        </span>
      </nav>

      <header className="hero">
        <h1>Find the flaw. See the cost. Close the gap.</h1>
        <p>
          SBVF pairs static taint analysis with search-based testing to surface real web
          vulnerabilities — each one explained in plain business terms, not just a CWE number.
        </p>
      </header>

      <div className="control">
        <div className="field">
          <label htmlFor="sample">Sample project</label>
          <select id="sample" value={sample} onChange={(e) => setSample(e.target.value)}>
            {SAMPLES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
        </div>
        <div className="field" style={{ flex: 1, minWidth: 240 }}>
          <label htmlFor="path">…or a local folder / Git repo URL</label>
          <input
            id="path"
            type="text"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="C:\path\to\project   or   https://github.com/owner/repo (overrides sample)"
          />
        </div>
        <button className="btn btn-primary" onClick={scan} disabled={scanning}>
          <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden>
            <path d="M8 5v14l11-7z" />
          </svg>
          {scanning ? "Scanning…" : "Scan code"}
        </button>
      </div>

      <div className="kpis">
        <div className="kpi">
          <div className="cap">Files scanned</div>
          <div className="big">{files}</div>
        </div>
        <div className="kpi">
          <div className="cap">Findings</div>
          <div className={`big${findings.length ? " danger" : ""}`}>{findings.length}</div>
        </div>
        <div className="kpi">
          <div className="cap">High / Critical</div>
          <div className={`big${highCount ? " danger" : ""}`}>{highCount}</div>
        </div>
        <div className="kpi">
          <div className="cap">Detected stack</div>
          <div className="big sm">{stack}</div>
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h2>Analysis steps</h2>
          <span className="spacer" />
          <span className={`status-chip ${chipCls}`}>
            <span className="dot" />
            {status}
          </span>
        </div>
        <div className="log" ref={logRef}>
          {steps.length === 0 ? (
            <div className="empty">The analyzer streams every step: detect → walk files → taint → findings.</div>
          ) : (
            steps.map((s, i) => {
              const b = STEP_BADGE[s.kind] || STEP_BADGE.file;
              return (
                <div className="ln" key={i}>
                  <span className={`lbadge ${b.cls}`}>{b.label}</span>
                  <span className="pl">{s.text}</span>
                </div>
              );
            })
          )}
        </div>
      </div>

      <div className="card">
        <div className="card-head">
          <h2>Findings</h2>
          <span className="count">{findings.length} vulnerabilities</span>
          <span className="spacer" />
          <button
            className="btn btn-ghost"
            disabled={!result || findings.length === 0}
            onClick={() => result && exportPdf(result)}
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />
            </svg>
            Export PDF
          </button>
        </div>
        <p className="hint">
          Each finding opens to show <b className="k-in">how it got in</b>,{" "}
          <b className="k-imp">business impact</b>, and <b className="k-fix">how to close it</b>.
        </p>
        <div className="findings">
          {findings.length === 0 ? (
            <div className="empty">No scan yet. Press Scan to analyze the source code.</div>
          ) : (
            findings.map((f, i) => <FindingCard key={i} finding={f} defaultOpen={i === 0} />)
          )}
        </div>
      </div>

      <footer>SBVF research prototype · all targets run on 127.0.0.1 · for academic use only</footer>
    </div>
  );
}
