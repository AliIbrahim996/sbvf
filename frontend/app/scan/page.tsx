"use client";
import { useEffect, useRef, useState } from "react";
import { AuthGate } from "@/components/AuthGate";
import { FindingCard } from "@/components/FindingCard";
import { Nav } from "@/components/Nav";
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
  confirm: { cls: "b-confirm", label: "CONFIRM" },
};

type Phase = "idle" | "live" | "done" | "err";

export default function ScanPage() {
  const [sample, setSample] = useState("php_native");
  const [path, setPath] = useState("");
  const [confirmUrl, setConfirmUrl] = useState("");
  const [steps, setSteps] = useState<{ kind: string; text: string }[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [status, setStatus] = useState("Idle — choose a project and press Scan");
  const [phase, setPhase] = useState<Phase>("idle");
  const [scanning, setScanning] = useState(false);
  const [stack, setStack] = useState("—");
  const [files, setFiles] = useState(0);
  const [branchPrompt, setBranchPrompt] = useState<{ token: string; branches: string[]; current: string } | null>(null);
  const [awaitingBranch, setAwaitingBranch] = useState(false);
  const [chosenBranch, setChosenBranch] = useState("");
  const esRef = useRef<EventSource | null>(null);
  const logRef = useRef<HTMLDivElement | null>(null);

  const highCount = findings.filter((f) => f.severity === "high" || f.severity === "critical").length;

  useEffect(() => () => esRef.current?.close(), []);

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

  async function scan() {
    esRef.current?.close();
    setSteps([]);
    setFindings([]);
    setResult(null);
    setStack("…");
    setFiles(0);
    setBranchPrompt(null);
    setAwaitingBranch(false);
    setChosenBranch("");
    const live: Finding[] = [];
    const t = path.trim();
    const remote = t.includes("://") || /^git@/i.test(t) || /^(www\.)?(github|gitlab|bitbucket)\./i.test(t);
    setStatus(remote ? "Cloning repository…" : "Scanning…");
    setPhase("live");
    setScanning(true);

    // Start the scan with a same-origin POST, then stream it over SSE. Routing the
    // start through POST (JSON body) is what stops a cross-site GET (an <img> tag,
    // say) from driving the local API — see ui/server.py `_guard`.
    // branch_select is offered for any repo URL or local git folder; the backend
    // only prompts when the target is really a git repo with more than one branch.
    const payload: Record<string, unknown> = t ? { path: t, branch_select: true } : { sample };
    if (confirmUrl.trim()) payload.confirm = confirmUrl.trim();

    let eventsUrl: string;
    try {
      const res = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d?.message || `could not start scan (${res.status})`);
      }
      const d = await res.json();
      eventsUrl = d.events_url || `/api/scans/${d.scan_id}/events`;
    } catch (err) {
      pushStep({ kind: "error", text: err instanceof Error ? err.message : "could not start the scan" });
      setStatus("Error");
      setPhase("err");
      setScanning(false);
      return;
    }

    const es = new EventSource(eventsUrl);
    esRef.current = es;

    es.addEventListener("branch_prompt", (e) => {
      const d = parse<{ token: string; branches: string[]; current: string }>(e);
      if (!d) return;
      setBranchPrompt(d);
      setChosenBranch("");
      setAwaitingBranch(true);
      setStatus(`Choose a branch to scan (${d.branches.length} available)…`);
      pushStep({ kind: "clone", text: `Repository has ${d.branches.length} branches — choose one to continue` });
    });

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

  // The moment a branch is chosen, resume the paused scan and lock the dropdown.
  async function pickBranch(branch: string) {
    if (!branchPrompt || !branch) return;
    setChosenBranch(branch);
    setAwaitingBranch(false);               // lock: no further editing
    setStatus("Scanning…");
    pushStep({ kind: "clone", text: `Branch selected: ${branch}` });
    try {
      const res = await fetch("/api/scan/branch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: branchPrompt.token, branch }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        pushStep({ kind: "error", text: `could not select branch: ${d?.message || res.status}` });
      }
    } catch {
      pushStep({ kind: "error", text: "could not send branch selection to the server" });
    }
  }

  const chipCls = phase === "live" ? "live" : phase === "done" ? "done" : phase === "err" ? "err" : "";

  return (
    <div className="shell">
      <Nav />

      <header className="hero hero-scan">
        <h1>Scan a project</h1>
        <p>Pick a bundled sample or point SBVF at a local folder or a Git repository URL.</p>
      </header>

      <AuthGate>
      <div className="control">
        <div className="field">
          <label htmlFor="sample">Sample project</label>
          <select id="sample" value={sample} disabled={scanning} onChange={(e) => setSample(e.target.value)}>
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
            disabled={scanning}
            onChange={(e) => setPath(e.target.value)}
            placeholder="/path/to/project  ·  C:\path\to\project  ·  https://github.com/owner/repo (overrides sample)"
          />
        </div>
        {branchPrompt && (
          <div className="field" style={{ minWidth: 200 }}>
            <label htmlFor="branch">Branch{awaitingBranch ? "" : " (locked)"}</label>
            <select
              id="branch"
              value={chosenBranch}
              disabled={!awaitingBranch}
              onChange={(e) => pickBranch(e.target.value)}
            >
              <option value="" disabled>
                — choose branch —
              </option>
              {branchPrompt.branches.map((b) => (
                <option key={b} value={b}>
                  {b}
                  {b === branchPrompt.current ? " (default)" : ""}
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="field" style={{ flex: 1, minWidth: 240 }}>
          <label htmlFor="confirm">Confirm live (optional) — URL of the running app</label>
          <input
            id="confirm"
            type="text"
            value={confirmUrl}
            disabled={scanning}
            onChange={(e) => setConfirmUrl(e.target.value)}
            placeholder="http://127.0.0.1:8000 — localhost only; SBVF connects and replays requests"
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
      </AuthGate>

      <footer>SBVF research prototype · all targets run on 127.0.0.1 · for academic use only</footer>
    </div>
  );
}
