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

export default function Page() {
  const [sample, setSample] = useState("php_native");
  const [path, setPath] = useState("");
  const [steps, setSteps] = useState<{ kind: string; text: string }[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [status, setStatus] = useState("Idle — choose a project and press Scan");
  const [scanning, setScanning] = useState(false);
  const [stack, setStack] = useState("—");
  const [files, setFiles] = useState(0);
  const esRef = useRef<EventSource | null>(null);
  const logRef = useRef<HTMLDivElement | null>(null);

  const highCount = findings.filter((f) => f.severity === "high" || f.severity === "critical").length;

  // Close the stream if the component unmounts mid-scan.
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
      } else {
        pushStep({ kind: "error", text: "malformed scan_done from backend" });
        setStatus("Error");
      }
      setScanning(false);
      es.close();
    });
    es.addEventListener("scan_error", (e) => {
      const d = parse<{ message: string }>(e);
      pushStep({ kind: "error", text: d?.message || "scan error" });
      setStatus("Error");
      setScanning(false);
      es.close();
    });
    es.onerror = () => {
      setStatus((s) => (s === "Completed" ? s : "Stream ended"));
      setScanning(false);
      es.close();
    };
  }

  return (
    <div className="shell">
      <header className="top">
        <div className="logo">🛡️</div>
        <div className="brand">
          <h1>SBVF · Search-Based Vulnerability Framework</h1>
          <p>Finds how it got in, what the business stands to lose, and how to close it.</p>
        </div>
        <span className="badge-next">Next.js</span>
      </header>

      <div className="toolbar">
        <div className="field">
          <label>Sample project</label>
          <select value={sample} onChange={(e) => setSample(e.target.value)}>
            {SAMPLES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </select>
        </div>
        <div className="field" style={{ flex: 1, minWidth: 240 }}>
          <label>…or a local folder / GitHub · GitLab · Bitbucket repo URL</label>
          <input
            type="text"
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="C:\path\to\project   or   https://github.com/owner/repo (overrides sample)"
            style={{ minWidth: "100%" }}
          />
        </div>
        <button className="run-btn" onClick={scan} disabled={scanning}>
          ▶&nbsp;&nbsp;Scan code
        </button>
      </div>

      <div className="kpis">
        <div className="kpi">
          <div className="cap">Files scanned</div>
          <div className="big">{files}</div>
        </div>
        <div className="kpi">
          <div className="cap">Findings</div>
          <div className="big" style={{ color: "var(--bad)" }}>{findings.length}</div>
        </div>
        <div className="kpi">
          <div className="cap">High / Critical</div>
          <div className="big" style={{ color: "var(--bad)" }}>{highCount}</div>
        </div>
        <div className="kpi">
          <div className="cap">Detected stack</div>
          <div className="big" style={{ fontSize: 17, paddingTop: 12 }}>{stack}</div>
        </div>
      </div>

      <div className="card">
        <h2>
          Analysis steps <span className="tag">{status}</span>
        </h2>
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
        <h2>
          Findings <span className="tag">{findings.length} vulnerabilities</span>
          <button
            className="ghost-btn"
            style={{ marginLeft: 12 }}
            disabled={!result || findings.length === 0}
            onClick={() => result && exportPdf(result)}
          >
            ⬇ Export PDF report
          </button>
        </h2>
        <p style={{ margin: "-6px 0 14px", color: "var(--muted)", fontSize: 12.5 }}>
          Each finding opens to show <b style={{ color: "var(--accent)" }}>how it got in</b>,{" "}
          <b style={{ color: "var(--warn)" }}>business impact</b>, and{" "}
          <b style={{ color: "var(--ok)" }}>how to close it</b>.
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
