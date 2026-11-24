"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { FindingCard } from "@/components/FindingCard";
import { Nav } from "@/components/Nav";
import { ActivityIcon, BackIcon } from "@/components/icons";
import { exportPdf } from "@/lib/pdf";
import type { ActivityEntry, Finding, StoredScan } from "@/lib/types";

const fmtDate = (s: string) => {
  try {
    return new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  } catch {
    return s;
  }
};

export default function ScanDetail({ params }: { params: { id: string } }) {
  const id = params.id;
  const [scan, setScan] = useState<StoredScan | null>(null);
  const [activity, setActivity] = useState<ActivityEntry[]>([]);
  const [state, setState] = useState<"loading" | "ok" | "off" | "missing">("loading");

  useEffect(() => {
    (async () => {
      try {
        const r = await fetch(`/api/scans/${id}`);
        if (r.status === 503) return setState("off");
        if (r.status === 404) return setState("missing");
        const d = (await r.json()) as StoredScan;
        setScan(d);
        setState("ok");
        const a = await fetch(`/api/activity?scan_id=${id}`);
        if (a.ok) setActivity((await a.json()).activity || []);
      } catch {
        setState("missing");
      }
    })();
  }, [id]);

  const findings: Finding[] = scan?.findings || [];
  const high = findings.filter((f) => f.severity === "high" || f.severity === "critical").length;
  const stack = scan ? Object.values(scan.frameworks || {}).filter(Boolean).join(", ") || "—" : "—";

  return (
    <div className="shell">
      <Nav />

      <header className="hero hero-scan">
        <Link href="/history" className="back"><BackIcon /> All scans</Link>
        <h1>{state === "ok" ? `Scan #${id}` : "Scan"}</h1>
        {scan && <p className="mono">{scan.root} · {fmtDate(scan.created_at)}</p>}
      </header>

      {state === "off" ? (
        <div className="empty">History requires the database service.</div>
      ) : state === "missing" ? (
        <div className="empty">Scan not found.</div>
      ) : state === "loading" ? (
        <div className="empty">Loading…</div>
      ) : scan ? (
        <>
          <div className="kpis">
            <div className="kpi"><div className="cap">Files scanned</div><div className="big">{scan.files_scanned}</div></div>
            <div className="kpi"><div className="cap">Findings</div><div className={`big${findings.length ? " danger" : ""}`}>{findings.length}</div></div>
            <div className="kpi"><div className="cap">High / Critical</div><div className={`big${high ? " danger" : ""}`}>{high}</div></div>
            <div className="kpi"><div className="cap">Stack</div><div className="big sm">{stack}</div></div>
          </div>

          <div className="card">
            <div className="card-head">
              <h2>Findings</h2>
              <span className="count">{findings.length} vulnerabilities</span>
              <span className="spacer" />
              <button className="btn btn-ghost" disabled={findings.length === 0} onClick={() => exportPdf(scan)}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />
                </svg>
                Export PDF
              </button>
            </div>
            <div className="findings">
              {findings.length === 0 ? (
                <div className="empty">No vulnerabilities were found in this scan.</div>
              ) : (
                findings.map((f, i) => <FindingCard key={i} finding={f} defaultOpen={i === 0} />)
              )}
            </div>
          </div>

          {activity.length > 0 && (
            <div className="card">
              <div className="card-head"><h2>Activity</h2></div>
              <ul className="timeline">
                {activity.map((a) => (
                  <li key={a.id}>
                    <span className="tl-ic"><ActivityIcon /></span>
                    <span className="tl-act">{a.action}</span>
                    <span className="tl-meta">{a.actor} · {fmtDate(a.created_at)}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      ) : null}

      <footer>SBVF research prototype · all targets run on 127.0.0.1 · for academic use only</footer>
    </div>
  );
}
