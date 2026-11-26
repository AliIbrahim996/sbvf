"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { AskPanel } from "@/components/AskPanel";
import { AuthGate } from "@/components/AuthGate";
import { Nav } from "@/components/Nav";
import { ActivityIcon } from "@/components/icons";
import { useAuth } from "@/lib/auth";
import type { ActivityEntry, ScanSummary } from "@/lib/types";

const fmtDate = (s: string) => {
  try {
    return new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  } catch {
    return s;
  }
};

const highCrit = (s: ScanSummary) => {
  const b = s.counts?.by_severity || {};
  return (b.critical || 0) + (b.high || 0);
};

export default function HistoryPage() {
  const { authEnabled, user, loading: authLoading, refresh } = useAuth();
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [activity, setActivity] = useState<ActivityEntry[]>([]);
  const [off, setOff] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    try {
      const r = await fetch("/api/scans");
      if (r.status === 401) {       // session expired → let AuthGate take over
        refresh();
        return;
      }
      if (r.status === 503) {
        setOff(true);
        setScans([]);
        return;
      }
      const d = await r.json();
      setScans(d.scans || []);
      const a = await fetch("/api/activity?limit=12");
      if (a.ok) setActivity((await a.json()).activity || []);
    } catch {
      setError("Could not reach the backend.");
      setScans([]);
    }
  }

  useEffect(() => {
    // Wait until auth state is known; only fetch when not gated (auth off or signed in).
    if (authLoading) return;
    if (authEnabled && !user) return;
    load();
  }, [authLoading, authEnabled, user]);  // eslint-disable-line react-hooks/exhaustive-deps

  async function remove(id: number) {
    if (!confirm(`Delete scan #${id}? This cannot be undone.`)) return;
    try {
      await fetch(`/api/scans/${id}`, { method: "DELETE" });
      load();
    } catch {
      /* ignore; refresh will reflect reality */
    }
  }

  return (
    <div className="shell">
      <Nav />

      <header className="hero hero-scan">
        <h1>Scan history</h1>
        <p>Every scan is stored with its findings and an activity log.</p>
      </header>

      <AuthGate>
      {off ? (
        <div className="empty">
          History requires the database service. Run with Docker Compose (which starts
          PostgreSQL) or set <code>DATABASE_URL</code> on the backend.
        </div>
      ) : error ? (
        <div className="empty">{error}</div>
      ) : scans === null ? (
        <div className="empty">Loading…</div>
      ) : scans.length === 0 ? (
        <div className="empty">No scans yet. Run one from the scanner and it will appear here.</div>
      ) : (
        <>
          <div className="card">
            <div className="card-head">
              <h2>Scans</h2>
              <span className="count">{scans.length}</span>
            </div>
            <div className="table-wrap">
              <table className="htable">
                <thead>
                  <tr>
                    <th>When</th><th>Target</th><th>Type</th><th>Stack</th>
                    <th className="num">Files</th><th className="num">Findings</th>
                    <th className="num">High/Crit</th><th></th>
                  </tr>
                </thead>
                <tbody>
                  {scans.map((s) => (
                    <tr key={s.id}>
                      <td><Link className="rowlink" href={`/history/${s.id}`}>{fmtDate(s.created_at)}</Link></td>
                      <td className="mono ellip" title={s.root}>{s.root || "—"}</td>
                      <td><span className="chip">{s.scan_type}</span></td>
                      <td>{Object.values(s.frameworks || {}).filter(Boolean).join(", ") || "—"}</td>
                      <td className="num">{s.files_scanned}</td>
                      <td className="num">{s.findings_count}</td>
                      <td className="num">{highCrit(s) > 0 ? <b className="danger">{highCrit(s)}</b> : 0}</td>
                      <td className="num">
                        <button className="icon-del" onClick={() => remove(s.id)} aria-label={`Delete scan ${s.id}`} title="Delete">✕</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <AskPanel />

          {activity.length > 0 && (
            <div className="card">
              <div className="card-head">
                <h2>Recent activity</h2>
              </div>
              <ul className="timeline">
                {activity.map((a) => (
                  <li key={a.id}>
                    <span className="tl-ic"><ActivityIcon /></span>
                    <span className="tl-act">{a.action}</span>
                    <span className="tl-meta">
                      {a.scan_id ? `scan #${a.scan_id} · ` : ""}{a.actor} · {fmtDate(a.created_at)}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
      </AuthGate>

      <footer>SBVF research prototype · all targets run on 127.0.0.1 · for academic use only</footer>
    </div>
  );
}
