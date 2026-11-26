"use client";
import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { AuthGate } from "@/components/AuthGate";
import { FindingCard } from "@/components/FindingCard";
import { Nav } from "@/components/Nav";
import { ActivityIcon, BackIcon } from "@/components/icons";
import { useAuth } from "@/lib/auth";
import { exportPdf } from "@/lib/pdf";
import type {
  ActivityEntry,
  AiStatus,
  Assessment,
  Finding,
  Prioritization,
  RankItem,
  ScanAi,
  StoredScan,
} from "@/lib/types";

const fmtDate = (s: string) => {
  try {
    return new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  } catch {
    return s;
  }
};

/** Parse a stream of `event:`/`data:` SSE frames, invoking `onEvent` per frame. */
async function readSse(res: Response, onEvent: (event: string, data: any) => void) {
  const reader = res.body?.getReader();
  if (!reader) return;
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let sep;
    while ((sep = buf.indexOf("\n\n")) !== -1) {
      const frame = buf.slice(0, sep);
      buf = buf.slice(sep + 2);
      let event = "message";
      const dataLines: string[] = [];
      for (const line of frame.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
      }
      if (dataLines.length) {
        try {
          onEvent(event, JSON.parse(dataLines.join("\n")));
        } catch {
          /* ignore malformed frame */
        }
      }
    }
  }
}

export default function ScanDetail({ params }: { params: { id: string } }) {
  const id = params.id;
  const { authEnabled, user, loading: authLoading, refresh } = useAuth();
  const [scan, setScan] = useState<StoredScan | null>(null);
  const [activity, setActivity] = useState<ActivityEntry[]>([]);
  const [state, setState] = useState<"loading" | "ok" | "off" | "missing">("loading");

  const [ai, setAi] = useState<AiStatus | null>(null);
  const [assessments, setAssessments] = useState<Record<number, Assessment>>({});
  const [prioritization, setPrioritization] = useState<Prioritization | null>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState("");
  const [aiError, setAiError] = useState("");

  useEffect(() => {
    if (authLoading) return;
    if (authEnabled && !user) return;        // gated; AuthGate shows the sign-in prompt
    (async () => {
      try {
        const r = await fetch(`/api/scans/${id}`);
        if (r.status === 401) return refresh();
        if (r.status === 503) return setState("off");
        if (r.status === 404) return setState("missing");
        const d = (await r.json()) as StoredScan;
        setScan(d);
        setState("ok");
        const a = await fetch(`/api/activity?scan_id=${id}`);
        if (a.ok) setActivity((await a.json()).activity || []);
        const aiRes = await fetch(`/api/ai/status`);
        if (aiRes.ok) setAi(await aiRes.json());
        const stored = await fetch(`/api/scans/${id}/ai`);
        if (stored.ok) {
          const sa = (await stored.json()) as ScanAi;
          const map: Record<number, Assessment> = {};
          for (const as of sa.assessments || []) map[as.finding_idx] = as;
          setAssessments(map);
          setPrioritization(sa.prioritization || null);
        }
      } catch {
        setState("missing");
      }
    })();
  }, [id, authLoading, authEnabled, user]);  // eslint-disable-line react-hooks/exhaustive-deps

  const runAgents = useCallback(async () => {
    setRunning(true);
    setAiError("");
    setProgress("Contacting the AI provider…");
    try {
      const res = await fetch(`/api/scans/${id}/agents`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      await readSse(res, (event, data) => {
        if (event === "start") {
          setProgress(`Running ${(data.agents || []).join(", ")} with ${data.provider} on ${data.findings} finding(s)…`);
        } else if (event === "assessed") {
          setAssessments((prev) => ({
            ...prev,
            [data.idx]: {
              finding_idx: data.idx,
              is_false_positive: data.triage ? data.triage.is_false_positive : null,
              confidence: data.triage ? data.triage.confidence : null,
              rationale: data.triage ? data.triage.rationale : "",
              remediation_summary: data.remediation ? data.remediation.summary : null,
              remediation: data.remediation ? data.remediation.remediation : null,
            },
          }));
          setProgress(`Assessed finding #${data.idx + 1}…`);
        } else if (event === "prioritized") {
          setPrioritization(data as Prioritization);
          setProgress("Prioritizing…");
        } else if (event === "agents_done") {
          setProgress("");
        } else if (event === "agents_error") {
          setAiError(data.message || "AI analysis failed.");
        } else if (event === "agent_error") {
          setAiError(`${data.agent}: ${data.message}`);
        }
      });
    } catch {
      setAiError("AI analysis could not be reached.");
    } finally {
      setRunning(false);
      setProgress("");
    }
  }, [id]);

  const findings: Finding[] = scan?.findings || [];
  const high = findings.filter((f) => f.severity === "high" || f.severity === "critical").length;
  const stack = scan ? Object.values(scan.frameworks || {}).filter(Boolean).join(", ") || "—" : "—";

  const rankByIdx: Record<number, RankItem> = {};
  (prioritization?.ranking || []).forEach((r) => (rankByIdx[r.idx] = r));
  const order = prioritization?.ranking?.length
    ? prioritization.ranking.map((r) => r.idx).filter((i) => i >= 0 && i < findings.length)
    : findings.map((_, i) => i);
  // Any finding missing from the ranking keeps a place at the end.
  findings.forEach((_, i) => {
    if (!order.includes(i)) order.push(i);
  });

  return (
    <div className="shell">
      <Nav />

      <header className="hero hero-scan">
        <Link href="/history" className="back"><BackIcon /> All scans</Link>
        <h1>{state === "ok" ? `Scan #${id}` : "Scan"}</h1>
        {scan && <p className="mono">{scan.root} · {fmtDate(scan.created_at)}</p>}
      </header>

      <AuthGate>
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

          {ai?.enabled && findings.length > 0 && (
            <div className="card ai-run">
              <div className="card-head">
                <h2>AI analysis</h2>
                <span className="spacer" />
                <button className="btn btn-primary" onClick={runAgents} disabled={running}>
                  {running ? "Analyzing…" : prioritization || Object.keys(assessments).length ? "Re-run AI analysis" : "Run AI analysis"}
                </button>
              </div>
              {progress && <p className="ai-progress">{progress}</p>}
              {aiError && <p className="ai-err">{aiError}</p>}
              <p className="ai-note">
                Triage, remediation and risk ranking run on {ai.providers.join(" / ") || "the configured provider"}.
                Running them sends the relevant code snippets to that provider.
              </p>
              {prioritization?.summary && (
                <div className="ai-summary">
                  <div className="eyebrow">Risk posture</div>
                  <p>{prioritization.summary}</p>
                </div>
              )}
            </div>
          )}

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
                order.map((origIdx, pos) => (
                  <FindingCard
                    key={origIdx}
                    finding={findings[origIdx]}
                    defaultOpen={pos === 0}
                    assessment={assessments[origIdx]}
                    rank={rankByIdx[origIdx]}
                  />
                ))
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
      </AuthGate>

      <footer>SBVF research prototype · all targets run on 127.0.0.1 · for academic use only</footer>
    </div>
  );
}
