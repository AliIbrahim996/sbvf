"use client";
import { useState } from "react";
import type { Assessment, Finding, RankItem } from "@/lib/types";
import { DetectionPath } from "./DetectionPath";

const IconIn = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3" />
  </svg>
);
const IconImpact = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0ZM12 9v4M12 17h.01" />
  </svg>
);
const IconFix = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    <path d="M20 6 9 17l-5-5" />
  </svg>
);
const Chevron = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    <path d="m6 9 6 6 6-6" />
  </svg>
);
const IconAi = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    <path d="M12 3v3M5.6 5.6l2.1 2.1M3 12h3M18 12h3M16.3 7.7l2.1-2.1M12 18v3M7.7 16.3l-2.1 2.1M16.3 16.3l2.1 2.1" />
    <circle cx="12" cy="12" r="4" />
  </svg>
);

/** One finding, as an expandable card with the three panels, plus optional AI
 *  assessment (false-positive verdict, risk rank, AI remediation). */
export function FindingCard({
  finding,
  defaultOpen,
  assessment,
  rank,
}: {
  finding: Finding;
  defaultOpen?: boolean;
  assessment?: Assessment;
  rank?: RankItem;
}) {
  const [open, setOpen] = useState(!!defaultOpen);
  const f = finding;
  const fp = assessment && assessment.is_false_positive === true;
  const conf = assessment && assessment.confidence != null ? Math.round(assessment.confidence * 100) : null;
  return (
    <article className={`finding sev-${f.severity} ${open ? "open" : ""} ${fp ? "is-fp" : ""}`}>
      <div className="fhead" onClick={() => setOpen((o) => !o)}>
        <span className={`sev sev-${f.severity}`}>{(f.severity || "").toUpperCase()}</span>
        <span className="ftitle">
          {f.title || f.vuln}
          <span className="cwe">{f.cwe}</span>
        </span>
        <code className="floc">{f.location}</code>
        {f.dynamic?.confirmed && (
          <span className="dynbadge" title={f.dynamic.checks
            .map((c) => `${c.vuln} reproduced on ${c.method} ${c.path}` +
              (c.evals != null ? ` in ${c.evals} request(s)` : ""))
            .join("\n")}>
            Confirmed live
          </span>
        )}
        {rank && <span className="airisk" title={rank.reason}>Risk {Math.round(rank.risk_score)}</span>}
        {assessment && assessment.is_false_positive != null && (
          <span className={`aibadge ${fp ? "fp" : "tp"}`} title={assessment.rationale}>
            {fp ? "Likely false positive" : "Confirmed"}
            {conf != null && <b>{conf}%</b>}
          </span>
        )}
        {f.action && <span className="faction">{f.action}</span>}
        <span className="chev">
          <Chevron />
        </span>
      </div>
      <div className="fpath">
        <span className="src">{f.source}</span> &rarr; <b className="sink">{f.sink}</b>
      </div>
      {open && (
        <div className="fbody">
          <DetectionPath finding={f} />
          <section className="panel">
            <div className="eyebrow">
              <IconIn /> How it got in
            </div>
            <p>{f.how_in || f.message}</p>
            {f.code && <pre>{f.code.trim()}</pre>}
          </section>
          <section className="panel">
            <div className="eyebrow imp">
              <IconImpact /> Business impact
            </div>
            {f.exposure && f.exposure.length > 0 && (
              <div className="expo">
                {f.exposure.map((e) => (
                  <span key={e}>{e}</span>
                ))}
              </div>
            )}
            <p>{f.impact}</p>
          </section>
          <section className="panel">
            <div className="eyebrow fix">
              <IconFix /> How to close it
            </div>
            {f.owner && (
              <div className="owner">
                Owner: <b>{f.owner}</b>
              </div>
            )}
            <ol>
              {(f.fix || []).map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ol>
          </section>
          {assessment && (assessment.remediation || assessment.rationale) && (
            <section className="panel ai">
              <div className="eyebrow aipanel">
                <IconAi /> AI analysis
                {assessment.provider && <span className="aimeta">{assessment.provider}{assessment.model ? ` · ${assessment.model}` : ""}</span>}
              </div>
              {assessment.rationale && (
                <p className="airat">
                  <b>Triage:</b> {assessment.rationale}
                </p>
              )}
              {assessment.remediation_summary && <p className="aisum">{assessment.remediation_summary}</p>}
              {assessment.remediation && <pre className="airem">{assessment.remediation.trim()}</pre>}
            </section>
          )}
        </div>
      )}
    </article>
  );
}
