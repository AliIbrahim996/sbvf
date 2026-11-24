"use client";
import { useState } from "react";
import type { Finding } from "@/lib/types";

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

/** One finding, as an expandable card with the three panels. */
export function FindingCard({ finding, defaultOpen }: { finding: Finding; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(!!defaultOpen);
  const f = finding;
  return (
    <article className={`finding sev-${f.severity} ${open ? "open" : ""}`}>
      <div className="fhead" onClick={() => setOpen((o) => !o)}>
        <span className={`sev sev-${f.severity}`}>{(f.severity || "").toUpperCase()}</span>
        <span className="ftitle">
          {f.title || f.vuln}
          <span className="cwe">{f.cwe}</span>
        </span>
        <code className="floc">{f.location}</code>
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
        </div>
      )}
    </article>
  );
}
