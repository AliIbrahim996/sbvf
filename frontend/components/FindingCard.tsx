"use client";
import { useState } from "react";
import type { Finding } from "@/lib/types";

/** One finding, as an expandable card with the three breka-style panels. */
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
        <span className="chev">▾</span>
      </div>
      <div className="fpath">
        <span className="src">{f.source}</span> &rarr; <b className="sink">{f.sink}</b>
      </div>
      {open && (
        <div className="fbody">
          <section className="panel">
            <div className="eyebrow">⟐ How it got in</div>
            <p>{f.how_in || f.message}</p>
            {f.code && <pre>{f.code.trim()}</pre>}
          </section>
          <section className="panel">
            <div className="eyebrow imp">◎ Business impact</div>
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
            <div className="eyebrow fix">✓ How to close it</div>
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
