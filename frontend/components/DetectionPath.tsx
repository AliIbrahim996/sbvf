"use client";
import { useEffect, useMemo, useState } from "react";
import type { Finding } from "@/lib/types";
import { buildDetectionPath, type StepKind } from "@/lib/detectionPath";

const STEP_MS = 1300;

function StepIcon({ kind }: { kind: StepKind }) {
  const common = {
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
  };
  switch (kind) {
    case "scan":
      return (
        <svg {...common}>
          <circle cx="11" cy="11" r="7" />
          <path d="m21 21-4.3-4.3" />
        </svg>
      );
    case "source":
      return (
        <svg {...common}>
          <path d="M12 2v14M6 10l6 6 6-6" />
          <path d="M4 20h16" />
        </svg>
      );
    case "file":
      return (
        <svg {...common}>
          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
          <path d="M14 2v6h6M8 13h8M8 17h5" />
        </svg>
      );
    case "handler":
      return (
        <svg {...common}>
          <path d="M4 12h16M14 6l6 6-6 6" />
        </svg>
      );
    case "rule":
      return (
        <svg {...common}>
          <path d="M9 11l3 3L22 4" />
          <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" />
        </svg>
      );
    case "sink":
      return (
        <svg {...common}>
          <path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
          <path d="M12 9v4M12 17h.01" />
        </svg>
      );
    case "confirmed":
      return (
        <svg {...common}>
          <path d="M12 2 4 6v6c0 5 3.4 8.5 8 10 4.6-1.5 8-5 8-10V6z" />
          <path d="m9 12 2 2 4-4" />
        </svg>
      );
    default: // vuln
      return (
        <svg {...common}>
          <path d="M12 2 4 6v6c0 5 3.4 8.5 8 10 4.6-1.5 8-5 8-10V6z" />
          <path d="M12 8v4M12 16h.01" />
        </svg>
      );
  }
}

const IconPlay = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden><path d="M8 5v14l11-7z" /></svg>
);
const IconPause = () => (
  <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden><path d="M6 5h4v14H6zM14 5h4v14h-4z" /></svg>
);
const IconArrow = ({ dir }: { dir: "l" | "r" }) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    <path d={dir === "l" ? "m14 6-6 6 6 6" : "m10 6 6 6-6 6"} />
  </svg>
);

/** "How the scanner reached it": an animated, step-by-step graph of the
 *  detection path derived from the finding's recorded source -> sink chain. */
export function DetectionPath({ finding }: { finding: Finding }) {
  const steps = useMemo(() => buildDetectionPath(finding), [finding]);
  const [i, setI] = useState(0);
  const [playing, setPlaying] = useState(false);
  const last = steps.length - 1;

  useEffect(() => {
    if (!playing) return;
    if (i >= last) {
      setPlaying(false);
      return;
    }
    const t = setTimeout(() => setI((x) => Math.min(x + 1, last)), STEP_MS);
    return () => clearTimeout(t);
  }, [playing, i, last]);

  const go = (n: number) => {
    setPlaying(false);
    setI(Math.max(0, Math.min(n, last)));
  };
  const toggle = () => {
    if (i >= last) setI(0); // replay from the start
    setPlaying((p) => !p);
  };

  return (
    <section className="panel dpath">
      <div className="eyebrow dp">
        <StepIcon kind="scan" /> Detection path
        <span className="dpcount">
          Step {i + 1} of {steps.length}
        </span>
      </div>

      <ol className="dpgraph">
        {steps.map((s, idx) => {
          const state = idx < i ? "done" : idx === i ? "active" : "next";
          return (
            <li key={idx} className={`dpnode ${state} k-${s.kind}`}>
              <button
                type="button"
                className="dpdot"
                onClick={() => go(idx)}
                aria-current={idx === i}
                title={s.title}
              >
                <StepIcon kind={s.kind} />
              </button>
              <div className="dptext">
                <div className="dptitle">{s.title}</div>
                {s.meta && <code className="dpmeta">{s.meta}</code>}
              </div>
            </li>
          );
        })}
      </ol>

      <p className="dpnarr" aria-live="polite">
        {steps[i].detail}
      </p>

      <div className="dpctl">
        <button type="button" className="btn btn-ghost" onClick={() => go(i - 1)} disabled={i === 0} aria-label="Previous step">
          <IconArrow dir="l" />
        </button>
        <button type="button" className="btn btn-primary dpplay" onClick={toggle}>
          {playing ? <IconPause /> : <IconPlay />}
          {playing ? "Pause" : i >= last ? "Replay" : "Play"}
        </button>
        <button type="button" className="btn btn-ghost" onClick={() => go(i + 1)} disabled={i === last} aria-label="Next step">
          <IconArrow dir="r" />
        </button>
      </div>
    </section>
  );
}
