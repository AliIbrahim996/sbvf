import Link from "next/link";
import { Nav } from "@/components/Nav";
import { Reveal } from "@/components/Reveal";

const COVERAGE = [
  { tag: "A01", name: "Broken Access Control", cwe: "IDOR · CWE-639" },
  { tag: "A02", name: "Security Misconfiguration", cwe: "CWE-16" },
  { tag: "A04", name: "Cryptographic Failures", cwe: "CWE-327 / 798" },
  { tag: "A08", name: "Software & Data Integrity Failures", cwe: "CWE-502" },
  { tag: "A10", name: "Mishandling Exceptions", cwe: "CWE-209 / 390" },
  { tag: "—", name: "SQL Injection", cwe: "CWE-89" },
  { tag: "—", name: "Cross-Site Scripting", cwe: "CWE-79" },
  { tag: "—", name: "Command Injection", cwe: "CWE-78" },
  { tag: "—", name: "Path / File Inclusion", cwe: "CWE-98 / 22" },
  { tag: "—", name: "Code Injection", cwe: "CWE-94" },
];

const FEATURES = [
  {
    title: "Static taint analysis",
    body: "Traces untrusted input from source to sink across PHP, Python, and JavaScript / TypeScript — with framework awareness for Django, FastAPI, Flask, Laravel, Yii, Express and NestJS.",
    icon: (
      <path d="M3 12h4l3-8 4 16 3-8h4" />
    ),
  },
  {
    title: "Search-based testing",
    body: "Genetic, cuckoo-search and random strategies drive inputs against live benchmark targets to confirm exploitability — not just pattern matches.",
    icon: (
      <>
        <circle cx="11" cy="11" r="7" />
        <path d="m21 21-4.3-4.3" />
      </>
    ),
  },
  {
    title: "Findings in plain terms",
    body: "Every result explains how it got in, what the business stands to lose, and how to close it — with owner, exposure and prioritised remediation steps.",
    icon: (
      <>
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <path d="M14 2v6h6M9 13h6M9 17h4" />
      </>
    ),
  },
  {
    title: "Exportable PDF reports",
    body: "Turn any scan into a clean, branded vulnerability report — severity summary, per-finding detail and remediation — ready to share with stakeholders.",
    icon: (
      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3" />
    ),
  },
];

const STEPS = [
  { n: "1", title: "Point it at code", body: "Choose a bundled sample, a local folder, or paste a GitHub / GitLab / Bitbucket URL." },
  { n: "2", title: "Watch it analyze", body: "Detection, file walk, taint tracing and findings stream live over Server-Sent Events." },
  { n: "3", title: "Act on the findings", body: "Review prioritised results with remediation, then export a shareable PDF report." },
];

export default function Landing() {
  return (
    <div className="shell">
      <Nav
        right={
          <Link href="/scan" className="btn btn-primary btn-sm nav-cta">
            Open scanner
          </Link>
        }
      />

      <section className="lp-hero">
        <span className="lp-eyebrow anim-up" style={{ animationDelay: "40ms" }}>Static + search-based web security analysis</span>
        <h1 className="anim-up" style={{ animationDelay: "120ms" }}>Find the flaw.<br />See the cost. Close the gap.</h1>
        <p className="anim-up" style={{ animationDelay: "220ms" }}>
          SBVF pairs static taint analysis with search-based testing to surface real web
          vulnerabilities — each one explained in plain business terms, not just a CWE number.
        </p>
        <div className="lp-cta anim-up" style={{ animationDelay: "320ms" }}>
          <Link href="/scan" className="btn btn-primary btn-lg">
            <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden><path d="M8 5v14l11-7z" /></svg>
            Launch the scanner
          </Link>
          <a href="#how" className="btn btn-ghost btn-lg">How it works</a>
        </div>
      </section>

      <Reveal className="lp-section">
        <div className="lp-section-head">
          <h2>What it detects</h2>
          <p>OWASP Top-10 classes and the taint-based vulnerabilities behind them.</p>
        </div>
        <div className="coverage">
          {COVERAGE.map((c) => (
            <div className="cov" key={c.name}>
              <span className={`cov-tag${c.tag === "—" ? " muted" : ""}`}>{c.tag}</span>
              <div>
                <div className="cov-name">{c.name}</div>
                <div className="cov-cwe">{c.cwe}</div>
              </div>
            </div>
          ))}
        </div>
      </Reveal>

      <Reveal className="lp-section">
        <div className="lp-section-head">
          <h2>Built to be understood</h2>
          <p>Not another wall of raw alerts — findings a team can actually act on.</p>
        </div>
        <div className="feature-grid">
          {FEATURES.map((f) => (
            <div className="feature" key={f.title}>
              <span className="feature-ic" aria-hidden>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  {f.icon}
                </svg>
              </span>
              <h3>{f.title}</h3>
              <p>{f.body}</p>
            </div>
          ))}
        </div>
      </Reveal>

      <Reveal className="lp-section" id="how">
        <div className="lp-section-head">
          <h2>How it works</h2>
          <p>From source code to a shareable report in three steps.</p>
        </div>
        <div className="steps">
          {STEPS.map((s) => (
            <div className="step" key={s.n}>
              <span className="step-n">{s.n}</span>
              <h3>{s.title}</h3>
              <p>{s.body}</p>
            </div>
          ))}
        </div>
      </Reveal>

      <Reveal>
        <section className="lp-band">
          <div>
            <h2>Ready to scan?</h2>
            <p>Run it against a bundled sample in seconds — no setup required.</p>
          </div>
          <Link href="/scan" className="btn btn-primary btn-lg">
            <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden><path d="M8 5v14l11-7z" /></svg>
            Launch the scanner
          </Link>
        </section>
      </Reveal>

      <footer>SBVF research prototype · all targets run on 127.0.0.1 · for academic use only</footer>
    </div>
  );
}
