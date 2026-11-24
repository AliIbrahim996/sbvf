import type { ScanResult, Finding } from "./types";

const esc = (s: string) =>
  (s || "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string),
  );

const SEV_ORDER = ["critical", "high", "medium", "low"] as const;
const sevRank = (s: string) => {
  const i = SEV_ORDER.indexOf((s || "").toLowerCase() as (typeof SEV_ORDER)[number]);
  return i === -1 ? SEV_ORDER.length : i;
};

/** Build a clean, branded printable report and print it via a hidden iframe
 *  (Save as PDF). No pop-up; falls back to downloading a self-contained .html. */
export function exportPdf(scan: ScanResult) {
  const findings = [...(scan.findings || [])].sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
  const stack = Object.values(scan.frameworks || {}).filter(Boolean).join(", ") || "n/a";
  const c = (scan.counts && scan.counts.by_severity) || {};
  const crit = (c.critical || 0) + (c.high || 0);
  const med = c.medium || 0;
  const low = c.low || 0;
  const total = findings.length;
  const when = new Date().toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

  // Stacked severity bar segments (only non-zero).
  const segs = [
    { n: crit, cls: "s-high", label: "High / Critical" },
    { n: med, cls: "s-medium", label: "Medium" },
    { n: low, cls: "s-low", label: "Low" },
  ].filter((s) => s.n > 0);
  const bar = total
    ? `<div class="bar">${segs
        .map((s) => `<span class="${s.cls}" style="width:${(s.n / total) * 100}%" title="${s.label}"></span>`)
        .join("")}</div>`
    : "";

  const sevClass = (s: string) => {
    const l = (s || "").toLowerCase();
    return l === "critical" || l === "high" ? "s-high" : l === "medium" ? "s-medium" : "s-low";
  };

  const section = (f: Finding, i: number) => `
    <section class="rf ${sevClass(f.severity)}">
      <div class="rf-head">
        <span class="rsev ${sevClass(f.severity)}">${esc((f.severity || "").toUpperCase())}</span>
        <h3>${i + 1}. ${esc(f.title || f.vuln)}</h3>
        <span class="rcwe">${esc(f.cwe || "")}</span>
        ${f.action ? `<span class="rpill">${esc(f.action)}</span>` : ""}
      </div>
      <div class="rmeta">
        <span><b>Location</b> ${esc(f.location || "")}</span>
        <span><b>Path</b> ${esc(f.source || "")} &rarr; ${esc(f.sink || "")}</span>
      </div>
      <div class="rb"><div class="rh in">How it got in</div><p>${esc(f.how_in || f.message || "")}</p>
        ${f.code ? `<pre>${esc(f.code.trim())}</pre>` : ""}</div>
      <div class="rb"><div class="rh imp">Business impact</div>
        ${f.exposure && f.exposure.length ? `<div class="rexp">${f.exposure.map((e) => `<span>${esc(e)}</span>`).join("")}</div>` : ""}
        <p>${esc(f.impact || "")}</p></div>
      <div class="rb"><div class="rh fix">How to close it</div>
        <p class="rown">Owner: <b>${esc(f.owner || "Engineering")}</b></p>
        <ol>${(f.fix || []).map((s) => `<li>${esc(s)}</li>`).join("")}</ol></div>
    </section>`;

  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
  <title>SBVF — Vulnerability Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root{
      --ink:#17150f;--soft:#444038;--muted:#726d63;--faint:#9a938a;
      --line:#e6e1d6;--line2:#d8d2c4;--surface:#fff;--tint:#faf8f4;
      --blue:#2563eb;--blue-soft:#e6eefc;--blue-ink:#1d4ed8;
      --crit:#d6333f;--crit-soft:#fbe9ea;--med:#c2740a;--med-soft:#fbf0dd;
      --low:#6b7280;--low-soft:#eef0f2;--ok:#0f9d6b;--ok-soft:#e4f6ee;
    }
    *{box-sizing:border-box}
    body{font-family:"Inter",-apple-system,Segoe UI,system-ui,Arial,sans-serif;color:var(--ink);
      margin:0;font-size:12.5px;line-height:1.55;-webkit-print-color-adjust:exact;print-color-adjust:exact;}
    .page{max-width:820px;margin:0 auto;padding:40px 44px;}
    code,pre,.mono{font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;}

    /* ---- header ---- */
    .head{display:flex;align-items:center;gap:14px;padding-bottom:18px;border-bottom:2px solid var(--ink);}
    .logo{width:40px;height:40px;border-radius:10px;background:var(--ink);color:#fff;display:grid;place-items:center;flex:none;}
    .logo svg{width:23px;height:23px;}
    .head .t b{font-size:20px;font-weight:800;letter-spacing:-.02em;display:block;line-height:1.1;}
    .head .t span{font-size:12px;color:var(--muted);}
    .head .rep{margin-left:auto;text-align:right;}
    .head .rep .k{font-size:15px;font-weight:800;letter-spacing:-.01em;}
    .head .rep .d{font-size:11px;color:var(--muted);}

    /* ---- target meta ---- */
    .target{display:flex;flex-wrap:wrap;gap:10px 28px;margin:16px 0 26px;}
    .target div{font-size:11.5px;}
    .target .l{color:var(--muted);text-transform:uppercase;letter-spacing:.06em;font-size:9.5px;font-weight:700;margin-bottom:2px;}
    .target .v{font-weight:600;}

    h2.sec{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);
      margin:0 0 14px;font-weight:700;}

    /* ---- summary ---- */
    .summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px;}
    .kc{border:1px solid var(--line);border-radius:10px;padding:12px 14px;background:var(--tint);}
    .kc .n{font-size:26px;font-weight:800;letter-spacing:-.02em;}
    .kc .l{font-size:9.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:700;margin-top:2px;}
    .kc.crit .n{color:var(--crit);} .kc.med .n{color:var(--med);} .kc.low .n{color:var(--low);}
    .bar{display:flex;height:9px;border-radius:999px;overflow:hidden;background:var(--low-soft);margin:4px 0 30px;}
    .bar span{display:block;height:100%;}
    .bar .s-high{background:var(--crit);} .bar .s-medium{background:var(--med);} .bar .s-low{background:var(--low);}

    /* ---- findings ---- */
    .rf{border:1px solid var(--line);border-left:4px solid var(--low);border-radius:10px;
      padding:16px 18px;margin:0 0 14px;page-break-inside:avoid;background:var(--surface);}
    .rf.s-high{border-left-color:var(--crit);} .rf.s-medium{border-left-color:var(--med);}
    .rf-head{display:flex;align-items:center;gap:10px;margin-bottom:10px;flex-wrap:wrap;}
    .rf-head h3{font-size:15px;margin:0;font-weight:700;letter-spacing:-.01em;}
    .rcwe{color:var(--faint);font-size:11px;font-weight:600;}
    .rsev{display:inline-block;color:#fff;font-size:9.5px;font-weight:800;letter-spacing:.04em;
      border-radius:5px;padding:3px 8px;}
    .rsev.s-high{background:var(--crit);} .rsev.s-medium{background:var(--med);} .rsev.s-low{background:var(--low);}
    .rpill{margin-left:auto;font-size:10px;font-weight:600;color:var(--muted);
      border:1px solid var(--line2);border-radius:999px;padding:2px 10px;}
    .rmeta{display:flex;flex-wrap:wrap;gap:4px 22px;font-size:11px;color:var(--soft);margin:0 0 12px;
      padding:8px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line);}
    .rmeta b{color:var(--muted);font-weight:700;text-transform:uppercase;font-size:9px;letter-spacing:.05em;margin-right:5px;}
    .rb{margin:12px 0;}
    .rh{font-size:10px;text-transform:uppercase;font-weight:800;letter-spacing:.06em;margin:0 0 5px;}
    .rh.in{color:var(--blue-ink);} .rh.imp{color:var(--med);} .rh.fix{color:var(--ok);}
    .rb p{margin:0;color:var(--soft);line-height:1.6;}
    .rexp{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 8px;}
    .rexp span{font-size:10px;font-weight:600;color:var(--med);background:var(--med-soft);
      border:1px solid var(--med);border-radius:999px;padding:2px 9px;}
    .rown{font-size:11px;color:var(--muted);margin:0 0 6px;} .rown b{color:var(--ink);}
    pre{background:var(--tint);border:1px solid var(--line);border-radius:7px;padding:10px 12px;overflow:auto;
      font-size:11px;line-height:1.5;margin:8px 0 0;color:var(--ink);}
    ol{margin:4px 0 0;padding-left:20px;color:var(--soft);line-height:1.7;} li{margin:2px 0;}
    .none{border:1px dashed var(--line2);border-radius:10px;padding:34px;text-align:center;color:var(--muted);background:var(--tint);}

    footer{margin-top:24px;padding-top:12px;border-top:1px solid var(--line);
      color:var(--faint);font-size:10px;text-align:center;}

    @page{margin:14mm;}
    @media print{.page{padding:0;max-width:none;}}
  </style></head><body>
  <div class="page">
    <header class="head">
      <span class="logo"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2 4 5v6c0 5 3.4 8.3 8 11 4.6-2.7 8-6 8-11V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></svg></span>
      <span class="t"><b>SBVF</b><span>Search-Based Vulnerability Framework</span></span>
      <span class="rep"><div class="k">Vulnerability Report</div><div class="d">Generated ${esc(when)}</div></span>
    </header>

    <div class="target">
      <div><div class="l">Target</div><div class="v">${esc(scan.root || "n/a")}</div></div>
      <div><div class="l">Stack</div><div class="v">${esc(stack)}</div></div>
      <div><div class="l">Files scanned</div><div class="v">${scan.files_scanned || 0}</div></div>
      <div><div class="l">Findings</div><div class="v">${total}</div></div>
    </div>

    <h2 class="sec">Executive summary</h2>
    <div class="summary">
      <div class="kc"><div class="n">${total}</div><div class="l">Total findings</div></div>
      <div class="kc crit"><div class="n">${crit}</div><div class="l">High / Critical</div></div>
      <div class="kc med"><div class="n">${med}</div><div class="l">Medium</div></div>
      <div class="kc low"><div class="n">${low}</div><div class="l">Low</div></div>
    </div>
    ${bar}

    <h2 class="sec">Findings</h2>
    ${findings.map(section).join("") || '<div class="none">No vulnerabilities found in this scan.</div>'}

    <footer>SBVF static analysis · remediation guidance is general and should be reviewed for your context · all targets run on 127.0.0.1 for academic use.</footer>
  </div>
  </body></html>`;

  const download = () => {
    const blob = new Blob([html], { type: "text/html" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "sbvf-report.html";
    a.click();
    URL.revokeObjectURL(a.href);
  };

  let frame: HTMLIFrameElement;
  try {
    frame = document.createElement("iframe");
    frame.style.cssText = "position:fixed;right:0;bottom:0;width:0;height:0;border:0;opacity:0";
    document.body.appendChild(frame);
    const win = frame.contentWindow;
    if (!win) throw new Error("no iframe window");
    win.document.open();
    win.document.write(html);
    win.document.close();
    // Give the web fonts a moment to load before printing.
    setTimeout(() => {
      try {
        win.focus();
        win.print();
        setTimeout(() => frame.remove(), 1500);
      } catch {
        frame.remove();
        download();
      }
    }, 450);
  } catch {
    download();
  }
}
