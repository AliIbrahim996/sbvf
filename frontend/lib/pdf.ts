import type { ScanResult, Finding } from "./types";

const esc = (s: string) =>
  (s || "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string),
  );

/** Build a clean printable report and print it via a hidden iframe (Save as PDF).
 *  No pop-up; falls back to downloading a self-contained .html file. */
export function exportPdf(scan: ScanResult) {
  const findings = scan.findings || [];
  const stack = Object.values(scan.frameworks || {}).filter(Boolean).join(", ") || "n/a";
  const c = (scan.counts && scan.counts.by_severity) || {};
  const when = new Date().toLocaleString();

  const section = (f: Finding, i: number) => `
    <section class="rf s-${f.severity}">
      <h3><span class="rsev s-${f.severity}">${(f.severity || "").toUpperCase()}</span>
        ${i + 1}. ${esc(f.title || f.vuln)} <span class="rcwe">${esc(f.cwe || "")}</span></h3>
      <div class="rmeta"><b>Location:</b> ${esc(f.location)} &nbsp;·&nbsp;
        <b>Path:</b> ${esc(f.source)} &rarr; ${esc(f.sink)} &nbsp;·&nbsp;
        <b>Priority:</b> ${esc(f.action || "")}</div>
      <div class="rb"><div class="rh">How it got in</div><p>${esc(f.how_in || f.message)}</p>
        ${f.code ? `<pre>${esc(f.code.trim())}</pre>` : ""}</div>
      <div class="rb"><div class="rh">Business impact</div>
        ${f.exposure && f.exposure.length ? `<p class="rexp">Exposure: ${f.exposure.map(esc).join(" · ")}</p>` : ""}
        <p>${esc(f.impact || "")}</p></div>
      <div class="rb"><div class="rh">How to close it</div>
        <p class="rown">Owner: ${esc(f.owner || "Engineering")}</p>
        <ol>${(f.fix || []).map((s) => `<li>${esc(s)}</li>`).join("")}</ol></div>
    </section>`;

  const html = `<!doctype html><html><head><meta charset="utf-8"><title>SBVF report</title><style>
    *{box-sizing:border-box} body{font:13px/1.6 "Segoe UI",system-ui,Arial,sans-serif;color:#111;margin:32px}
    h1{font-size:22px;margin:0 0 2px} .sub{color:#555;font-size:12px;margin:0 0 18px}
    .summary{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 18px}
    .kc{border:1px solid #ddd;border-radius:8px;padding:8px 14px;min-width:92px}
    .kc .n{font-size:22px;font-weight:800} .kc .l{font-size:10px;text-transform:uppercase;color:#777}
    .rf{border:1px solid #e2e2e2;border-left:4px solid #999;border-radius:8px;padding:12px 16px;margin:0 0 14px;page-break-inside:avoid}
    .rf.s-high,.rf.s-critical{border-left-color:#d33}.rf.s-medium{border-left-color:#e08600}
    .rf h3{font-size:15px;margin:0 0 6px} .rcwe{color:#888;font-size:11px;font-weight:600}
    .rsev{display:inline-block;color:#fff;font-size:10px;font-weight:800;border-radius:4px;padding:2px 7px;margin-right:8px}
    .rsev.s-high,.rsev.s-critical{background:#d33}.rsev.s-medium{background:#e08600}.rsev.s-low{background:#777}
    .rmeta{font-size:11.5px;color:#444;margin:0 0 10px;font-family:ui-monospace,Consolas,monospace}
    .rb{margin:9px 0} .rh{font-size:10.5px;text-transform:uppercase;font-weight:800;color:#333;margin:0 0 3px}
    .rb p{margin:0} .rexp{color:#a15c00;font-weight:600} .rown{color:#555;font-size:12px}
    pre{background:#f5f6f8;border:1px solid #e2e2e2;border-radius:6px;padding:8px 10px;overflow:auto;font:11px/1.45 ui-monospace,Consolas,monospace;margin:6px 0 0}
    ol{margin:4px 0 0;padding-left:20px} li{margin:2px 0}
    footer{margin-top:18px;color:#999;font-size:10.5px;border-top:1px solid #eee;padding-top:8px}
    @media print{body{margin:14mm}}
    </style></head><body>
    <h1>SBVF — Vulnerability Report</h1>
    <p class="sub">Target: <b>${esc(scan.root || "")}</b> · Stack: ${esc(stack)} · Files scanned: ${scan.files_scanned || 0} · Generated ${esc(when)}</p>
    <div class="summary">
      <div class="kc"><div class="n">${findings.length}</div><div class="l">Findings</div></div>
      <div class="kc"><div class="n" style="color:#d33">${(c.critical || 0) + (c.high || 0)}</div><div class="l">High / Critical</div></div>
      <div class="kc"><div class="n" style="color:#e08600">${c.medium || 0}</div><div class="l">Medium</div></div>
      <div class="kc"><div class="n" style="color:#777">${c.low || 0}</div><div class="l">Low</div></div>
    </div>
    ${findings.map(section).join("") || "<p>No vulnerabilities found.</p>"}
    <footer>SBVF static analysis · remediation guidance is general and should be reviewed for your context.</footer>
    </body></html>`;

  const frame = document.createElement("iframe");
  frame.style.cssText = "position:fixed;right:0;bottom:0;width:0;height:0;border:0;opacity:0";
  document.body.appendChild(frame);
  const doc = frame.contentWindow!.document;
  doc.open();
  doc.write(html);
  doc.close();
  setTimeout(() => {
    try {
      frame.contentWindow!.focus();
      frame.contentWindow!.print();
      setTimeout(() => frame.remove(), 1500);
    } catch {
      const blob = new Blob([html], { type: "text/html" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "sbvf-report.html";
      a.click();
      URL.revokeObjectURL(a.href);
      frame.remove();
    }
  }, 300);
}
