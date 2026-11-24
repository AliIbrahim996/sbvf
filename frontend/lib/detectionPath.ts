import type { Finding } from "./types";

/** A single node in the "how the scanner reached it" path. */
export type StepKind = "scan" | "source" | "file" | "handler" | "rule" | "sink" | "vuln";

export interface PathStep {
  kind: StepKind;
  title: string;
  detail: string;
  meta?: string;
}

const METHOD_PHRASE: Record<string, string> = {
  GET: "a GET query parameter",
  POST: "a POST body field",
  REQUEST: "a request parameter",
  PATH: "a URL path segment",
  COOKIE: "a cookie",
  HEADER: "a request header",
};

/** Pattern-rule / manifest findings (A02/A03/A04/A08/A10) have no taint flow:
 *  the scanner matched a construct on a line rather than tracing a source. */
export function isPatternFinding(f: Finding): boolean {
  return !!(f.rule && f.rule.trim()) ||
    /^(pattern rule|dependency manifest)/i.test(f.source || "");
}

/** Reconstruct the scanner's reasoning path from a finding's recorded fields.
 *  Taint findings get source -> handler -> sink -> vuln; pattern/manifest
 *  findings get file -> rule -> match -> vuln. Pure and side-effect free. */
export function buildDetectionPath(f: Finding): PathStep[] {
  const steps: PathStep[] = [];
  const fw = f.framework ? f.framework : "the codebase";
  const loc = f.location || `${f.file}:${f.line}`;

  steps.push({
    kind: "scan",
    title: "Scan starts",
    detail: `The static scanner indexes ${fw} and begins reading source files — no code is executed.`,
    meta: fw,
  });

  if (isPatternFinding(f)) {
    steps.push({
      kind: "file",
      title: "File analysed",
      detail: `The scanner reads ${f.file} line by line.`,
      meta: f.file,
    });
    const rule = f.rule && f.rule.trim() ? f.rule : "a pattern rule";
    steps.push({
      kind: "rule",
      title: "Rule evaluated",
      detail: `Rule ${rule} checks each line for a known-dangerous construct.`,
      meta: rule,
    });
    steps.push({
      kind: "sink",
      title: "Pattern matched",
      detail: f.message || "A dangerous construct matched the rule.",
      meta: `${f.sink}  ·  ${loc}`,
    });
  } else {
    const where = (f.method && METHOD_PHRASE[f.method]) || "an untrusted input";
    const param = f.param ? ` '${f.param}'` : "";
    steps.push({
      kind: "source",
      title: "Untrusted source",
      detail: `Input enters from ${f.source} — ${where}${param}. The scanner marks it tainted.`,
      meta: f.source,
    });
    steps.push(
      f.function
        ? {
            kind: "handler",
            title: "Reaches handler",
            detail: `The tainted value flows through the request handler ${f.function} with no sanitizer, validator or encoder on the way.`,
            meta: `${f.function}()`,
          }
        : {
            kind: "handler",
            title: "Propagates",
            detail: `The tainted value propagates through ${f.file} with nothing to sanitize, validate or encode it.`,
            meta: f.file,
          },
    );
    steps.push({
      kind: "sink",
      title: "Hits the sink",
      detail: `The still-tainted value reaches ${f.sink} at ${loc}, where it is dangerous.`,
      meta: `${f.sink}  ·  ${loc}`,
    });
  }

  steps.push({
    kind: "vuln",
    title: f.title || f.vuln,
    detail: f.how_in || f.message || "The scanner records the vulnerability.",
    meta: `${f.cwe} · ${(f.severity || "").toUpperCase()}`,
  });
  return steps;
}
