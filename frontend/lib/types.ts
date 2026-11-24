// Shape of a Finding as returned by the Python SAST API (model.Finding.to_dict).
export interface Finding {
  vuln: string;
  file: string;
  line: number;
  sink: string;
  source: string;
  framework: string;
  code: string;
  message: string;
  severity: "critical" | "high" | "medium" | "low";
  cwe: string;
  title: string;
  location: string;
  param?: string;
  method?: string;
  function?: string;
  how_in?: string;
  impact?: string;
  fix?: string[];
  owner?: string;
  exposure?: string[];
  action?: string;
}

export interface ScanResult {
  root: string;
  frameworks: Record<string, string>;
  files_scanned: number;
  findings: Finding[];
  counts: { by_vuln: Record<string, number>; by_severity: Record<string, number> };
}

export interface ScanStep {
  kind: string;
  text: string;
  data?: Record<string, unknown>;
}

export const SAMPLES: { value: string; label: string }[] = [
  { value: "php_native", label: "PHP · native" },
  { value: "php_yii", label: "PHP · Yii" },
  { value: "php_laravel", label: "PHP · Laravel" },
  { value: "python_native", label: "Python · native" },
  { value: "python_fastapi", label: "Python · FastAPI" },
  { value: "python_django", label: "Python · Django" },
  { value: "node_express", label: "Node.js · Express" },
  { value: "node_nestjs", label: "Node.js · NestJS" },
  { value: "idor_django", label: "IDOR · Django (A01)" },
  { value: "crypto_py", label: "Crypto failures · Python (A04)" },
  { value: "misconfig_py", label: "Security misconfig · Python (A02)" },
];
