"use client";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { AskIcon } from "@/components/icons";
import type { AiStatus, AskResponse, AskSource, ChatMessage } from "@/lib/types";

/** Q&A over scan history. Global when `scanId` is omitted, else scoped to a scan.
 *  Renders nothing when no AI provider is configured. */
export function AskPanel({ scanId }: { scanId?: number }) {
  const [status, setStatus] = useState<AiStatus | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const endRef = useRef<HTMLDivElement>(null);

  const chatUrl = scanId != null ? `/api/chat?scan_id=${scanId}` : "/api/chat";

  useEffect(() => {
    (async () => {
      try {
        const s = await fetch("/api/ai/status");
        if (s.ok) setStatus(await s.json());
        const c = await fetch(chatUrl);
        if (c.ok) setMessages((await c.json()).messages || []);
      } catch {
        /* leave panel empty */
      }
    })();
  }, [chatUrl]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [messages.length, busy]);

  async function ask(e: React.FormEvent) {
    e.preventDefault();
    const q = question.trim();
    if (!q || busy) return;
    setBusy(true);
    setError("");
    setMessages((prev) => [...prev, { id: -Date.now(), created_at: "", scan_id: scanId ?? null, role: "user", content: q }]);
    setQuestion("");
    try {
      const r = await fetch("/api/ask", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ question: q, scan_id: scanId ?? null }),
      });
      const d = (await r.json()) as AskResponse;
      if (!r.ok || !d.ok) {
        setError(d.message || "Q&A failed.");
      } else {
        setMessages((prev) => [
          ...prev,
          {
            id: -Date.now() - 1,
            created_at: "",
            scan_id: scanId ?? null,
            role: "assistant",
            content: d.answer,
            provider: d.provider,
            model: d.model,
            details: { sources: d.sources },
          },
        ]);
      }
    } catch {
      setError("Could not reach the Q&A service.");
    } finally {
      setBusy(false);
    }
  }

  if (!status?.enabled) return null;

  return (
    <div className="card askpanel">
      <div className="card-head">
        <h2><AskIcon /> Ask about {scanId != null ? "this scan" : "your scans"}</h2>
      </div>
      {messages.length > 0 && (
        <div className="chat">
          {messages.map((m) => (
            <div key={m.id} className={`bubble ${m.role}`}>
              <p>{m.content}</p>
              {m.role === "assistant" && m.details?.sources && m.details.sources.length > 0 && (
                <div className="sources">
                  {dedupeSources(m.details.sources).map((s, i) => (
                    <Link key={i} href={`/history/${s.scan_id}`} className="srcchip" title={`${s.severity || ""} ${s.cwe || ""} ${s.location}`}>
                      scan #{s.scan_id}{s.location ? ` · ${s.location}` : ""}
                    </Link>
                  ))}
                </div>
              )}
            </div>
          ))}
          {busy && <div className="bubble assistant pending"><p>Thinking…</p></div>}
          <div ref={endRef} />
        </div>
      )}
      {error && <p className="ai-err">{error}</p>}
      <form className="askform" onSubmit={ask}>
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder={scanId != null ? "e.g. What's the biggest risk in this scan?" : "e.g. Which scans found SQL injection?"}
          aria-label="Ask a question about your scan history"
          disabled={busy}
        />
        <button className="btn btn-primary" type="submit" disabled={busy || !question.trim()}>
          {busy ? "Asking…" : "Ask"}
        </button>
      </form>
      <p className="ai-note">
        Answered from your stored scans by {status.providers.join(" / ") || "the configured provider"}.
        Your question and the relevant findings are sent to that provider.
      </p>
    </div>
  );
}

function dedupeSources(sources: AskSource[]): AskSource[] {
  const seen = new Set<string>();
  const out: AskSource[] = [];
  for (const s of sources) {
    const key = `${s.scan_id}|${s.location}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(s);
    if (out.length >= 8) break;
  }
  return out;
}
