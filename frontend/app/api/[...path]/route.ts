import { NextRequest } from "next/server";

// Proxy the Python SBVF API through this handler so the browser talks same-origin.
// GET is streamed incrementally (SSE: next rewrites buffer them); other methods
// (DELETE, and later POST) are forwarded and their JSON response returned.
// Node runtime + force-dynamic + passing the upstream ReadableStream straight
// through keeps SSE live.
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const API = process.env.SBVF_API_ORIGIN || "http://127.0.0.1:8080";

// Carry the browser's session cookie through to the backend so multi-user auth
// (when enabled) can identify the request. Only the Cookie header is forwarded.
function passCookie(req: NextRequest, extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = { ...(extra || {}) };
  const cookie = req.headers.get("cookie");
  if (cookie) headers["cookie"] = cookie;
  return headers;
}

// Relay a Set-Cookie from the backend (login/logout) back to the browser, so the
// session cookie is stored for this same-origin frontend.
function withSetCookie(upstream: Response, headers: Record<string, string>): Headers {
  const out = new Headers(headers);
  const setCookie = upstream.headers.get("set-cookie");
  if (setCookie) out.set("set-cookie", setCookie);
  return out;
}

export async function GET(req: NextRequest, ctx: { params: { path: string[] } }) {
  const target = `${API}/api/${ctx.params.path.join("/")}${req.nextUrl.search}`;
  let upstream: Response;
  try {
    upstream = await fetch(target, {
      headers: passCookie(req, { accept: "text/event-stream" }),
      cache: "no-store",
    });
  } catch {
    return new Response(
      `event: scan_error\ndata: ${JSON.stringify({ message: `cannot reach backend at ${API}` })}\n\n`,
      { status: 502, headers: { "Content-Type": "text/event-stream" } },
    );
  }
  return new Response(upstream.body, {
    status: upstream.status,
    headers: withSetCookie(upstream, {
      "Content-Type": upstream.headers.get("content-type") || "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    }),
  });
}

// Forward a non-streaming method (DELETE now; POST added with Phase 2) and relay
// the upstream JSON response verbatim.
async function forward(req: NextRequest, ctx: { params: { path: string[] } }, method: string) {
  const target = `${API}/api/${ctx.params.path.join("/")}${req.nextUrl.search}`;
  const hasBody = method !== "DELETE" && method !== "GET";
  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method,
      cache: "no-store",
      headers: passCookie(req, hasBody ? { "content-type": req.headers.get("content-type") || "application/json" } : {}),
      body: hasBody ? await req.text() : undefined,
    });
  } catch {
    return Response.json({ message: `cannot reach backend at ${API}` }, { status: 502 });
  }
  const body = await upstream.text();
  return new Response(body, {
    status: upstream.status,
    headers: withSetCookie(upstream, { "Content-Type": upstream.headers.get("content-type") || "application/json" }),
  });
}

export function DELETE(req: NextRequest, ctx: { params: { path: string[] } }) {
  return forward(req, ctx, "DELETE");
}

// POST is streamed (the AI-agents endpoint emits SSE progress); the body is
// forwarded and the upstream stream is passed straight through, like GET.
export async function POST(req: NextRequest, ctx: { params: { path: string[] } }) {
  const target = `${API}/api/${ctx.params.path.join("/")}${req.nextUrl.search}`;
  const body = await req.text();
  let upstream: Response;
  try {
    upstream = await fetch(target, {
      method: "POST",
      cache: "no-store",
      headers: passCookie(req, {
        "content-type": req.headers.get("content-type") || "application/json",
        accept: "text/event-stream",
      }),
      body,
    });
  } catch {
    return new Response(
      `event: agents_error\ndata: ${JSON.stringify({ message: `cannot reach backend at ${API}` })}\n\n`,
      { status: 502, headers: { "Content-Type": "text/event-stream" } },
    );
  }
  // Auth endpoints (login/register/logout) reply JSON with a Set-Cookie; stream
  // endpoints reply SSE. Passing the body straight through handles both; relay
  // any Set-Cookie so the session cookie lands on this same-origin frontend.
  return new Response(upstream.body, {
    status: upstream.status,
    headers: withSetCookie(upstream, {
      "Content-Type": upstream.headers.get("content-type") || "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    }),
  });
}
