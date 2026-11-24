import { NextRequest } from "next/server";

// Proxy the Python SBVF API through this handler so the browser talks same-origin.
// GET is streamed incrementally (SSE: next rewrites buffer them); other methods
// (DELETE, and later POST) are forwarded and their JSON response returned.
// Node runtime + force-dynamic + passing the upstream ReadableStream straight
// through keeps SSE live.
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const API = process.env.SBVF_API_ORIGIN || "http://127.0.0.1:8080";

export async function GET(req: NextRequest, ctx: { params: { path: string[] } }) {
  const target = `${API}/api/${ctx.params.path.join("/")}${req.nextUrl.search}`;
  let upstream: Response;
  try {
    upstream = await fetch(target, {
      headers: { accept: "text/event-stream" },
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
    headers: {
      "Content-Type": upstream.headers.get("content-type") || "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
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
      headers: hasBody ? { "content-type": req.headers.get("content-type") || "application/json" } : undefined,
      body: hasBody ? await req.text() : undefined,
    });
  } catch {
    return Response.json({ message: `cannot reach backend at ${API}` }, { status: 502 });
  }
  const body = await upstream.text();
  return new Response(body, {
    status: upstream.status,
    headers: { "Content-Type": upstream.headers.get("content-type") || "application/json" },
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
      headers: {
        "content-type": req.headers.get("content-type") || "application/json",
        accept: "text/event-stream",
      },
      body,
    });
  } catch {
    return new Response(
      `event: agents_error\ndata: ${JSON.stringify({ message: `cannot reach backend at ${API}` })}\n\n`,
      { status: 502, headers: { "Content-Type": "text/event-stream" } },
    );
  }
  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      "Content-Type": upstream.headers.get("content-type") || "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
