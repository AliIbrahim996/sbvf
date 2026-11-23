import { NextRequest } from "next/server";

// Stream the Python SBVF API (SSE) through this handler so the browser talks
// same-origin and Server-Sent Events are forwarded incrementally (next rewrites
// buffer them). Node runtime + force-dynamic + passing the upstream ReadableStream
// straight through keeps the stream live.
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
