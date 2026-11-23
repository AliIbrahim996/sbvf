/** @type {import('next').NextConfig} */
// The SBVF backend (ui/server.py) serves the SSE API. We proxy it through a
// streaming route handler (app/api/[...path]/route.ts) rather than next
// rewrites, because rewrites buffer Server-Sent Events and the live scan log
// would never stream. Override the backend origin with SBVF_API_ORIGIN.
const nextConfig = {
  reactStrictMode: true,
};

export default nextConfig;
