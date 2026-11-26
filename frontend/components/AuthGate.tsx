"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { useAuth } from "@/lib/auth";

/**
 * Wraps a protected page's content. When multi-user auth is enabled on the backend
 * and no one is signed in, it shows a sign-in prompt instead of the content (and
 * the content's data fetches never run). When auth is disabled — the default — it
 * renders children unchanged, so the single-user app is untouched.
 */
export function AuthGate({ children }: { children: ReactNode }) {
  const { loading, authEnabled, user } = useAuth();
  const pathname = usePathname();

  if (!authEnabled || user) return <>{children}</>;
  if (loading) return <div className="empty">Checking your session…</div>;

  const next = encodeURIComponent(pathname || "/history");
  return (
    <div className="empty auth-gate">
      <p>Sign in to view this page.</p>
      <Link className="btn btn-primary btn-sm" href={`/login?next=${next}`}>Sign in</Link>
    </div>
  );
}
