"use client";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState } from "react";
import { Nav } from "@/components/Nav";
import { useAuth } from "@/lib/auth";

function LoginInner() {
  const { authEnabled, user, loading, login, register } = useAuth();
  const router = useRouter();
  const params = useSearchParams();
  const next = params.get("next") || "/history";

  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Already signed in, or auth is off entirely → nothing to do here.
  useEffect(() => {
    if (!loading && (user || !authEnabled)) router.replace(next);
  }, [loading, user, authEnabled, next, router]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    const act = mode === "login" ? login : register;
    const res = await act(username.trim(), password);
    setBusy(false);
    if (res.ok) router.replace(next);
    else setError(res.message || "Something went wrong.");
  }

  return (
    <div className="shell">
      <Nav />
      <header className="hero">
        <h1>{mode === "login" ? "Sign in" : "Create your account"}</h1>
        <p>
          {mode === "login"
            ? "Sign in to see and run your own scans."
            : "The first account becomes the admin. Choose a username and a password of at least 8 characters."}
        </p>
      </header>

      <div className="card auth-card">
        <form onSubmit={submit} className="auth-form">
          <div className="field">
            <label htmlFor="username">Username</label>
            <input
              id="username" type="text" autoComplete="username" value={username}
              onChange={(e) => setUsername(e.target.value)} required autoFocus
              placeholder="e.g. alice" />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input
              id="password" type="password"
              autoComplete={mode === "login" ? "current-password" : "new-password"}
              value={password} onChange={(e) => setPassword(e.target.value)} required
              placeholder="••••••••" />
          </div>

          {error && <p className="auth-error" role="alert">{error}</p>}

          <button type="submit" className="btn btn-primary btn-lg" disabled={busy}>
            {busy ? "Working…" : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>

        <p className="auth-switch">
          {mode === "login" ? (
            <>No account yet?{" "}
              <button type="button" className="linklike" onClick={() => { setMode("register"); setError(null); }}>
                Create one
              </button>
            </>
          ) : (
            <>Already have an account?{" "}
              <button type="button" className="linklike" onClick={() => { setMode("login"); setError(null); }}>
                Sign in
              </button>
            </>
          )}
        </p>
      </div>

      <footer>SBVF research prototype · all targets run on 127.0.0.1 · for academic use only</footer>
    </div>
  );
}

export default function LoginPage() {
  // useSearchParams requires a Suspense boundary for static generation.
  return (
    <Suspense fallback={<div className="shell"><Nav /><div className="empty">Loading…</div></div>}>
      <LoginInner />
    </Suspense>
  );
}
