"use client";
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import type { AuthMe, AuthUser } from "@/lib/types";

/**
 * Multi-user auth state for the dashboard. The backend is open by default; auth
 * is active only when it runs with SBVF_AUTH, which `GET /api/auth/me` reports as
 * `auth_enabled`. When disabled, `user` stays null and `authEnabled` is false, so
 * the UI shows no auth controls and nothing is gated — the single-user experience
 * is unchanged.
 */
interface AuthContextValue {
  loading: boolean;
  authEnabled: boolean;
  user: AuthUser | null;
  refresh: () => Promise<void>;
  login: (username: string, password: string) => Promise<{ ok: boolean; message?: string }>;
  register: (username: string, password: string) => Promise<{ ok: boolean; message?: string }>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

async function postAuth(path: string, body?: object): Promise<{ ok: boolean; message?: string; data?: AuthMe["user"] }> {
  try {
    const r = await fetch(`/api/auth/${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const d = await r.json().catch(() => ({}));
    return { ok: r.ok, message: d?.message, data: d?.user };
  } catch {
    return { ok: false, message: "Could not reach the backend." };
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [loading, setLoading] = useState(true);
  const [authEnabled, setAuthEnabled] = useState(false);
  const [user, setUser] = useState<AuthUser | null>(null);

  const refresh = useCallback(async () => {
    try {
      const r = await fetch("/api/auth/me", { cache: "no-store" });
      const d: AuthMe = await r.json();
      setAuthEnabled(!!d.auth_enabled);
      setUser(d.authenticated ? d.user || null : null);
    } catch {
      // Backend unreachable: treat as auth-off so the app still renders.
      setAuthEnabled(false);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const login = useCallback(async (username: string, password: string) => {
    const res = await postAuth("login", { username, password });
    if (res.ok) await refresh();
    return { ok: res.ok, message: res.message };
  }, [refresh]);

  const register = useCallback(async (username: string, password: string) => {
    const res = await postAuth("register", { username, password });
    if (res.ok) await refresh();
    return { ok: res.ok, message: res.message };
  }, [refresh]);

  const logout = useCallback(async () => {
    await postAuth("logout");
    await refresh();
  }, [refresh]);

  return (
    <AuthContext.Provider value={{ loading, authEnabled, user, refresh, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}
