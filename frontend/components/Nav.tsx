"use client";
import Link from "next/link";
import { useEffect, useState, type ReactNode } from "react";

/** Shared top bar: SVG shield wordmark (links home), an optional right slot,
 *  and the light/dark theme toggle. */
export function Nav({ right }: { right?: ReactNode }) {
  const [theme, setTheme] = useState<"light" | "dark" | null>(null);

  useEffect(() => {
    const cur = document.documentElement.getAttribute("data-theme");
    setTheme(cur === "light" ? "light" : "dark");
  }, []);

  function toggleTheme() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("sbvf-theme", next);
    } catch {
      /* storage blocked — in-memory toggle still works */
    }
  }

  return (
    <nav className="nav">
      <Link href="/" className="brand-link" aria-label="SBVF home">
        <span className="mark" aria-hidden>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2 4 5v6c0 5 3.4 8.3 8 11 4.6-2.7 8-6 8-11V5l-8-3Z" />
            <path d="m9 12 2 2 4-4" />
          </svg>
        </span>
        <span className="wordmark">
          <b>SBVF</b>
          <small>Search-Based Vulnerability Framework</small>
        </span>
      </Link>
      <span className="nav-right">
        <Link href="/history" className="nav-link">History</Link>
        {right}
        <button className="theme-btn" onClick={toggleTheme} aria-label="Toggle colour theme" title="Toggle theme">
          {theme !== "light" ? (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="4" />
              <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z" />
            </svg>
          )}
        </button>
      </span>
    </nav>
  );
}
