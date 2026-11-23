import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SBVF — Search-Based Vulnerability Framework",
  description: "Static + search-based web vulnerability analysis dashboard.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
