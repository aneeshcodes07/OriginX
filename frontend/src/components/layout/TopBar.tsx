"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Search, FolderGit2, Sun, Moon } from "lucide-react";

const TITLE_MAP: Record<string, { title: string; subtitle: string }> = {
  "/": { title: "Security Overview", subtitle: "Real-time posture and threat telemetry for your third-party software supply chain." },
  "/scanner": { title: "Package Scanner", subtitle: "Deep static inspection, integrity verification, and OSV intelligence." },
  "/projects": { title: "Project Scanner", subtitle: "Comprehensive dependency audit for manifests and lockfiles." },
  "/comparison": { title: "Version Comparison Engine", subtitle: "Side-by-side AST and file diff analysis across releases." },
  "/dependencies": { title: "Dependency Explorer", subtitle: "Graph relationships, hierarchy depth, and typosquatting risk signals." },
  "/vulnerabilities": { title: "Vulnerability Intelligence", subtitle: "Direct Open Source Vulnerabilities (OSV) and GHSA advisory lookup." },
  "/history": { title: "Scan History", subtitle: "Search and audit past assessments stored securely in the database." },
  "/reports": { title: "Security Reports", subtitle: "Executive audits, policy compliance summaries, and downloadable JSON reports." },
  "/policies": { title: "Security Policies", subtitle: "Configure automated ALLOW, REVIEW, and BLOCK triggers." },
  "/settings": { title: "User Preferences", subtitle: "Configure default scan scopes, alert sensitivities, and display preferences." }
};

export function TopBar() {
  const pathname = usePathname();
  const current = TITLE_MAP[pathname] || { title: "OriginX", subtitle: "Software Supply Chain Security Intelligence" };
  const [theme, setTheme] = useState<string>("dark");

  useEffect(() => {
    const saved = localStorage.getItem("originx_theme") || localStorage.getItem("supplyguard_theme") || "dark";
    setTheme(saved);
    document.documentElement.setAttribute("data-theme", saved);
  }, []);

  const toggleTheme = () => {
    const nextTheme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    localStorage.setItem("originx_theme", nextTheme);
    localStorage.setItem("supplyguard_theme", nextTheme);
    document.documentElement.setAttribute("data-theme", nextTheme);
  };

  return (
    <header className="top-bar">
      <div className="top-bar-title">
        <div>
          <h2 className="page-title">{current.title}</h2>
          <p style={{ fontSize: "12px", color: "var(--text-muted)" }}>{current.subtitle}</p>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <button
          onClick={toggleTheme}
          type="button"
          className="btn-secondary"
          style={{ padding: "8px 12px", display: "inline-flex", alignItems: "center", gap: "6px" }}
          title={theme === "dark" ? "Switch to Minimalist Light Theme" : "Switch to Dark Theme"}
          aria-label="Toggle theme"
        >
          {theme === "dark" ? <Sun size={15} color="var(--risk-medium)" /> : <Moon size={15} color="var(--accent-primary)" />}
          <span style={{ fontSize: "12px", fontWeight: 500 }}>{theme === "dark" ? "Light" : "Dark"}</span>
        </button>

        <Link href="/scanner" className="btn-primary">
          <Search size={14} />
          <span>Scan Package</span>
        </Link>
        <Link href="/projects" className="btn-secondary">
          <FolderGit2 size={14} />
          <span>Scan Project</span>
        </Link>
      </div>
    </header>
  );
}
