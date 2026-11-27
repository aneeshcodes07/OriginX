"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import {
  ShieldCheck,
  Search,
  FolderGit2,
  GitCompare,
  Network,
  Bug,
  History,
  FileText,
  Sliders,
  Settings as SettingsIcon,
  Activity
} from "lucide-react";
import { api } from "@/lib/api";

const NAV_ITEMS = [
  { label: "Overview", href: "/", icon: Activity },
  { label: "Package Scanner", href: "/scanner", icon: Search },
  { label: "Project Scanner", href: "/projects", icon: FolderGit2 },
  { label: "Version Comparison", href: "/comparison", icon: GitCompare },
  { label: "Dependency Explorer", href: "/dependencies", icon: Network },
  { label: "Vulnerability Intelligence", href: "/vulnerabilities", icon: Bug },
  { label: "Scan History", href: "/history", icon: History },
  { label: "Security Reports", href: "/reports", icon: FileText },
  { label: "Security Policies", href: "/policies", icon: Sliders },
  { label: "User Preferences", href: "/settings", icon: SettingsIcon },
];

export function Sidebar() {
  const pathname = usePathname();
  const [isHealthy, setIsHealthy] = useState<boolean | null>(null);

  useEffect(() => {
    let mounted = true;
    api.getHealth()
      .then(() => { if (mounted) setIsHealthy(true); })
      .catch(() => { if (mounted) setIsHealthy(false); });
    return () => { mounted = false; };
  }, [pathname]);

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-logo" style={{ color: "var(--accent-primary)" }}>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            {/* Origin node with interconnected orbital network and shield contour */}
            <circle cx="12" cy="12" r="3" fill="currentColor" fillOpacity="0.2" strokeWidth="2.5" />
            <path d="M12 2v4M12 18v4M2 12h4M18 12h4" strokeWidth="2" />
            <path d="M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" strokeWidth="1.5" strokeOpacity="0.7" />
            <polygon points="12 3 20 7 20 13 12 21 4 13 4 7" strokeWidth="1.2" strokeOpacity="0.4" />
          </svg>
        </div>
        <div className="brand-text">
          <h1>OriginX</h1>
          <p>Supply Chain Intelligence</p>
        </div>
      </div>

      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`nav-item ${isActive ? "active" : ""}`}
            >
              <Icon size={17} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="status-indicator">
          <div
            className="status-dot"
            style={{
              backgroundColor: isHealthy === false ? "var(--risk-high)" : "var(--risk-low)",
              boxShadow: isHealthy === false ? "0 0 8px var(--risk-high)" : "0 0 8px var(--risk-low)"
            }}
          />
          <span>{isHealthy === false ? "Service Degraded" : "System Protected & Active"}</span>
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "11px", color: "var(--text-muted)" }}>
          <span>Enterprise Platform</span>
          <span className="code-tag" style={{ fontSize: "10px" }}>v1.0</span>
        </div>
      </div>
    </aside>
  );
}
