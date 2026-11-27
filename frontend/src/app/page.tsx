"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Bug,
  Search,
  FolderGit2,
  GitCompare,
  Clock,
  ArrowRight,
  RefreshCw,
  Sliders,
  FileText,
  X
} from "lucide-react";
import { api } from "@/lib/api";
import { DashboardStats, Scan } from "@/types";

export default function DashboardOverviewPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDashboard = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsData, scansData] = await Promise.all([
        api.getDashboardStats(false),
        api.listScans({ is_demo: false, limit: 8 })
      ]);
      setStats(statsData);
      setRecentScans(scansData);
    } catch (err: any) {
      setError(err.message || "Failed to connect to OriginX backend API.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {error && (
        <div style={{
          backgroundColor: "var(--risk-high-bg)",
          border: "1px solid var(--risk-high)",
          borderRadius: "var(--radius-md)",
          padding: "14px 18px",
          color: "var(--text-primary)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: "12px"
        }}>
          <div>
            <strong style={{ color: "var(--risk-high)" }}>Connection Notice: </strong>
            <span>{error === "Failed to fetch" ? "Backend API is offline at http://127.0.0.1:8000. Start the backend server or click Retry." : error}</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <button onClick={loadDashboard} className="btn-secondary" style={{ padding: "4px 12px" }}>
              <RefreshCw size={13} /> Retry
            </button>
            <button
              onClick={() => setError(null)}
              className="btn-secondary"
              style={{ padding: "4px 8px" }}
              title="Dismiss Notice"
              aria-label="Dismiss Notice"
            >
              <X size={13} />
            </button>
          </div>
        </div>
      )}

      {/* Summary Stat Cards */}
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
        gap: "16px"
      }}>
        <div className="sg-card">
          <div className="sg-card-header" style={{ marginBottom: "8px" }}>
            <span className="card-subtitle">Packages Assessed</span>
            <Search size={16} color="var(--accent-primary)" />
          </div>
          <div style={{ fontSize: "30px", fontWeight: 800, color: "var(--text-primary)", letterSpacing: "-0.5px" }}>
            {loading ? "..." : stats?.total_scanned ?? 0}
          </div>
          <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "6px" }}>
            {stats?.latest_scan_time ? (
              <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                <Clock size={11} /> Last: {new Date(stats.latest_scan_time).toLocaleTimeString()}
              </span>
            ) : "No packages audited yet"}
          </div>
        </div>

        <div className="sg-card">
          <div className="sg-card-header" style={{ marginBottom: "8px" }}>
            <span className="card-subtitle">High-Risk Threat Indicators</span>
            <AlertTriangle size={16} color="var(--risk-high)" />
          </div>
          <div style={{ fontSize: "30px", fontWeight: 800, color: "var(--risk-high)", letterSpacing: "-0.5px" }}>
            {loading ? "..." : stats?.high_risk_findings ?? 0}
          </div>
          <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "6px" }}>
            Requires security review
          </div>
        </div>

        <div className="sg-card">
          <div className="sg-card-header" style={{ marginBottom: "8px" }}>
            <span className="card-subtitle">Known Vulnerabilities</span>
            <Bug size={16} color="var(--risk-medium)" />
          </div>
          <div style={{ fontSize: "30px", fontWeight: 800, color: "var(--risk-medium)", letterSpacing: "-0.5px" }}>
            {loading ? "..." : stats?.known_vulnerabilities ?? 0}
          </div>
          <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "6px" }}>
            Reported CVE & GHSA advisories
          </div>
        </div>

        <div className="sg-card">
          <div className="sg-card-header" style={{ marginBottom: "8px" }}>
            <span className="card-subtitle">Action Required</span>
            <ShieldAlert size={16} color="var(--accent-primary)" />
          </div>
          <div style={{ fontSize: "30px", fontWeight: 800, color: "var(--accent-primary)", letterSpacing: "-0.5px" }}>
            {loading ? "..." : stats?.packages_requiring_review ?? 0}
          </div>
          <div style={{ fontSize: "12px", color: "var(--text-muted)", marginTop: "6px" }}>
            Under Review or Blocked
          </div>
        </div>
      </div>

      {/* Main Grid: Risk Distribution + Quick Actions */}
      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 0.9fr", gap: "20px" }}>
        {/* Risk Distribution Card */}
        <div className="sg-card">
          <div className="sg-card-header">
            <div>
              <h3 className="card-title">Risk Distribution</h3>
              <p className="card-subtitle">Aggregate classification of assessed dependencies</p>
            </div>
          </div>

          {stats && stats.total_scanned > 0 ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-around", padding: "12px 0" }}>
              <div style={{ display: "flex", flexDirection: "column", gap: "12px", width: "100%" }}>
                {[
                  { label: "Critical Risk (75-100)", count: stats.risk_distribution.CRITICAL, color: "var(--risk-critical)" },
                  { label: "High Risk (50-74)", count: stats.risk_distribution.HIGH, color: "var(--risk-high)" },
                  { label: "Medium Risk (25-49)", count: stats.risk_distribution.MEDIUM, color: "var(--risk-medium)" },
                  { label: "Low Risk (0-24)", count: stats.risk_distribution.LOW, color: "var(--risk-low)" }
                ].map((item) => {
                  const pct = stats.total_scanned > 0 ? Math.round((item.count / stats.total_scanned) * 100) : 0;
                  return (
                    <div key={item.label}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginBottom: "5px" }}>
                        <span style={{ color: "var(--text-secondary)" }}>{item.label}</span>
                        <span style={{ fontWeight: 600, color: item.color }}>{item.count} ({pct}%)</span>
                      </div>
                      <div style={{ height: "6px", backgroundColor: "var(--bg-main)", borderRadius: "3px", overflow: "hidden" }}>
                        <div style={{ width: `${pct}%`, height: "100%", backgroundColor: item.color }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <div className="empty-state" style={{ padding: "32px 12px" }}>
              <ShieldCheck size={36} className="empty-state-icon" color="var(--accent-primary)" />
              <div className="empty-state-title">No Scans Recorded Yet</div>
              <p className="empty-state-desc">Scan any package from npm or PyPI to generate security assessments.</p>
              <Link href="/scanner" className="btn-primary" style={{ display: "inline-flex" }}>
                Scan a Package
              </Link>
            </div>
          )}
        </div>

        {/* Quick Actions */}
        <div className="sg-card">
          <div className="sg-card-header">
            <div>
              <h3 className="card-title">Quick Actions</h3>
              <p className="card-subtitle">Initiate security workflows</p>
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            <Link href="/scanner" className="sg-card" style={{ padding: "14px", display: "flex", alignItems: "center", justifyContent: "space-between", backgroundColor: "var(--bg-elevated)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <Search size={18} color="var(--accent-primary)" />
                <div>
                  <div style={{ fontWeight: 600, fontSize: "13px" }}>Scan Registry Package</div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Inspect npm or PyPI packages by name and version</div>
                </div>
              </div>
              <ArrowRight size={14} color="var(--text-muted)" />
            </Link>

            <Link href="/comparison" className="sg-card" style={{ padding: "14px", display: "flex", alignItems: "center", justifyContent: "space-between", backgroundColor: "var(--bg-elevated)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <GitCompare size={18} color="var(--accent-secondary)" />
                <div>
                  <div style={{ fontWeight: 600, fontSize: "13px" }}>Compare Two Releases</div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Side-by-side AST and line-level diff viewer</div>
                </div>
              </div>
              <ArrowRight size={14} color="var(--text-muted)" />
            </Link>

            <Link href="/projects" className="sg-card" style={{ padding: "14px", display: "flex", alignItems: "center", justifyContent: "space-between", backgroundColor: "var(--bg-elevated)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <FolderGit2 size={18} color="var(--risk-low)" />
                <div>
                  <div style={{ fontWeight: 600, fontSize: "13px" }}>Audit Project Manifest</div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Analyze package.json, lockfiles, or requirements.txt</div>
                </div>
              </div>
              <ArrowRight size={14} color="var(--text-muted)" />
            </Link>

            <Link href="/policies" className="sg-card" style={{ padding: "14px", display: "flex", alignItems: "center", justifyContent: "space-between", backgroundColor: "var(--bg-elevated)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <Sliders size={18} color="var(--risk-medium)" />
                <div>
                  <div style={{ fontWeight: 600, fontSize: "13px" }}>Configure Security Policies</div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>Set automated ALLOW, REVIEW, and BLOCK triggers</div>
                </div>
              </div>
              <ArrowRight size={14} color="var(--text-muted)" />
            </Link>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="sg-card">
        <div className="sg-card-header">
          <div>
            <h3 className="card-title">Recent Scans</h3>
            <p className="card-subtitle">Verified assessments from the database</p>
          </div>
          <Link href="/history" className="btn-secondary" style={{ padding: "5px 12px", fontSize: "12px" }}>
            View All History
          </Link>
        </div>

        {recentScans.length > 0 ? (
          <div className="table-container">
            <table className="sg-table">
              <thead>
                <tr>
                  <th>Package Name</th>
                  <th>Ecosystem</th>
                  <th>Version</th>
                  <th>Risk Score</th>
                  <th>Classification</th>
                  <th>Policy Decision</th>
                  <th>Scan Timestamp</th>
                  <th>Report</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => (
                  <tr key={scan.id}>
                    <td style={{ fontWeight: 600 }}>{scan.package_name}</td>
                    <td>
                      <span className="code-tag">{scan.ecosystem}</span>
                    </td>
                    <td>
                      <span className="code-tag">v{scan.version}</span>
                    </td>
                    <td>
                      <span style={{ fontWeight: 700, fontFamily: "var(--font-mono)" }}>
                        {scan.risk_score}
                      </span>
                      <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>/100</span>
                    </td>
                    <td>
                      <span className={`risk-pill ${scan.risk_classification.toLowerCase()}`}>
                        {scan.risk_classification}
                      </span>
                    </td>
                    <td>
                      <span className={`policy-badge ${scan.policy_decision.toLowerCase()}`}>
                        {scan.policy_decision}
                      </span>
                    </td>
                    <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td>
                      <Link href={`/reports?scan_id=${scan.id}`} className="btn-secondary" style={{ padding: "4px 10px", fontSize: "11px" }}>
                        View Report
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state" style={{ padding: "40px" }}>
            <p className="empty-state-desc">No scans recorded yet. Use the Package Scanner to audit your first dependency.</p>
          </div>
        )}
      </div>
    </div>
  );
}
