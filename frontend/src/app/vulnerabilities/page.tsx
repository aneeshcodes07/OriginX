"use client";

import { useState } from "react";
import {
  Bug,
  Search,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock
} from "lucide-react";
import { api } from "@/lib/api";

export default function VulnerabilityIntelligencePage() {
  const [ecosystem, setEcosystem] = useState<"npm" | "pypi">("npm");
  const [packageName, setPackageName] = useState("lodash");
  const [packageVersion, setPackageVersion] = useState("4.17.20");
  const [loading, setLoading] = useState(false);
  const [vulns, setVulns] = useState<any[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleQuery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!packageName.trim() || !packageVersion.trim()) return;

    setLoading(true);
    setError(null);
    setVulns(null);

    try {
      // Query package scan to fetch real OSV records
      const res = await api.scanPackage({
        ecosystem,
        package_name: packageName.trim(),
        version: packageVersion.trim()
      });
      setVulns(res.vulnerabilities || []);
    } catch (err: any) {
      setError(err.message || "Failed to query OSV.dev intelligence API.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Lookup Card */}
      <div className="sg-card">
        <form onSubmit={handleQuery}>
          <div style={{ display: "grid", gridTemplateColumns: "140px 1.5fr 1fr auto", gap: "14px", alignItems: "flex-end" }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Ecosystem</label>
              <select
                value={ecosystem}
                onChange={(e: any) => setEcosystem(e.target.value)}
                className="form-select"
              >
                <option value="npm">npm</option>
                <option value="pypi">PyPI</option>
              </select>
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Package Name</label>
              <input
                type="text"
                placeholder="e.g. lodash or requests"
                value={packageName}
                onChange={(e) => setPackageName(e.target.value)}
                className="form-input"
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Version</label>
              <input
                type="text"
                placeholder="e.g. 4.17.20"
                value={packageVersion}
                onChange={(e) => setPackageVersion(e.target.value)}
                className="form-input"
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ height: "39px" }}
            >
              {loading ? <Clock className="animate-spin" size={14} /> : <Search size={14} />}
              <span>{loading ? "Querying OSV..." : "Query Intelligence"}</span>
            </button>
          </div>
        </form>

        {error && (
          <div style={{ marginTop: "14px", padding: "10px", backgroundColor: "var(--risk-high-bg)", color: "var(--risk-high)", borderRadius: "var(--radius-sm)", fontSize: "13px" }}>
            {error}
          </div>
        )}
      </div>

      {/* Intelligence Results */}
      {vulns && (
        <div className="sg-card">
          <div className="sg-card-header">
            <div>
              <h3 className="card-title">
                OSV.dev Intelligence: {packageName}@{packageVersion}
              </h3>
              <p className="card-subtitle">
                Queried against Open Source Vulnerabilities database and GitHub Security Advisories
              </p>
            </div>
            <span className={`risk-pill ${vulns.length > 0 ? "high" : "low"}`}>
              {vulns.length} Advisories Found
            </span>
          </div>

          {vulns.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              {vulns.map((v, i) => (
                <div key={i} style={{ padding: "16px", backgroundColor: "var(--bg-elevated)", borderRadius: "var(--radius-md)", border: "1px solid var(--border-color)" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span className={`risk-pill ${v.severity.toLowerCase()}`}>{v.severity}</span>
                      <strong className="code-tag">{v.vuln_id}</strong>
                    </div>

                    {v.source_url && (
                      <a href={v.source_url} target="_blank" rel="noreferrer" className="btn-secondary" style={{ padding: "3px 8px", fontSize: "11px" }}>
                        View Advisory <ExternalLink size={11} />
                      </a>
                    )}
                  </div>

                  <p style={{ fontSize: "13px", color: "var(--text-primary)", marginBottom: "8px" }}>
                    {v.summary || v.details || "Reported security advisory"}
                  </p>

                  <div style={{ display: "flex", gap: "20px", fontSize: "12px", color: "var(--text-muted)" }}>
                    <span>Affected Versions: <strong style={{ color: "var(--risk-medium)" }}>{v.affected_range || "Reported releases"}</strong></span>
                    {v.fixed_version && <span>Fixed in: <strong style={{ color: "var(--risk-low)" }}>{v.fixed_version}</strong></span>}
                    {v.published_at && <span>Published: {new Date(v.published_at).toLocaleDateString()}</span>}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <ShieldCheck size={36} className="empty-state-icon" color="var(--risk-low)" />
              <div className="empty-state-title">No Known Vulnerabilities Reported</div>
              <p className="empty-state-desc">
                OSV.dev returned 0 known vulnerabilities for {packageName}@{packageVersion}.
                Remember: absence of known vulnerabilities is not proof that untrusted code is safe.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
