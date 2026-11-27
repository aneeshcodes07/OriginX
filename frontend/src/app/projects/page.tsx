"use client";

import { useState } from "react";
import {
  FolderGit2,
  Upload,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Bug,
  FileCode,
  CheckCircle,
  ExternalLink
} from "lucide-react";
import { api } from "@/lib/api";

export default function ProjectScannerPage() {
  const [manifestFile, setManifestFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manifestFile) return;

    setScanning(true);
    setError(null);
    setResult(null);

    try {
      const data = await api.scanProject(manifestFile);
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Failed to scan project manifest.");
    } finally {
      setScanning(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Upload Manifest Card */}
      <div className="sg-card">
        <form onSubmit={handleScan}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: "16px", alignItems: "flex-end" }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Upload Manifest or Lockfile (package.json, package-lock.json, requirements.txt, pyproject.toml)</label>
              <input
                type="file"
                accept=".json,.txt,.toml"
                onChange={(e) => setManifestFile(e.target.files?.[0] || null)}
                className="form-input"
                required
              />
            </div>

            <button
              type="submit"
              disabled={scanning || !manifestFile}
              className="btn-primary"
              style={{ height: "39px" }}
            >
              <FolderGit2 size={14} />
              <span>{scanning ? "Analyzing Tree..." : "Analyze Manifest"}</span>
            </button>
          </div>
        </form>

        {error && (
          <div style={{ marginTop: "16px", padding: "12px", backgroundColor: "var(--risk-high-bg)", border: "1px solid var(--risk-high)", borderRadius: "var(--radius-md)", color: "var(--text-primary)", fontSize: "13px" }}>
            <strong>Analysis Error: </strong> {error}
          </div>
        )}
      </div>

      {/* Project Scan Output */}
      {result && (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* Executive Overview Banner */}
          <div className="sg-card" style={{
            borderLeft: `4px solid ${
              result.overall_assessment === "CRITICAL" ? "var(--risk-critical)" :
              result.overall_assessment === "REVIEW" ? "var(--risk-medium)" : "var(--risk-low)"
            }`
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <h2 style={{ fontSize: "18px", fontWeight: 700 }}>Project Manifest: {result.project_filename}</h2>
                  <span className="code-tag">{result.ecosystem}</span>
                </div>
                <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "4px" }}>
                  {result.recommendation}
                </p>
              </div>

              <span className={`risk-pill ${result.overall_assessment === "CRITICAL" ? "critical" : result.overall_assessment === "REVIEW" ? "medium" : "low"}`}>
                {result.overall_assessment} STATUS
              </span>
            </div>
          </div>

          {/* Metric Summary Cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "14px" }}>
            <div className="sg-card" style={{ padding: "16px" }}>
              <div className="card-subtitle">Dependencies Discovered</div>
              <div style={{ fontSize: "24px", fontWeight: 700, marginTop: "4px" }}>
                {result.total_dependencies_discovered}
              </div>
            </div>

            <div className="sg-card" style={{ padding: "16px" }}>
              <div className="card-subtitle">Dependencies Analyzed</div>
              <div style={{ fontSize: "24px", fontWeight: 700, color: "var(--accent-secondary)", marginTop: "4px" }}>
                {result.dependencies_analyzed}
              </div>
            </div>

            <div className="sg-card" style={{ padding: "16px" }}>
              <div className="card-subtitle">Known Vulnerabilities</div>
              <div style={{ fontSize: "24px", fontWeight: 700, color: result.known_vulnerabilities_count > 0 ? "var(--risk-high)" : "var(--risk-low)", marginTop: "4px" }}>
                {result.known_vulnerabilities_count}
              </div>
            </div>

            <div className="sg-card" style={{ padding: "16px" }}>
              <div className="card-subtitle">Typosquat / Unpinned Signals</div>
              <div style={{ fontSize: "24px", fontWeight: 700, color: result.typosquat_and_unpinned_issues.length > 0 ? "var(--risk-medium)" : "var(--risk-low)", marginTop: "4px" }}>
                {result.typosquat_and_unpinned_issues.length}
              </div>
            </div>
          </div>

          {/* Typosquat and Unpinned issues */}
          {result.typosquat_and_unpinned_issues.length > 0 && (
            <div className="sg-card">
              <h3 className="card-title" style={{ color: "var(--risk-medium)", marginBottom: "12px" }}>
                <AlertTriangle size={16} /> Supply Chain Configuration Warnings
              </h3>
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {result.typosquat_and_unpinned_issues.map((iss: any, i: number) => (
                  <div key={i} style={{ padding: "8px 12px", backgroundColor: "var(--bg-elevated)", borderRadius: "var(--radius-sm)", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "12px" }}>
                    <div>
                      <strong className="code-tag" style={{ marginRight: "8px" }}>{iss.package}</strong>
                      <span>{iss.reason}</span>
                    </div>
                    <span className="risk-pill medium">{iss.severity}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Discovered Dependencies List */}
          <div className="sg-card">
            <h3 className="card-title" style={{ marginBottom: "14px" }}>Discovered Dependencies Tree</h3>
            <div className="table-container">
              <table className="sg-table">
                <thead>
                  <tr>
                    <th>Package Name</th>
                    <th>Version Constraint</th>
                    <th>Scope / Type</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {result.dependencies_list.map((dep: any, i: number) => (
                    <tr key={i}>
                      <td style={{ fontWeight: 600 }}>{dep.name}</td>
                      <td><span className="code-tag">{dep.version}</span></td>
                      <td><span style={{ fontSize: "12px", textTransform: "capitalize" }}>{dep.dep_type}</span></td>
                      <td>
                        {dep.has_vulnerabilities ? (
                          <span className="risk-pill high">Vulnerable ({dep.vulnerabilities_count})</span>
                        ) : dep.is_unpinned ? (
                          <span className="risk-pill medium">Unpinned</span>
                        ) : (
                          <span className="risk-pill low">Passed</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
