"use client";

import { useState } from "react";
import Link from "next/link";
import {
  Search,
  Upload,
  FileCode,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Bug,
  CheckCircle,
  FileText,
  Clock,
  ExternalLink
} from "lucide-react";
import { api } from "@/lib/api";
import { Scan, Finding } from "@/types";

export default function PackageScannerPage() {
  const [mode, setMode] = useState<"registry" | "archive">("registry");
  const [ecosystem, setEcosystem] = useState<"npm" | "pypi">("npm");
  const [packageName, setPackageName] = useState("lodash");
  const [packageVersion, setPackageVersion] = useState("4.17.21");
  const [archiveFile, setArchiveFile] = useState<File | null>(null);

  const [scanning, setScanning] = useState(false);
  const [scanStage, setScanStage] = useState<string>("");
  const [scanResult, setScanResult] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [activeTab, setActiveTab] = useState<"findings" | "vulnerabilities" | "dependencies" | "metadata">("findings");
  const [analystNotes, setAnalystNotes] = useState<Record<string, string>>({});

  const handleScanRegistry = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!packageName.trim()) return;

    setScanning(true);
    setError(null);
    setScanResult(null);
    setScanStage("Connecting to registry & resolving metadata...");

    try {
      setScanStage("Retrieving package metadata from public registry...");
      const res = await api.scanPackage({
        ecosystem,
        package_name: packageName.trim(),
        version: packageVersion.trim() || "latest"
      });
      setScanResult(res);
      setScanStage("Scan complete");
    } catch (err: any) {
      setError(err.message || "Failed to scan package.");
    } finally {
      setScanning(false);
    }
  };

  const handleScanArchive = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!archiveFile) return;

    setScanning(true);
    setError(null);
    setScanResult(null);
    setScanStage("Inspecting archive contents safely without execution...");

    try {
      const res = await api.scanArchive(archiveFile, ecosystem);
      setScanResult(res);
      setScanStage("Archive scan complete");
    } catch (err: any) {
      setError(err.message || "Failed to analyze archive.");
    } finally {
      setScanning(false);
    }
  };

  const toggleFalsePositive = async (finding: Finding) => {
    if (!scanResult) return;
    const newStatus = !finding.is_false_positive;
    const note = analystNotes[finding.id] || "Marked as false positive by security reviewer";

    try {
      const updated = await api.updateFinding(scanResult.id, finding.id, newStatus, note);
      setScanResult({
        ...scanResult,
        findings: scanResult.findings.map(f => f.id === finding.id ? updated : f)
      });
    } catch (err: any) {
      alert("Failed to update finding: " + err.message);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Mode Selector */}
      <div className="segmented-control">
        <button
          className={`segment-btn ${mode === "registry" ? "active" : ""}`}
          onClick={() => setMode("registry")}
        >
          <Search size={13} style={{ display: "inline", marginRight: "6px" }} />
          Registry Package Scan
        </button>
        <button
          className={`segment-btn ${mode === "archive" ? "active" : ""}`}
          onClick={() => setMode("archive")}
        >
          <Upload size={13} style={{ display: "inline", marginRight: "6px" }} />
          Upload Package Archive (.tgz, .tar.gz, .whl, .zip)
        </button>
      </div>

      {/* Input Form Card */}
      <div className="sg-card">
        {mode === "registry" ? (
          <form onSubmit={handleScanRegistry}>
            <div style={{ display: "grid", gridTemplateColumns: "140px 1fr 180px auto", gap: "14px", alignItems: "flex-end" }}>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Ecosystem</label>
                <select
                  value={ecosystem}
                  onChange={(e: any) => setEcosystem(e.target.value)}
                  className="form-select"
                >
                  <option value="npm">npm (JavaScript)</option>
                  <option value="pypi">PyPI (Python)</option>
                </select>
              </div>

              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Package Name</label>
                <input
                  type="text"
                  placeholder={ecosystem === "npm" ? "e.g. lodash or express" : "e.g. requests or numpy"}
                  value={packageName}
                  onChange={(e) => setPackageName(e.target.value)}
                  className="form-input"
                  required
                />
              </div>

              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Exact Version or &apos;latest&apos;</label>
                <input
                  type="text"
                  placeholder="e.g. 4.17.21 or latest"
                  value={packageVersion}
                  onChange={(e) => setPackageVersion(e.target.value)}
                  className="form-input"
                />
              </div>

              <button
                type="submit"
                disabled={scanning}
                className="btn-primary"
                style={{ height: "42px" }}
              >
                {scanning ? <Clock className="animate-spin" size={14} /> : <Search size={14} />}
                <span>{scanning ? "Scanning..." : "Scan Package"}</span>
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleScanArchive}>
            <div style={{ display: "grid", gridTemplateColumns: "140px 1fr auto", gap: "14px", alignItems: "flex-end" }}>
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
                <label className="form-label">Select Package Archive (.tgz, .tar.gz, .whl, .zip)</label>
                <input
                  type="file"
                  accept=".tgz,.tar.gz,.tar,.whl,.zip"
                  onChange={(e) => setArchiveFile(e.target.files?.[0] || null)}
                  className="form-input"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={scanning || !archiveFile}
                className="btn-primary"
                style={{ height: "42px" }}
              >
                <Upload size={14} />
                <span>{scanning ? "Analyzing..." : "Analyze Archive"}</span>
              </button>
            </div>
          </form>
        )}

        {/* Live scanning progress bar */}
        {scanning && (
          <div style={{ marginTop: "18px", padding: "14px", backgroundColor: "var(--bg-main)", borderRadius: "var(--radius-md)", border: "1px solid var(--border-color)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px", marginBottom: "6px" }}>
              <span style={{ color: "var(--accent-primary)", fontWeight: 600 }}>Active Scan in Progress</span>
              <span style={{ color: "var(--text-muted)" }}>Safe static analysis</span>
            </div>
            <div style={{ fontSize: "13px", color: "var(--text-primary)", marginBottom: "8px" }}>
              {scanStage}
            </div>
            <div style={{ height: "4px", backgroundColor: "var(--bg-elevated)", borderRadius: "2px", overflow: "hidden" }}>
              <div style={{ width: "70%", height: "100%", backgroundColor: "var(--accent-primary)", animation: "pulse 1.5s infinite" }} />
            </div>
          </div>
        )}

        {error && (
          <div style={{ marginTop: "16px", padding: "12px", backgroundColor: "var(--risk-high-bg)", border: "1px solid var(--risk-high)", borderRadius: "var(--radius-md)", color: "var(--text-primary)", fontSize: "13px" }}>
            <strong>Scan Error: </strong> {error}
          </div>
        )}
      </div>

      {/* Scan Results View */}
      {scanResult && (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* Header Banner */}
          <div className="sg-card" style={{
            borderLeft: `4px solid ${
              scanResult.risk_classification === "CRITICAL" ? "var(--risk-critical)" :
              scanResult.risk_classification === "HIGH" ? "var(--risk-high)" :
              scanResult.risk_classification === "MEDIUM" ? "var(--risk-medium)" : "var(--risk-low)"
            }`
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <h2 style={{ fontSize: "20px", fontWeight: 700 }}>{scanResult.package_name}</h2>
                  <span className="code-tag">v{scanResult.version}</span>
                  <span className="code-tag">{scanResult.ecosystem}</span>
                </div>
                <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "4px" }}>
                  {scanResult.metadata_summary?.description || "Package metadata inspected"}
                </p>
                <div style={{ display: "flex", gap: "16px", fontSize: "12px", color: "var(--text-muted)", marginTop: "8px" }}>
                  <span>License: <strong style={{ color: "var(--text-primary)" }}>{scanResult.metadata_summary?.license || "UNKNOWN"}</strong></span>
                  <span>Direct Dependencies: <strong style={{ color: "var(--text-primary)" }}>{scanResult.metadata_summary?.direct_dependencies_count ?? scanResult.dependencies?.length ?? 0}</strong></span>
                  <span>Duration: <strong style={{ color: "var(--text-primary)" }}>{scanResult.duration_ms}ms</strong></span>
                </div>
              </div>

              <div style={{ textAlign: "right" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", justifyContent: "flex-end" }}>
                  <span className={`risk-pill ${scanResult.risk_classification.toLowerCase()}`}>
                    {scanResult.risk_classification} RISK
                  </span>
                  <span className={`policy-badge ${scanResult.policy_decision.toLowerCase()}`}>
                    {scanResult.policy_decision}
                  </span>
                </div>
                <div style={{ fontSize: "28px", fontWeight: 800, fontFamily: "var(--font-mono)", marginTop: "4px", color: "var(--text-primary)" }}>
                  {scanResult.risk_score} <span style={{ fontSize: "14px", color: "var(--text-muted)" }}>/100</span>
                </div>
              </div>
            </div>

            {/* Policy Reasons */}
            {scanResult.policy_reasons && scanResult.policy_reasons.length > 0 && (
              <div style={{ marginTop: "14px", padding: "10px", backgroundColor: "var(--bg-main)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-color)" }}>
                <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                  Policy Assessment Rationale
                </div>
                <ul style={{ paddingLeft: "16px", marginTop: "4px", fontSize: "12px", color: "var(--text-secondary)" }}>
                  {scanResult.policy_reasons.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Result Subtabs */}
          <div className="segmented-control" style={{ width: "fit-content" }}>
            <button
              className={`segment-btn ${activeTab === "findings" ? "active" : ""}`}
              onClick={() => setActiveTab("findings")}
            >
              Static Findings ({scanResult.findings.length})
            </button>
            <button
              className={`segment-btn ${activeTab === "vulnerabilities" ? "active" : ""}`}
              onClick={() => setActiveTab("vulnerabilities")}
            >
              Known Vulnerabilities ({scanResult.vulnerabilities.length})
            </button>
            <button
              className={`segment-btn ${activeTab === "dependencies" ? "active" : ""}`}
              onClick={() => setActiveTab("dependencies")}
            >
              Dependencies ({scanResult.dependencies.length})
            </button>
            <button
              className={`segment-btn ${activeTab === "metadata" ? "active" : ""}`}
              onClick={() => setActiveTab("metadata")}
            >
              Metadata & Integrity
            </button>
          </div>

          {/* TAB 1: Static Findings */}
          {activeTab === "findings" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              {scanResult.findings.length > 0 ? (
                scanResult.findings.map((f) => (
                  <div
                    key={f.id}
                    className="sg-card"
                    style={{
                      opacity: f.is_false_positive ? 0.6 : 1,
                      backgroundColor: f.is_false_positive ? "var(--bg-main)" : "var(--bg-card)"
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <span className={`risk-pill ${f.severity.toLowerCase()}`}>{f.severity}</span>
                        <span className="code-tag">{f.rule_id}</span>
                        <span style={{ fontWeight: 600, fontSize: "14px" }}>{f.title}</span>
                        {f.is_false_positive && (
                          <span style={{ fontSize: "11px", color: "var(--text-muted)", fontStyle: "italic" }}>
                            [Dismissed as False Positive]
                          </span>
                        )}
                      </div>

                      <button
                        onClick={() => toggleFalsePositive(f)}
                        className="btn-secondary"
                        style={{ padding: "4px 10px", fontSize: "11px" }}
                      >
                        {f.is_false_positive ? "Reactivate Finding" : "Mark False Positive"}
                      </button>
                    </div>

                    <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "8px" }}>
                      {f.explanation}
                    </p>

                    {f.evidence_excerpt && (
                      <div style={{ marginBottom: "8px" }}>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)", marginBottom: "2px" }}>
                          Evidence ({f.file_path || "package"} {f.line_number ? `: line ${f.line_number}` : ""}):
                        </div>
                        <div className="diff-viewer" style={{ padding: "6px 12px" }}>
                          <code>{f.evidence_excerpt}</code>
                        </div>
                      </div>
                    )}

                    <div style={{ fontSize: "12px", color: "var(--text-muted)", display: "flex", gap: "16px" }}>
                      <span><strong>Risk:</strong> {f.risk_reason}</span>
                      <span><strong>Action:</strong> {f.recommended_action}</span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="sg-card empty-state">
                  <ShieldCheck size={36} className="empty-state-icon" color="var(--risk-low)" />
                  <div className="empty-state-title">Zero Suspicious Code Patterns Detected</div>
                  <p className="empty-state-desc">Static analysis completed without triggering any heuristic or AST threat rules.</p>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: Known Vulnerabilities */}
          {activeTab === "vulnerabilities" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              {scanResult.vulnerabilities.length > 0 ? (
                scanResult.vulnerabilities.map((v) => (
                  <div key={v.id} className="sg-card">
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "6px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <span className={`risk-pill ${v.severity.toLowerCase()}`}>{v.severity}</span>
                        <strong className="code-tag">{v.vuln_id}</strong>
                        {v.source_url && (
                          <a href={v.source_url} target="_blank" rel="noreferrer" style={{ display: "inline-flex", alignItems: "center", gap: "4px", fontSize: "12px", color: "var(--accent-secondary)" }}>
                            Advisory <ExternalLink size={12} />
                          </a>
                        )}
                      </div>
                    </div>
                    <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "6px" }}>
                      {v.summary || v.details || "Known vulnerability listed in OSV database."}
                    </p>
                    <div style={{ fontSize: "12px", color: "var(--text-muted)", display: "flex", gap: "16px" }}>
                      <span>Affected: <code className="code-tag">{v.affected_range || "Reported versions"}</code></span>
                      {v.fixed_version && <span>Fixed in: <strong style={{ color: "var(--risk-low)" }}>{v.fixed_version}</strong></span>}
                    </div>
                  </div>
                ))
              ) : (
                <div className="sg-card empty-state">
                  <Bug size={36} className="empty-state-icon" color="var(--risk-low)" />
                  <div className="empty-state-title">No Known Vulnerabilities Found</div>
                  <p className="empty-state-desc">OSV.dev query returned zero active CVEs or GHSAs for this exact version.</p>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: Dependencies */}
          {activeTab === "dependencies" && (
            <div className="sg-card">
              <div className="table-container">
                <table className="sg-table">
                  <thead>
                    <tr>
                      <th>Dependency Name</th>
                      <th>Version Specifier</th>
                      <th>Type</th>
                      <th>Vulnerabilities</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResult.dependencies.length > 0 ? (
                      scanResult.dependencies.map((d) => (
                        <tr key={d.id}>
                          <td style={{ fontWeight: 600 }}>{d.name}</td>
                          <td><span className="code-tag">{d.version}</span></td>
                          <td><span style={{ textTransform: "capitalize", fontSize: "12px" }}>{d.dep_type}</span></td>
                          <td>
                            {d.has_vulnerabilities ? (
                              <span className="risk-pill high">Vulnerable</span>
                            ) : (
                              <span className="risk-pill low">Passed</span>
                            )}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={4} style={{ textAlign: "center", color: "var(--text-muted)", padding: "24px" }}>
                          Package has zero direct dependencies declared.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB 4: Metadata & Integrity */}
          {activeTab === "metadata" && (
            <div className="sg-card" style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <h3 className="card-title">Distribution & Integrity Information</h3>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px", fontSize: "13px" }}>
                <div style={{ padding: "10px", backgroundColor: "var(--bg-main)", borderRadius: "var(--radius-sm)" }}>
                  <div style={{ color: "var(--text-muted)", fontSize: "11px" }}>Archive SHA256</div>
                  <div className="code-tag" style={{ marginTop: "4px", wordBreak: "break-all" }}>
                    {scanResult.metadata_summary?.sha256 || scanResult.coverage_summary?.sha256 || "Not computed"}
                  </div>
                </div>
                <div style={{ padding: "10px", backgroundColor: "var(--bg-main)", borderRadius: "var(--radius-sm)" }}>
                  <div style={{ color: "var(--text-muted)", fontSize: "11px" }}>Repository URL</div>
                  <div style={{ marginTop: "4px" }}>
                    {scanResult.metadata_summary?.repo_url ? (
                      <a href={scanResult.metadata_summary.repo_url} target="_blank" rel="noreferrer" style={{ color: "var(--accent-secondary)", display: "inline-flex", alignItems: "center", gap: "4px" }}>
                        {scanResult.metadata_summary.repo_url} <ExternalLink size={12} />
                      </a>
                    ) : "None declared"}
                  </div>
                </div>
              </div>

              {scanResult.metadata_summary?.lifecycle_scripts && Object.keys(scanResult.metadata_summary.lifecycle_scripts).length > 0 && (
                <div>
                  <h4 style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "6px" }}>Installation Lifecycle Scripts:</h4>
                  <div className="diff-viewer" style={{ padding: "10px" }}>
                    {Object.entries(scanResult.metadata_summary.lifecycle_scripts).map(([k, v]) => (
                      <div key={k}>
                        <span style={{ color: "var(--risk-high)" }}>&quot;{k}&quot;</span>: <span style={{ color: "var(--text-primary)" }}>&quot;{String(v)}&quot;</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
