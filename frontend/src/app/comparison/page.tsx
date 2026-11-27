"use client";

import { useState } from "react";
import {
  GitCompare,
  Plus,
  Minus,
  FileText,
  AlertTriangle,
  Search,
  CheckCircle,
  FileCode,
  ArrowRight,
  Filter
} from "lucide-react";
import { api } from "@/lib/api";
import { VersionComparison } from "@/types";

export default function VersionComparisonPage() {
  const [ecosystem, setEcosystem] = useState<"npm" | "pypi">("npm");
  const [packageName, setPackageName] = useState("lodash");
  const [baseVersion, setBaseVersion] = useState("4.17.20");
  const [targetVersion, setTargetVersion] = useState("4.17.21");

  const [loading, setLoading] = useState(false);
  const [comparison, setComparison] = useState<VersionComparison | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [fileSearch, setFileSearch] = useState("");

  const handleCompare = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!packageName.trim() || !baseVersion.trim() || !targetVersion.trim()) return;

    setLoading(true);
    setError(null);
    setComparison(null);

    try {
      const res = await api.createComparison({
        ecosystem,
        package_name: packageName.trim(),
        base_version: baseVersion.trim(),
        target_version: targetVersion.trim()
      });
      setComparison(res);
      const diffs = res.diff_details_json?.file_diffs || [];
      if (diffs.length > 0) {
        setSelectedFile(diffs[0].file_path);
      }
    } catch (err: any) {
      setError(err.message || "Failed to compare versions.");
    } finally {
      setLoading(false);
    }
  };

  const fileDiffs = comparison?.diff_details_json?.file_diffs || [];
  const filteredDiffs = fileDiffs.filter((f: any) =>
    f.file_path.toLowerCase().includes(fileSearch.toLowerCase())
  );
  const activeDiff = fileDiffs.find((f: any) => f.file_path === selectedFile) || fileDiffs[0];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Compare Inputs Card */}
      <div className="sg-card">
        <form onSubmit={handleCompare}>
          <div style={{ display: "grid", gridTemplateColumns: "140px 1.5fr 1fr 1fr auto", gap: "14px", alignItems: "flex-end" }}>
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
                value={packageName}
                onChange={(e) => setPackageName(e.target.value)}
                className="form-input"
                placeholder="e.g. lodash"
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Base Version</label>
              <input
                type="text"
                value={baseVersion}
                onChange={(e) => setBaseVersion(e.target.value)}
                className="form-input"
                placeholder="e.g. 4.17.20"
                required
              />
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Target Version</label>
              <input
                type="text"
                value={targetVersion}
                onChange={(e) => setTargetVersion(e.target.value)}
                className="form-input"
                placeholder="e.g. 4.17.21"
                required
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary"
              style={{ height: "39px" }}
            >
              <GitCompare size={14} />
              <span>{loading ? "Comparing..." : "Compare Releases"}</span>
            </button>
          </div>
        </form>

        {error && (
          <div style={{ marginTop: "16px", padding: "12px", backgroundColor: "var(--risk-high-bg)", border: "1px solid var(--risk-high)", borderRadius: "var(--radius-md)", color: "var(--text-primary)", fontSize: "13px" }}>
            <strong>Comparison Error: </strong> {error}
          </div>
        )}
      </div>

      {/* Comparison Results */}
      {comparison && (
        <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
          {/* Summary Metric Cards */}
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "14px" }}>
            <div className="sg-card" style={{ padding: "16px" }}>
              <div className="card-subtitle">Files Added</div>
              <div style={{ fontSize: "24px", fontWeight: 700, color: "var(--risk-low)", marginTop: "4px" }}>
                +{comparison.files_added_count}
              </div>
            </div>

            <div className="sg-card" style={{ padding: "16px" }}>
              <div className="card-subtitle">Files Removed</div>
              <div style={{ fontSize: "24px", fontWeight: 700, color: "var(--risk-high)", marginTop: "4px" }}>
                -{comparison.files_removed_count}
              </div>
            </div>

            <div className="sg-card" style={{ padding: "16px" }}>
              <div className="card-subtitle">Files Modified</div>
              <div style={{ fontSize: "24px", fontWeight: 700, color: "var(--risk-medium)", marginTop: "4px" }}>
                {comparison.files_modified_count}
              </div>
            </div>

            <div className="sg-card" style={{ padding: "16px" }}>
              <div className="card-subtitle">Dependencies Added</div>
              <div style={{ fontSize: "24px", fontWeight: 700, color: "var(--accent-secondary)", marginTop: "4px" }}>
                +{comparison.deps_added_count}
              </div>
            </div>

            <div className="sg-card" style={{ padding: "16px" }}>
              <div className="card-subtitle">Install Scripts Changed</div>
              <div style={{ fontSize: "18px", fontWeight: 700, color: comparison.install_scripts_changed ? "var(--risk-high)" : "var(--risk-low)", marginTop: "6px" }}>
                {comparison.install_scripts_changed ? "MODIFIED" : "UNCHANGED"}
              </div>
            </div>
          </div>

          {/* Capabilities & Evidence Correlation Insights */}
          {comparison.diff_details_json?.correlations?.length > 0 && (
            <div className="sg-card" style={{ backgroundColor: "var(--bg-elevated)", border: "1px solid var(--risk-high)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--risk-high)", fontWeight: 600, fontSize: "14px" }}>
                <AlertTriangle size={18} />
                <span>Correlated Threat Patterns Detected ({comparison.diff_details_json.correlations.length})</span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginTop: "12px" }}>
                {comparison.diff_details_json.correlations.map((corr: any) => (
                  <div key={corr.correlation_id} style={{ padding: "10px", backgroundColor: "var(--bg-primary)", borderRadius: "var(--radius-sm)", borderLeft: "3px solid var(--risk-high)" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontWeight: 600, fontSize: "13px" }}>{corr.title}</span>
                      <span className="code-tag" style={{ fontSize: "11px", color: "var(--risk-high)" }}>{corr.severity} • {corr.confidence} CONFIDENCE</span>
                    </div>
                    <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px" }}>{corr.evidence_summary}</p>
                    <ul style={{ margin: "6px 0 0 16px", fontSize: "11px", color: "var(--text-muted)" }}>
                      {corr.reasoning.map((r: string, idx: number) => (
                        <li key={idx}>{r}</li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Behavioural Capabilities Changes */}
          {comparison.diff_details_json?.capabilities && (
            <div className="sg-card">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                <span style={{ fontWeight: 600, fontSize: "14px" }}>Behavioural Capability Evolution</span>
                <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                  +{comparison.diff_details_json.capabilities.summary.newly_introduced_count} new • -{comparison.diff_details_json.capabilities.summary.removed_count} removed
                </span>
              </div>

              {comparison.diff_details_json.capabilities.newly_introduced_capabilities.length > 0 ? (
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: "12px" }}>
                  {comparison.diff_details_json.capabilities.newly_introduced_capabilities.map((cap: any) => (
                    <div key={cap.category} style={{ padding: "12px", backgroundColor: "var(--bg-elevated)", border: "1px solid var(--accent-secondary)", borderRadius: "var(--radius-sm)" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontWeight: 600, fontSize: "12px", color: "var(--accent-secondary)" }}>{cap.capability_name}</span>
                        <span className="code-tag" style={{ fontSize: "10px" }}>NEW CAPABILITY</span>
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "6px" }}>
                        Detected in: {cap.introducing_files.join(", ")}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p style={{ fontSize: "12px", color: "var(--text-muted)" }}>No new behavioral capabilities introduced in this release.</p>
              )}
            </div>
          )}

          {/* Dependencies & Script changes highlights */}
          {(comparison.diff_details_json?.added_dependencies?.length > 0 ||
            comparison.diff_details_json?.added_scripts && Object.keys(comparison.diff_details_json.added_scripts).length > 0) && (
            <div className="sg-card" style={{ backgroundColor: "var(--bg-elevated)", border: "1px solid var(--risk-medium)" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "var(--risk-medium)", fontWeight: 600, fontSize: "13px" }}>
                <AlertTriangle size={16} />
                <span>Structural Changes Detected in Update</span>
              </div>
              <div style={{ marginTop: "10px", fontSize: "12px", color: "var(--text-secondary)" }}>
                {comparison.diff_details_json?.added_dependencies?.length > 0 && (
                  <p><strong>New Dependencies: </strong> {comparison.diff_details_json.added_dependencies.join(", ")}</p>
                )}
                {comparison.diff_details_json?.added_scripts && Object.keys(comparison.diff_details_json.added_scripts).length > 0 && (
                  <p style={{ marginTop: "4px" }}>
                    <strong>New Installation Scripts: </strong>
                    {Object.entries(comparison.diff_details_json.added_scripts).map(([k, v]) => (
                      <span key={k} className="code-tag" style={{ marginRight: "6px" }}>{k}: {String(v)}</span>
                    ))}
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Side-by-side Diff Viewer & File List */}
          <div style={{ display: "grid", gridTemplateColumns: "260px 1fr", gap: "16px", minHeight: "450px" }}>
            {/* File List */}
            <div className="sg-card" style={{ display: "flex", flexDirection: "column", gap: "10px", padding: "14px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", borderBottom: "1px solid var(--border-color)", paddingBottom: "10px" }}>
                <Filter size={14} color="var(--text-muted)" />
                <input
                  type="text"
                  placeholder="Filter modified files..."
                  value={fileSearch}
                  onChange={(e) => setFileSearch(e.target.value)}
                  className="form-input"
                  style={{ padding: "4px 8px", fontSize: "12px", width: "100%" }}
                />
              </div>

              <div style={{ overflowY: "auto", display: "flex", flexDirection: "column", gap: "4px" }}>
                {filteredDiffs.map((fd: any) => {
                  const isSelected = activeDiff?.file_path === fd.file_path;
                  return (
                    <button
                      key={fd.file_path}
                      onClick={() => setSelectedFile(fd.file_path)}
                      style={{
                        padding: "8px 10px",
                        textAlign: "left",
                        borderRadius: "var(--radius-sm)",
                        backgroundColor: isSelected ? "var(--bg-elevated)" : "transparent",
                        border: isSelected ? "1px solid var(--accent-secondary)" : "1px solid transparent",
                        color: isSelected ? "var(--accent-secondary)" : "var(--text-secondary)",
                        fontSize: "12px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center"
                      }}
                    >
                      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {fd.file_path}
                      </span>
                      <span style={{ fontSize: "10px", color: "var(--risk-low)" }}>
                        +{fd.total_added_lines}
                      </span>
                    </button>
                  );
                })}

                {filteredDiffs.length === 0 && (
                  <div style={{ fontSize: "12px", color: "var(--text-muted)", padding: "16px", textAlign: "center" }}>
                    No matching modified files found.
                  </div>
                )}
              </div>
            </div>

            {/* Diff Viewer Pane */}
            <div className="sg-card" style={{ padding: "14px", display: "flex", flexDirection: "column" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                <span className="code-tag" style={{ fontSize: "13px" }}>
                  {activeDiff?.file_path || "Select a file to inspect diff"}
                </span>
                {activeDiff && (
                  <div style={{ display: "flex", gap: "12px", fontSize: "12px" }}>
                    <span style={{ color: "var(--risk-low)", fontWeight: 600 }}>+{activeDiff.total_added_lines} lines</span>
                    <span style={{ color: "var(--risk-high)", fontWeight: 600 }}>-{activeDiff.total_removed_lines} lines</span>
                  </div>
                )}
              </div>

              {activeDiff ? (
                <div className="diff-viewer" style={{ flex: 1, padding: "10px" }}>
                  {activeDiff.diff_lines.map((line: string, i: number) => {
                    const isAdded = line.startsWith("+") && !line.startsWith("+++");
                    const isRemoved = line.startsWith("-") && !line.startsWith("---");
                    const isHeader = line.startsWith("@@") || line.startsWith("---") || line.startsWith("+++");
                    const lineClass = isAdded ? "added" : isRemoved ? "removed" : isHeader ? "header" : "";
                    return (
                      <div key={i} className={`diff-line ${lineClass}`}>
                        {line}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="empty-state" style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <p className="empty-state-desc">Select a file from the list to display side-by-side code changes.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
