"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import {
  FileText,
  Download,
  Printer,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Bug,
  CheckCircle,
  ExternalLink,
  Search
} from "lucide-react";
import { api } from "@/lib/api";
import { Scan } from "@/types";

function ReportViewer() {
  const searchParams = useSearchParams();
  const initialScanId = searchParams.get("scan_id") || "";

  const [scanId, setScanId] = useState(initialScanId);
  const [report, setReport] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);

  useEffect(() => {
    api.listScans({ is_demo: false, limit: 15 }).then(setRecentScans).catch(console.error);
  }, []);

  const fetchReport = async (id: string) => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const data = await api.getScanReport(id);
      setReport(data);
    } catch (err: any) {
      setError(err.message || "Failed to load report.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (initialScanId) {
      fetchReport(initialScanId);
    } else if (recentScans.length > 0 && !report) {
      fetchReport(recentScans[0].id);
      setScanId(recentScans[0].id);
    }
  }, [initialScanId, recentScans]);

  const downloadJSON = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `OriginX_${report.package_identity?.name}_${report.package_identity?.version}_Report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Selector & Actions */}
      <div className="sg-card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "16px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px", flex: 1, maxWidth: "520px" }}>
            <span style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
              Select Assessment:
            </span>
            <select
              value={scanId}
              onChange={(e) => {
                setScanId(e.target.value);
                fetchReport(e.target.value);
              }}
              className="form-select"
              style={{ width: "100%" }}
            >
              <option value="">Choose an audited scan...</option>
              {recentScans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.package_name}@{s.version} ({s.ecosystem}) - {s.risk_classification} ({new Date(s.created_at).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>

          <div style={{ display: "flex", gap: "10px" }}>
            <button
              onClick={downloadJSON}
              disabled={!report}
              className="btn-secondary"
            >
              <Download size={14} />
              <span>Export JSON</span>
            </button>
            <button
              onClick={() => window.print()}
              disabled={!report}
              className="btn-primary"
            >
              <Printer size={14} />
              <span>Print Audit Document</span>
            </button>
          </div>
        </div>

        {error && (
          <div style={{ marginTop: "14px", padding: "10px", backgroundColor: "var(--risk-high-bg)", color: "var(--risk-high)", borderRadius: "var(--radius-sm)", fontSize: "12px" }}>
            {error}
          </div>
        )}
      </div>

      {/* Report Document Content */}
      {report ? (
        <div className="sg-card" style={{ padding: "32px", display: "flex", flexDirection: "column", gap: "24px" }}>
          {/* Header */}
          <div style={{ borderBottom: "1px solid var(--border-color)", paddingBottom: "20px", display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span className="code-tag" style={{ color: "var(--accent-primary)", fontSize: "12px" }}>{report.report_id}</span>
              </div>
              <h1 style={{ fontSize: "24px", fontWeight: 800, marginTop: "8px" }}>
                Supply Chain Risk Assessment Report
              </h1>
              <p style={{ fontSize: "14px", color: "var(--text-secondary)", marginTop: "4px" }}>
                Target: <strong style={{ color: "var(--text-primary)" }}>{report.package_identity.name}</strong> @ <strong style={{ color: "var(--text-primary)" }}>v{report.package_identity.version}</strong> ({report.package_identity.ecosystem})
              </p>
            </div>

            <div style={{ textAlign: "right" }}>
              <span className={`policy-badge ${report.risk_assessment.policy_decision.toLowerCase()}`} style={{ fontSize: "13px", padding: "6px 14px" }}>
                DECISION: {report.risk_assessment.policy_decision}
              </span>
              <div style={{ fontSize: "24px", fontWeight: 800, fontFamily: "var(--font-mono)", marginTop: "6px" }}>
                Score: {report.risk_assessment.score} <span style={{ fontSize: "14px", color: "var(--text-muted)" }}>/100</span>
              </div>
              <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                Generated: {new Date(report.generated_at).toLocaleString()}
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <div>
            <h3 style={{ fontSize: "13px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--accent-secondary)", marginBottom: "8px" }}>
              Executive Summary
            </h3>
            <p style={{ fontSize: "14px", lineHeight: "1.6", color: "var(--text-primary)", backgroundColor: "var(--bg-main)", padding: "16px", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-color)" }}>
              {report.executive_summary}
            </p>
          </div>

          {/* Recommendations */}
          <div>
            <h3 style={{ fontSize: "13px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--accent-primary)", marginBottom: "8px" }}>
              Recommended Security Actions
            </h3>
            {Array.isArray(report.recommendations) && report.recommendations.length > 0 ? (
              <ul style={{ paddingLeft: "20px", display: "flex", flexDirection: "column", gap: "6px", fontSize: "13px", color: "var(--text-primary)" }}>
                {report.recommendations.map((rec: string, i: number) => (
                  <li key={i}>{rec}</li>
                ))}
              </ul>
            ) : Array.isArray(report.recommended_steps) && report.recommended_steps.length > 0 ? (
              <ul style={{ paddingLeft: "20px", display: "flex", flexDirection: "column", gap: "6px", fontSize: "13px", color: "var(--text-primary)" }}>
                {report.recommended_steps.map((rec: string, i: number) => (
                  <li key={i}>{rec}</li>
                ))}
              </ul>
            ) : (
              <div style={{ padding: "12px 16px", backgroundColor: "var(--bg-main)", borderRadius: "var(--radius-sm)", border: "1px dashed var(--border-color)", fontSize: "13px", color: "var(--text-muted)" }}>
                No explicit remediation actions required for this assessment.
              </div>
            )}
          </div>

          {/* Static Findings Section */}
          <div>
            <h3 style={{ fontSize: "13px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--text-secondary)", marginBottom: "10px" }}>
              Static Analysis Threat Detections ({report.findings.length})
            </h3>
            {report.findings.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {report.findings.map((f: any) => (
                  <div key={f.id} style={{ padding: "14px", backgroundColor: "var(--bg-main)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-color)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                      <span className={`risk-pill ${f.severity.toLowerCase()}`}>{f.severity}</span>
                      <strong className="code-tag">{f.rule_id}</strong>
                      <span style={{ fontWeight: 600 }}>{f.title}</span>
                      {f.is_false_positive && <span style={{ color: "var(--text-muted)", fontSize: "11px" }}>[Dismissed FP]</span>}
                    </div>
                    <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "4px" }}>{f.explanation}</p>
                    {f.evidence_excerpt && (
                      <div className="diff-viewer" style={{ marginTop: "6px", padding: "6px 10px" }}>
                        <code>{f.evidence_excerpt}</code>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: "13px", color: "var(--text-muted)" }}>No static threat indicators detected.</div>
            )}
          </div>

          {/* Vulnerabilities Section */}
          <div>
            <h3 style={{ fontSize: "13px", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.5px", color: "var(--text-secondary)", marginBottom: "10px" }}>
              Known Vulnerability Intelligence ({report.vulnerabilities.length})
            </h3>
            {report.vulnerabilities.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {report.vulnerabilities.map((v: any, i: number) => (
                  <div key={i} style={{ padding: "14px", backgroundColor: "var(--bg-main)", borderRadius: "var(--radius-sm)", border: "1px solid var(--border-color)" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "4px" }}>
                      <span className={`risk-pill ${v.severity.toLowerCase()}`}>{v.severity}</span>
                      <strong className="code-tag">{v.vuln_id}</strong>
                    </div>
                    <p style={{ fontSize: "13px", color: "var(--text-secondary)" }}>{v.summary}</p>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: "13px", color: "var(--text-muted)" }}>Zero published CVEs or GHSAs found in OSV database.</div>
            )}
          </div>

          {/* Analysis Limitations & Skipped Checks */}
          <div style={{ borderTop: "1px solid var(--border-color)", paddingTop: "16px" }}>
            <h4 style={{ fontSize: "12px", color: "var(--text-muted)", textTransform: "uppercase", marginBottom: "6px" }}>
              Coverage Limitations & Verification Notes
            </h4>
            <ul style={{ paddingLeft: "18px", fontSize: "12px", color: "var(--text-muted)" }}>
              {report.limitations_and_skipped_checks.map((lim: string, i: number) => (
                <li key={i}>{lim}</li>
              ))}
            </ul>
          </div>
        </div>
      ) : (
        <div className="sg-card empty-state">
          <FileText size={36} className="empty-state-icon" />
          <div className="empty-state-title">No Assessment Report Selected</div>
          <p className="empty-state-desc">Choose a scan from the dropdown above or audit a package to generate a formal security report.</p>
        </div>
      )}
    </div>
  );
}

export default function SecurityReportsPage() {
  return (
    <Suspense fallback={<div className="sg-card empty-state">Loading report viewer...</div>}>
      <ReportViewer />
    </Suspense>
  );
}
