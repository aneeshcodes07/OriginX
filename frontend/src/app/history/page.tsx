"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  History,
  Search,
  Filter,
  Trash2,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  Clock,
  RefreshCw
} from "lucide-react";
import { api } from "@/lib/api";
import { Scan } from "@/types";

export default function ScanHistoryPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [ecosystem, setEcosystem] = useState<string>("");
  const [risk, setRisk] = useState<string>("");

  const fetchScans = async () => {
    setLoading(true);
    try {
      const data = await api.listScans({
        search: search || undefined,
        ecosystem: ecosystem || undefined,
        risk: risk || undefined,
        is_demo: false,
        limit: 100
      });
      setScans(data);
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [ecosystem, risk]);

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this scan record from database?")) return;
    try {
      await api.deleteScan(id);
      setScans(scans.filter(s => s.id !== id));
    } catch (err: any) {
      alert("Failed to delete scan: " + err.message);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Filters Card */}
      <div className="sg-card">
        <div style={{ display: "grid", gridTemplateColumns: "1.5fr 160px 160px auto", gap: "12px", alignItems: "center" }}>
          <div style={{ position: "relative" }}>
            <input
              type="text"
              placeholder="Search by package name..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") fetchScans(); }}
              className="form-input"
              style={{ width: "100%" }}
            />
          </div>

          <select
            value={ecosystem}
            onChange={(e) => setEcosystem(e.target.value)}
            className="form-select"
          >
            <option value="">All Ecosystems</option>
            <option value="npm">npm</option>
            <option value="pypi">PyPI</option>
          </select>

          <select
            value={risk}
            onChange={(e) => setRisk(e.target.value)}
            className="form-select"
          >
            <option value="">All Risk Levels</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <button onClick={fetchScans} className="btn-secondary" style={{ height: "42px" }}>
            <RefreshCw size={13} />
            <span>Apply Filter</span>
          </button>
        </div>
      </div>

      {/* History Table Card */}
      <div className="sg-card">
        <div className="sg-card-header">
          <div>
            <h3 className="card-title">Audit History</h3>
            <p className="card-subtitle">Showing {scans.length} verified package assessments</p>
          </div>
        </div>

        {loading ? (
          <div className="empty-state" style={{ padding: "40px" }}>
            <Clock size={32} className="empty-state-icon animate-spin" />
            <div className="empty-state-title">Loading history from database...</div>
          </div>
        ) : scans.length > 0 ? (
          <div className="table-container">
            <table className="sg-table">
              <thead>
                <tr>
                  <th>Scan ID</th>
                  <th>Package Name</th>
                  <th>Ecosystem</th>
                  <th>Version</th>
                  <th>Assessment Scope</th>
                  <th>Risk Score</th>
                  <th>Classification</th>
                  <th>Policy Decision</th>
                  <th>Duration</th>
                  <th>Timestamp</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((s) => (
                  <tr key={s.id}>
                    <td>
                      <span className="code-tag" style={{ fontSize: "11px" }}>{s.id.slice(0, 8)}...</span>
                    </td>
                    <td style={{ fontWeight: 600 }}>{s.package_name}</td>
                    <td><span className="code-tag">{s.ecosystem}</span></td>
                    <td><span className="code-tag">v{s.version}</span></td>
                    <td><span style={{ fontSize: "11px", textTransform: "capitalize", color: "var(--text-muted)" }}>{s.scan_type}</span></td>
                    <td>
                      <strong style={{ fontFamily: "var(--font-mono)", color: "var(--text-primary)" }}>{s.risk_score}</strong>
                    </td>
                    <td>
                      <span className={`risk-pill ${s.risk_classification.toLowerCase()}`}>
                        {s.risk_classification}
                      </span>
                    </td>
                    <td>
                      <span className={`policy-badge ${s.policy_decision.toLowerCase()}`}>
                        {s.policy_decision}
                      </span>
                    </td>
                    <td style={{ fontSize: "12px", color: "var(--text-muted)" }}>{s.duration_ms}ms</td>
                    <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                      {new Date(s.created_at).toLocaleString()}
                    </td>
                    <td>
                      <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                        <Link href={`/reports?scan_id=${s.id}`} className="btn-secondary" style={{ padding: "4px 10px", fontSize: "11px" }}>
                          Report
                        </Link>
                        <button
                          onClick={() => handleDelete(s.id)}
                          className="btn-secondary"
                          style={{ padding: "4px 8px", color: "var(--risk-critical)" }}
                          title="Delete Scan Record"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <History size={36} className="empty-state-icon" />
            <div className="empty-state-title">No Scan History Found</div>
            <p className="empty-state-desc">No records match your selected filters. Scan a package to generate an entry.</p>
          </div>
        )}
      </div>
    </div>
  );
}
