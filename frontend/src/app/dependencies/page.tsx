"use client";

import { useEffect, useState } from "react";
import {
  Network,
  Search,
  Filter,
  AlertTriangle,
  Bug,
  ShieldCheck,
  CheckCircle,
  ExternalLink
} from "lucide-react";
import { api } from "@/lib/api";
import { Scan, Dependency } from "@/types";

export default function DependencyExplorerPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState<string>("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listScans({ limit: 20 })
      .then((data) => {
        setScans(data);
        if (data.length > 0) {
          setSelectedScanId(data[0].id);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const activeScan = scans.find(s => s.id === selectedScanId);
  const dependencies: Dependency[] = activeScan?.dependencies || [];

  const filteredDeps = dependencies.filter(d => {
    const matchesSearch = d.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = !filterType || d.dep_type === filterType;
    return matchesSearch && matchesType;
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Selector & Filter Card */}
      <div className="sg-card">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 160px", gap: "14px", alignItems: "flex-end" }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Select Assessed Package</label>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="form-select"
            >
              {scans.map(s => (
                <option key={s.id} value={s.id}>
                  {s.package_name}@{s.version} ({s.ecosystem}) - {s.dependencies?.length || 0} deps
                </option>
              ))}
            </select>
          </div>

          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Search Dependency</label>
            <input
              type="text"
              placeholder="Filter by dependency name..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="form-input"
            />
          </div>

          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Scope Filter</label>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="form-select"
            >
              <option value="">All Scopes</option>
              <option value="direct">Direct</option>
              <option value="transitive">Transitive</option>
              <option value="dev">Dev</option>
              <option value="optional">Optional</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Dependency Table & Graph */}
      <div className="sg-card">
        <div className="sg-card-header">
          <div>
            <h3 className="card-title">
              <Network size={16} /> Dependency Relationship Graph
            </h3>
            <p className="card-subtitle">
              Auditing {activeScan ? `${activeScan.package_name}@${activeScan.version}` : "package"} direct & transitive tree
            </p>
          </div>
          <span className="code-tag">{filteredDeps.length} items shown</span>
        </div>

        {filteredDeps.length > 0 ? (
          <div className="table-container">
            <table className="sg-table">
              <thead>
                <tr>
                  <th>Dependency Name</th>
                  <th>Version Specifier</th>
                  <th>Scope</th>
                  <th>Hierarchy Depth</th>
                  <th>Security Posture</th>
                </tr>
              </thead>
              <tbody>
                {filteredDeps.map((dep) => (
                  <tr key={dep.id}>
                    <td style={{ fontWeight: 600 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <span style={{ color: "var(--accent-secondary)" }}>•</span>
                        <span>{dep.name}</span>
                      </div>
                    </td>
                    <td>
                      <span className="code-tag">{dep.version}</span>
                    </td>
                    <td>
                      <span style={{ textTransform: "capitalize", fontSize: "12px", color: "var(--text-secondary)" }}>
                        {dep.dep_type}
                      </span>
                    </td>
                    <td>
                      <span className="code-tag" style={{ color: "var(--text-muted)" }}>Depth {dep.depth}</span>
                    </td>
                    <td>
                      {dep.has_vulnerabilities ? (
                        <span className="risk-pill high">Vulnerability Detected</span>
                      ) : (
                        <span className="risk-pill low">Verified Safe</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state" style={{ padding: "36px" }}>
            <ShieldCheck size={36} className="empty-state-icon" color="var(--risk-low)" />
            <div className="empty-state-title">No Dependencies to Display</div>
            <p className="empty-state-desc">
              {dependencies.length === 0
                ? "This package has zero declared sub-dependencies."
                : "No dependencies matched your search query."}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
