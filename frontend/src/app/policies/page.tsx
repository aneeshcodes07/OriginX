"use client";

import { useEffect, useState } from "react";
import {
  Sliders,
  CheckCircle,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  RefreshCw,
  Info
} from "lucide-react";
import { api } from "@/lib/api";
import { PolicyRule } from "@/types";

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchPolicies = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getPolicies();
      setPolicies(Array.isArray(data) ? data : []);
    } catch (err: any) {
      console.error("Failed to fetch policies:", err);
      setError(err.message || "Failed to load automated security policies.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleToggle = async (policyId: string) => {
    try {
      await api.togglePolicy(policyId);
      setPolicies(policies.map(p => p.id === policyId ? { ...p, enabled: !p.enabled } : p));
    } catch (err: any) {
      alert("Failed to toggle policy: " + err.message);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
      {/* Intro Card */}
      <div className="sg-card">
        <div className="sg-card-header">
          <div>
            <h3 className="card-title">
              <Sliders size={16} /> Automated Supply Chain Security Policies
            </h3>
            <p className="card-subtitle">
              Configure risk evaluation thresholds and automatic policy outcomes (ALLOW, REVIEW, BLOCK)
            </p>
          </div>
          <span className="code-tag">Active Engine: v2.0.0</span>
        </div>
        <p style={{ fontSize: "13px", color: "var(--text-secondary)", lineHeight: "1.6" }}>
          OriginX policies evaluate verifiable signals extracted during static inspection, metadata analysis,
          and OSV intelligence queries. Enabled rules enforce conservative security postures across CI/CD and developer workflows.
        </p>
      </div>

      {/* Error state if backend unreachable */}
      {error && (
        <div className="sg-card" style={{ borderColor: "var(--risk-critical-border)", backgroundColor: "var(--risk-critical-bg)", padding: "18px 24px" }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <AlertTriangle size={18} color="var(--risk-critical)" />
              <div>
                <strong style={{ fontSize: "14px", color: "var(--risk-critical)" }}>Connection Error</strong>
                <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginTop: "2px" }}>{error}</p>
              </div>
            </div>
            <button onClick={fetchPolicies} className="btn-secondary" style={{ padding: "6px 14px", display: "inline-flex", alignItems: "center", gap: "6px" }}>
              <RefreshCw size={13} />
              <span>Retry</span>
            </button>
          </div>
        </div>
      )}

      {/* Loading state */}
      {loading && !error && (
        <div className="sg-card" style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
          <RefreshCw className="animate-spin" size={24} style={{ margin: "0 auto 12px" }} />
          <p>Retrieving active security policies from OriginX engine...</p>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && policies.length === 0 && (
        <div className="sg-card" style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
          <Info size={24} style={{ margin: "0 auto 12px", color: "var(--accent-secondary)" }} />
          <p>No security policies configured in the database.</p>
        </div>
      )}

      {/* Policy Rules List */}
      {!loading && !error && policies.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          {policies.map((p) => (
            <div key={p.id} className="sg-card" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                  <span className="code-tag">{p.id}</span>
                  <span className={`policy-badge ${p.action.toLowerCase()}`}>{p.action}</span>
                  <strong style={{ fontSize: "14px" }}>{p.name}</strong>
                </div>
                <p style={{ fontSize: "13px", color: "var(--text-secondary)", maxWidth: "650px" }}>
                  {p.description}
                </p>
              </div>

              <button
                onClick={() => handleToggle(p.id)}
                className={p.enabled ? "btn-primary" : "btn-secondary"}
                style={{ padding: "6px 16px" }}
              >
                {p.enabled ? "Enabled" : "Disabled"}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
