"use client";

import { useEffect, useState } from "react";
import {
  Sliders,
  Shield,
  Bell,
  Eye,
  Check,
  Save,
  CheckCircle2
} from "lucide-react";

export default function UserPreferencesPage() {
  const [defaultEcosystem, setDefaultEcosystem] = useState<"npm" | "pypi">("npm");
  const [deepTraversal, setDeepTraversal] = useState(true);
  const [autoOsv, setAutoOsv] = useState(true);

  const [alertThreshold, setAlertThreshold] = useState<"all" | "high_critical" | "critical_only">("high_critical");
  const [typosquatSensitivity, setTyposquatSensitivity] = useState<"standard" | "strict">("strict");
  const [flagInstallScripts, setFlagInstallScripts] = useState(true);

  const [tableDensity, setTableDensity] = useState<"comfortable" | "compact">("comfortable");
  const [timeDisplay, setTimeDisplay] = useState<"local" | "utc">("local");
  const [theme, setTheme] = useState<string>("light");

  const [saved, setSaved] = useState(false);

  useEffect(() => {
    const savedTheme = localStorage.getItem("originx_theme") || localStorage.getItem("supplyguard_theme") || "dark";
    setTheme(savedTheme);
  }, []);

  const handleThemeChange = (newTheme: string) => {
    setTheme(newTheme);
    localStorage.setItem("originx_theme", newTheme);
    localStorage.setItem("supplyguard_theme", newTheme);
    document.documentElement.setAttribute("data-theme", newTheme);
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "24px", maxWidth: "860px" }}>
      {saved && (
        <div style={{
          padding: "12px 18px",
          backgroundColor: "var(--risk-low-bg)",
          border: "1px solid var(--risk-low)",
          borderRadius: "var(--radius-md)",
          color: "var(--risk-low)",
          fontSize: "13px",
          display: "flex",
          alignItems: "center",
          gap: "8px"
        }}>
          <CheckCircle2 size={16} />
          <span>User preferences have been successfully updated and applied.</span>
        </div>
      )}

      <form onSubmit={handleSave} style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
        {/* Section 1: Scanning Defaults */}
        <div className="sg-card">
          <div className="sg-card-header">
            <div>
              <h3 className="card-title">
                <Shield size={16} color="var(--accent-primary)" /> Scanning Scope & Defaults
              </h3>
              <p className="card-subtitle">Choose default parameters for new package and manifest scans</p>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Primary Ecosystem Preference</label>
              <select
                value={defaultEcosystem}
                onChange={(e: any) => setDefaultEcosystem(e.target.value)}
                className="form-select"
              >
                <option value="npm">npm / JavaScript</option>
                <option value="pypi">PyPI / Python</option>
              </select>
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Default Time Display</label>
              <select
                value={timeDisplay}
                onChange={(e: any) => setTimeDisplay(e.target.value)}
                className="form-select"
              >
                <option value="local">Local Timezone</option>
                <option value="utc">UTC (Coordinated Universal Time)</option>
              </select>
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "12px", borderTop: "1px solid var(--border-color)", paddingTop: "14px" }}>
            <label style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer", fontSize: "13px" }}>
              <div>
                <div style={{ fontWeight: 600 }}>Deep Transitive Dependency Traversal</div>
                <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>Automatically parse sub-dependency trees when lockfiles are provided</div>
              </div>
              <input
                type="checkbox"
                checked={deepTraversal}
                onChange={(e) => setDeepTraversal(e.target.checked)}
                style={{ width: "18px", height: "18px", accentColor: "var(--accent-primary)" }}
              />
            </label>

            <label style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer", fontSize: "13px" }}>
              <div>
                <div style={{ fontWeight: 600 }}>Live OSV.dev Intelligence Queries</div>
                <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>Automatically cross-reference scanned packages against open-source CVE databases</div>
              </div>
              <input
                type="checkbox"
                checked={autoOsv}
                onChange={(e) => setAutoOsv(e.target.checked)}
                style={{ width: "18px", height: "18px", accentColor: "var(--accent-primary)" }}
              />
            </label>
          </div>
        </div>

        {/* Section 2: Alert Sensitivities */}
        <div className="sg-card">
          <div className="sg-card-header">
            <div>
              <h3 className="card-title">
                <Bell size={16} color="var(--accent-secondary)" /> Alert Sensitivities & Threat Triggers
              </h3>
              <p className="card-subtitle">Configure when findings require mandatory security review</p>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Review Trigger Severity Threshold</label>
              <select
                value={alertThreshold}
                onChange={(e: any) => setAlertThreshold(e.target.value)}
                className="form-select"
              >
                <option value="high_critical">High & Critical Findings Only (Recommended)</option>
                <option value="critical_only">Critical Severity Only</option>
                <option value="all">All Findings (Strict Audit Mode)</option>
              </select>
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Typosquatting Detection Rigor</label>
              <select
                value={typosquatSensitivity}
                onChange={(e: any) => setTyposquatSensitivity(e.target.value)}
                className="form-select"
              >
                <option value="strict">Strict (Levenshtein distance &lt;= 2)</option>
                <option value="standard">Standard (Distance == 1 exact single-character)</option>
              </select>
            </div>
          </div>

          <div style={{ borderTop: "1px solid var(--border-color)", paddingTop: "14px" }}>
            <label style={{ display: "flex", alignItems: "center", justifyContent: "space-between", cursor: "pointer", fontSize: "13px" }}>
              <div>
                <div style={{ fontWeight: 600 }}>Highlight Lifecycle Scripts (preinstall / postinstall)</div>
                <div style={{ fontSize: "12px", color: "var(--text-muted)" }}>Warn whenever packages execute shell scripts during installation</div>
              </div>
              <input
                type="checkbox"
                checked={flagInstallScripts}
                onChange={(e) => setFlagInstallScripts(e.target.checked)}
                style={{ width: "18px", height: "18px", accentColor: "var(--accent-primary)" }}
              />
            </label>
          </div>
        </div>

        {/* Section 3: Interface & Display */}
        <div className="sg-card">
          <div className="sg-card-header">
            <div>
              <h3 className="card-title">
                <Eye size={16} color="var(--risk-low)" /> Workspace & Display Density
              </h3>
              <p className="card-subtitle">Adjust table layout density and report formatting</p>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Table Layout Density</label>
              <select
                value={tableDensity}
                onChange={(e: any) => setTableDensity(e.target.value)}
                className="form-select"
              >
                <option value="comfortable">Comfortable Spacing</option>
                <option value="compact">Compact (High-Density SOC)</option>
              </select>
            </div>

            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Color Theme</label>
              <select
                value={theme}
                onChange={(e) => handleThemeChange(e.target.value)}
                className="form-select"
              >
                <option value="light">Minimalist Light (Default)</option>
                <option value="dark">Minimalist Pitch Black</option>
              </select>
            </div>
          </div>
        </div>

        {/* Save Button */}
        <div>
          <button type="submit" className="btn-primary" style={{ padding: "11px 24px", fontSize: "14px" }}>
            <Save size={15} />
            <span>Save Preferences</span>
          </button>
        </div>
      </form>
    </div>
  );
}
