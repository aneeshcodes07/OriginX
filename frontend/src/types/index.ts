export type Ecosystem = "npm" | "pypi";

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type PolicyDecision = "ALLOW" | "REVIEW" | "BLOCK";

export interface Finding {
  id: string;
  scan_id: string;
  rule_id: string;
  title: string;
  severity: "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  file_path?: string;
  line_number?: number;
  evidence_excerpt?: string;
  explanation: string;
  risk_reason: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  recommended_action: string;
  is_false_positive: boolean;
  analyst_note?: string;
  created_at?: string;
}

export interface Vulnerability {
  id: string;
  vuln_id: string;
  summary?: string;
  details?: string;
  severity: string;
  cvss_score?: number;
  affected_range?: string;
  fixed_version?: string;
  source_url?: string;
  published_at?: string;
}

export interface Dependency {
  id: string;
  name: string;
  version: string;
  dep_type: "direct" | "transitive" | "dev" | "optional" | "unresolved";
  depth: number;
  has_vulnerabilities: boolean;
}

export interface Scan {
  id: string;
  package_name: string;
  ecosystem: string;
  version: string;
  scan_type: "registry" | "archive" | "project" | "demo";
  status: "pending" | "running" | "completed" | "failed";
  stage: string;
  risk_score: number;
  risk_classification: RiskLevel;
  policy_decision: PolicyDecision;
  policy_reasons: string[];
  is_demo: boolean;
  coverage_summary: Record<string, any>;
  metadata_summary: Record<string, any>;
  duration_ms: number;
  error_message?: string;
  created_at: string;
  findings: Finding[];
  vulnerabilities: Vulnerability[];
  dependencies: Dependency[];
}

export interface DashboardStats {
  total_scanned: number;
  high_risk_findings: number;
  medium_risk_findings: number;
  known_vulnerabilities: number;
  packages_requiring_review: number;
  latest_scan_time?: string;
  risk_distribution: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
  is_demo_metrics: boolean;
}

export interface CapabilityFinding {
  capability_id: string;
  capability_name: string;
  category: string;
  file_path: string;
  line_number: number;
  evidence_excerpt: string;
  detection_method: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  explanation: string;
}

export interface CapabilityDelta {
  summary: {
    total_base_capabilities: number;
    total_target_capabilities: number;
    newly_introduced_count: number;
    removed_count: number;
    unchanged_count: number;
  };
  newly_introduced_categories: string[];
  removed_categories: string[];
  unchanged_categories: string[];
  newly_introduced_capabilities: Array<{
    category: string;
    capability_name: string;
    confidence: string;
    finding_count: number;
    introducing_files: string[];
    evidence_items: CapabilityFinding[];
  }>;
  removed_capabilities: Array<{
    category: string;
    capability_name: string;
    finding_count: number;
    removed_from_files: string[];
  }>;
  unchanged_capabilities: Array<{
    category: string;
    capability_name: string;
    base_count: number;
    target_count: number;
    files: string[];
  }>;
}

export interface EvidenceCorrelation {
  correlation_id: string;
  pattern_type: string;
  title: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  evidence_summary: string;
  related_signals: Array<Record<string, any>>;
  reasoning: string[];
}

export interface VersionComparison {
  id: string;
  package_name: string;
  ecosystem: string;
  base_version: string;
  target_version: string;
  files_added_count: number;
  files_removed_count: number;
  files_modified_count: number;
  deps_added_count: number;
  deps_removed_count: number;
  install_scripts_changed: boolean;
  summary_json: Record<string, any>;
  diff_details_json: Record<string, any>;
  created_at: string;
}

export interface DemoFixture {
  fixture_key: string;
  id: string;
  category: string;
  title: string;
  ecosystem: string;
  package_name: string;
  version: string;
  description: string;
  expected_result: string;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  trigger_type: string;
  action: "BLOCK" | "REVIEW" | "WARN";
  enabled: boolean;
  version?: string;
}

export interface SecurityReport {
  report_id: string;
  scan_id: string;
  generated_at?: string;
  is_demo_report?: boolean;
  executive_summary: string;
  package_identity: {
    name: string;
    ecosystem: string;
    version: string;
    scan_type: string;
    duration_ms: number;
  };
  risk_assessment: {
    score: number;
    classification: RiskLevel;
    policy_decision: PolicyDecision;
    policy_reasons: string[];
  };
  coverage_summary?: Record<string, any>;
  metadata_summary?: Record<string, any>;
  findings: Finding[];
  vulnerabilities: Vulnerability[];
  dependencies: Dependency[];
  recommendations: string[];
  recommended_steps?: string[];
}
