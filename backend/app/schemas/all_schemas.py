from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

class FindingBase(BaseModel):
    rule_id: str
    title: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    evidence_excerpt: Optional[str] = None
    explanation: str
    risk_reason: str
    confidence: str = "HIGH"  # LOW, MEDIUM, HIGH
    recommended_action: str
    is_false_positive: bool = False
    analyst_note: Optional[str] = None

class FindingResponse(FindingBase):
    id: str
    scan_id: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class VulnerabilityBase(BaseModel):
    vuln_id: str
    summary: Optional[str] = None
    details: Optional[str] = None
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    affected_range: Optional[str] = None
    fixed_version: Optional[str] = None
    source_url: Optional[str] = None
    published_at: Optional[str] = None

class VulnerabilityResponse(VulnerabilityBase):
    id: str
    scan_id: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class DependencyBase(BaseModel):
    name: str
    version: str
    dep_type: str = "direct"
    depth: int = 1
    has_vulnerabilities: bool = False

class DependencyResponse(DependencyBase):
    id: str
    scan_id: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class ScanCreateRequest(BaseModel):
    ecosystem: str = Field(...)
    package_name: str = Field(...)
    version: Optional[str] = Field("latest")
    compare_version: Optional[str] = Field(None)
    registry_url: Optional[str] = None

class ScanResponse(BaseModel):
    id: str
    package_name: str
    ecosystem: str
    version: str
    scan_type: str
    status: str
    stage: str
    risk_score: float
    risk_classification: str
    policy_decision: str
    policy_reasons: List[str] = []
    is_demo: bool = False
    coverage_summary: Dict[str, Any] = {}
    metadata_summary: Dict[str, Any] = {}
    duration_ms: int = 0
    error_message: Optional[str] = None
    created_at: datetime
    findings: List[FindingResponse] = []
    vulnerabilities: List[VulnerabilityResponse] = []
    dependencies: List[DependencyResponse] = []
    model_config = ConfigDict(from_attributes=True)

class VersionComparisonRequest(BaseModel):
    ecosystem: str
    package_name: str
    base_version: str
    target_version: str

class VersionComparisonResponse(BaseModel):
    id: str
    package_name: str
    ecosystem: str
    base_version: str
    target_version: str
    files_added_count: int
    files_removed_count: int
    files_modified_count: int
    deps_added_count: int
    deps_removed_count: int
    install_scripts_changed: bool
    summary_json: Dict[str, Any]
    diff_details_json: Dict[str, Any]
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class PolicyRule(BaseModel):
    id: str
    name: str
    description: str
    enabled: bool = True
    trigger_type: str  # vulnerability, install_script, code_pattern, integrity, maintainer_change
    action: str        # BLOCK, REVIEW, WARN

class PolicyModel(BaseModel):
    id: str
    name: str
    description: str
    rules: List[PolicyRule]
    is_active: bool = True
    version: str = "1.0.0"

class FalsePositiveUpdateRequest(BaseModel):
    is_false_positive: bool
    analyst_note: Optional[str] = None

class DashboardStatsResponse(BaseModel):
    total_scanned: int
    high_risk_findings: int
    medium_risk_findings: int
    known_vulnerabilities: int
    packages_requiring_review: int
    latest_scan_time: Optional[datetime] = None
    risk_distribution: Dict[str, int]
    is_demo_metrics: bool = False
