import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON
)
from sqlalchemy.orm import relationship
from app.models.base import Base

def get_utc_now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), default="analyst")  # analyst, admin
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=get_utc_now, index=True)

    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    owner_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    ecosystem = Column(String(32), nullable=False, default="npm", index=True)
    latest_risk_score = Column(Float, default=0.0)
    latest_decision = Column(String(32), default="ALLOW")
    created_at = Column(DateTime, default=get_utc_now, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now)

    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id = Column(String(36), nullable=True, index=True)
    package_name = Column(String(255), nullable=False, index=True)
    ecosystem = Column(String(32), nullable=False, index=True)
    version = Column(String(64), nullable=False)
    scan_type = Column(String(32), nullable=False, default="registry")  # registry, archive, project, demo
    status = Column(String(32), nullable=False, default="pending")      # pending, running, completed, failed
    stage = Column(String(128), default="Initializing scan")
    
    risk_score = Column(Float, default=0.0)
    risk_classification = Column(String(32), default="LOW")            # LOW, MEDIUM, HIGH, CRITICAL
    policy_decision = Column(String(32), default="ALLOW")              # ALLOW, REVIEW, BLOCK
    policy_reasons = Column(JSON, default=list)
    
    is_demo = Column(Boolean, default=False, index=True)
    coverage_summary = Column(JSON, default=dict)
    metadata_summary = Column(JSON, default=dict)
    
    duration_ms = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, index=True)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    dependencies = relationship("Dependency", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False, default="MEDIUM")  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    file_path = Column(String(512), nullable=True)
    line_number = Column(Integer, nullable=True)
    evidence_excerpt = Column(Text, nullable=True)
    explanation = Column(Text, nullable=False)
    risk_reason = Column(Text, nullable=False)
    confidence = Column(String(32), default="HIGH")                  # LOW, MEDIUM, HIGH
    recommended_action = Column(Text, nullable=False)
    is_false_positive = Column(Boolean, default=False)
    analyst_note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now)

    scan = relationship("Scan", back_populates="findings")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    vuln_id = Column(String(64), nullable=False, index=True)         # GHSA-..., CVE-..., OSV-...
    summary = Column(Text, nullable=True)
    details = Column(Text, nullable=True)
    severity = Column(String(32), default="UNKNOWN")
    cvss_score = Column(Float, nullable=True)
    affected_range = Column(String(255), nullable=True)
    fixed_version = Column(String(64), nullable=True)
    source_url = Column(String(512), nullable=True)
    published_at = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=get_utc_now)

    scan = relationship("Scan", back_populates="vulnerabilities")


class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(64), nullable=False)
    dep_type = Column(String(32), default="direct")                  # direct, transitive, dev, optional, unresolved
    depth = Column(Integer, default=1)
    has_vulnerabilities = Column(Boolean, default=False)
    created_at = Column(DateTime, default=get_utc_now)

    scan = relationship("Scan", back_populates="dependencies")


class VersionComparison(Base):
    __tablename__ = "version_comparisons"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id = Column(String(36), nullable=True, index=True)
    package_name = Column(String(255), nullable=False, index=True)
    ecosystem = Column(String(32), nullable=False, index=True)
    base_version = Column(String(64), nullable=False)
    target_version = Column(String(64), nullable=False)
    
    files_added_count = Column(Integer, default=0)
    files_removed_count = Column(Integer, default=0)
    files_modified_count = Column(Integer, default=0)
    deps_added_count = Column(Integer, default=0)
    deps_removed_count = Column(Integer, default=0)
    install_scripts_changed = Column(Boolean, default=False)
    
    summary_json = Column(JSON, default=dict)
    diff_details_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=get_utc_now, index=True)


class Policy(Base):
    __tablename__ = "policies"

    id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    trigger_type = Column(String(64), nullable=False, default="vulnerability")
    action = Column(String(32), nullable=False, default="BLOCK")  # ALLOW, REVIEW, BLOCK
    is_active = Column(Boolean, default=True)
    version = Column(String(32), default="2.0.0")
    rules_json = Column(JSON, default=dict)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    event_type = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), nullable=False, default="system", index=True)
    action = Column(String(128), nullable=False)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(64), nullable=True, index=True)
    details_json = Column(JSON, default=dict)
    ip_address = Column(String(64), nullable=True)
    timestamp = Column(DateTime, default=get_utc_now, index=True)
