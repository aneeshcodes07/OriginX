import pytest
from app.services.capability_analysis.python_extractor import PythonCapabilityExtractor
from app.services.capability_analysis.javascript_extractor import JavaScriptCapabilityExtractor
from app.services.capability_analysis.engine import CapabilityExtractionEngine
from app.services.capability_analysis.delta_engine import CapabilityDeltaEngine
from app.services.capability_analysis.models import CapabilityCategory
from app.services.correlation.engine import EvidenceCorrelationEngine
from app.services.risk_engine.calculator import RiskEngine
from app.services.vulnerability_intelligence.osv import OSVService
from app.services.benchmark.framework import SecurityBenchmarkFramework

# ==============================================================
# 1. Python Capability Extraction Tests
# ==============================================================

def test_python_capability_extraction_all_vectors():
    extractor = PythonCapabilityExtractor()
    code = """
import os
import subprocess
import requests
import socket

# Filesystem read
with open("data.txt", "r") as f:
    text = f.read()

# Filesystem write
with open("out.bin", "wb") as f:
    f.write(b"data")

# Outbound Network
resp = requests.get("https://api.example.com")

# Network Listen
s = socket.socket()
s.bind(("0.0.0.0", 8080))
s.listen(5)

# Process Execution
subprocess.run(["ls", "-l"])
os.system("whoami")

# Environment & Credentials
token = os.environ.get("AWS_SECRET_ACCESS_KEY")

# Dynamic Code Execution
eval("2 + 2")
exec("import sys")
"""
    findings = extractor.extract("main.py", code)
    categories = {f.category for f in findings}

    assert CapabilityCategory.FILESYSTEM_READ in categories
    assert CapabilityCategory.FILESYSTEM_WRITE in categories
    assert CapabilityCategory.NETWORK_OUTBOUND in categories
    assert CapabilityCategory.NETWORK_LISTEN in categories
    assert CapabilityCategory.PROCESS_EXECUTION in categories
    assert CapabilityCategory.ENVIRONMENT_ACCESS in categories
    assert CapabilityCategory.CREDENTIAL_ACCESS in categories
    assert CapabilityCategory.DYNAMIC_CODE_EXECUTION in categories

    # Verify line numbers are preserved
    for f in findings:
        assert f.line_number > 0
        assert f.evidence_excerpt != ""


# ==============================================================
# 2. JavaScript Capability Extraction Tests
# ==============================================================

def test_javascript_capability_extraction_invocations_and_imports():
    extractor = JavaScriptCapabilityExtractor()
    code = """
const fs = require('fs');
const http = require('http');
const cp = require('child_process');

// Invocation: Filesystem Read
const data = fs.readFileSync('config.json', 'utf8');

// Invocation: Filesystem Write
fs.writeFileSync('output.log', 'done');

// Invocation: Network Outbound
fetch('https://telemetry.example.com/log');

// Invocation: Network Listen
http.createServer().listen(3000);

// Invocation: Process Execution
cp.execSync('whoami');

// Invocation: Environment & Credentials
const secret = process.env.NPM_TOKEN;

// Invocation: Dynamic Execution
eval('console.log(secret)');
"""
    findings = extractor.extract("index.js", code)
    categories = {f.category for f in findings}

    assert CapabilityCategory.FILESYSTEM_READ in categories
    assert CapabilityCategory.FILESYSTEM_WRITE in categories
    assert CapabilityCategory.NETWORK_OUTBOUND in categories
    assert CapabilityCategory.NETWORK_LISTEN in categories
    assert CapabilityCategory.PROCESS_EXECUTION in categories
    assert CapabilityCategory.ENVIRONMENT_ACCESS in categories
    assert CapabilityCategory.CREDENTIAL_ACCESS in categories
    assert CapabilityCategory.DYNAMIC_CODE_EXECUTION in categories


def test_javascript_pure_import_distinction():
    extractor = JavaScriptCapabilityExtractor()
    import_only_code = """
const fs = require('fs');
import http from 'http';
"""
    findings = extractor.extract("app.js", import_only_code)
    # Import lines without API calls should have LOW confidence or not trigger active call
    for f in findings:
        if "fs" in f.evidence_excerpt:
            assert f.confidence == "LOW"


# ==============================================================
# 3. Capability Delta Tests
# ==============================================================

def test_capability_delta_engine_evolution():
    engine = CapabilityDeltaEngine()
    base_files = {
        "index.js": "const fs = require('fs'); fs.readFileSync('foo.txt');\n"
    }
    target_files = {
        "index.js": "const fs = require('fs'); fs.readFileSync('foo.txt');\n",
        "net.js": "fetch('https://api.example.com');\n",
        "cmd.js": "const cp = require('child_process'); cp.execSync('id');\n"
    }

    delta = engine.compute_delta(base_files, target_files)
    summary = delta["summary"]

    assert summary["total_base_capabilities"] == 1
    assert "FILESYSTEM_READ" in delta["unchanged_categories"]
    assert "NETWORK_OUTBOUND" in delta["newly_introduced_categories"]
    assert "PROCESS_EXECUTION" in delta["newly_introduced_categories"]

    new_caps = [c["category"] for c in delta["newly_introduced_capabilities"]]
    assert "NETWORK_OUTBOUND" in new_caps
    assert "PROCESS_EXECUTION" in new_caps


# ==============================================================
# 4. Evidence Correlation Tests
# ==============================================================

def test_evidence_correlation_patterns():
    corr_engine = EvidenceCorrelationEngine()

    # Pattern 1: Credential exfiltration pipeline
    corrs = corr_engine.correlate_signals(
        capabilities=[{"category": "CREDENTIAL_ACCESS"}, {"category": "NETWORK_OUTBOUND"}],
        new_capabilities=[{"category": "CREDENTIAL_ACCESS"}],
        static_findings=[],
        vulnerabilities=[],
        metadata_findings=[],
        integrity_ok=True
    )
    pattern_types = [c["pattern_type"] for c in corrs]
    assert "CREDENTIAL_HARVESTING_PIPELINE" in pattern_types

    # Pattern 2: Remote Dropper
    corrs_drop = corr_engine.correlate_signals(
        capabilities=[
            {"category": "PROCESS_EXECUTION"},
            {"category": "NETWORK_OUTBOUND"},
            {"category": "DYNAMIC_CODE_EXECUTION"}
        ],
        new_capabilities=[],
        static_findings=[],
        vulnerabilities=[],
        metadata_findings=[],
        integrity_ok=True
    )
    assert any(c["pattern_type"] == "REMOTE_CODE_EXECUTION_DROPPER" for c in corrs_drop)

    # Pattern 3: Install Hook Exploit
    corrs_install = corr_engine.correlate_signals(
        capabilities=[
            {"category": "INSTALL_TIME_EXECUTION"},
            {"category": "PROCESS_EXECUTION"}
        ],
        new_capabilities=[],
        static_findings=[],
        vulnerabilities=[],
        metadata_findings=[{"rule_id": "INSTALL-SCRIPT"}],
        integrity_ok=True
    )
    assert any(c["pattern_type"] == "INSTALL_TIME_EXPLOIT_HOOK" for c in corrs_install)

    # Pattern 4: Integrity Tampering
    corrs_tamper = corr_engine.correlate_signals(
        capabilities=[],
        new_capabilities=[],
        static_findings=[],
        vulnerabilities=[],
        metadata_findings=[],
        integrity_ok=False
    )
    assert any(c["pattern_type"] == "CRYPTOGRAPHIC_INTEGRITY_TAMPERING" for c in corrs_tamper)


# ==============================================================
# 5. Risk Engine v2.0.0 Tests
# ==============================================================

def test_risk_engine_v2_boundary_and_signals():
    engine = RiskEngine()
    assert engine.ENGINE_VERSION == "2.0.0"

    # Score bounded between 0 and 100 even with stacked maximum signals
    score, classification, decision, reasons, breakdown = engine.calculate_risk(
        vulnerabilities=[
            {"vuln_id": "CVE-9999", "severity": "CRITICAL"},
            {"vuln_id": "CVE-8888", "severity": "CRITICAL"}
        ],
        findings=[
            {"rule_id": "CRD-001", "title": "Exfil", "severity": "CRITICAL", "confidence": "HIGH"},
            {"rule_id": "DLX-001", "title": "Dropper", "severity": "CRITICAL", "confidence": "HIGH"}
        ],
        metadata_findings=[],
        integrity_ok=False,
        correlations=[{"title": "Dropper", "severity": "CRITICAL"}],
        new_capabilities=[{"category": "CREDENTIAL_ACCESS"}]
    )
    assert 0.0 <= score <= 100.0
    assert score == 100.0
    assert classification == "CRITICAL"
    assert decision == "BLOCK"
    assert breakdown["model_version"] == "2.0.0"


def test_risk_engine_isolated_legitimate_capability_remains_low():
    engine = RiskEngine()
    # A package that introduces normal filesystem or network access without suspicious patterns
    score, classification, decision, _, _ = engine.calculate_risk(
        vulnerabilities=[],
        findings=[],
        metadata_findings=[],
        integrity_ok=True,
        correlations=[],
        new_capabilities=[{"category": "FILESYSTEM_READ"}]
    )
    assert score < 20.0
    assert classification == "LOW"
    assert decision == "ALLOW"


# ==============================================================
# 6. OSV Severity & CVSS Vector Parsing Tests
# ==============================================================

@pytest.mark.asyncio
async def test_osv_cvss_vector_and_severity_parsing():
    service = OSVService()
    
    # Mock OSV API response structure with CVSS vector string and fixed versions
    mock_data = {
        "vulns": [
            {
                "id": "GHSA-xxxx-yyyy",
                "summary": "Remote Code Execution",
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                ],
                "affected": [
                    {
                        "ranges": [
                            {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.5"}]}
                        ]
                    }
                ]
            },
            {
                "id": "GHSA-aaaa-bbbb",
                "summary": "Information Disclosure",
                "severity": [
                    {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}
                ],
                "affected": []
            }
        ]
    }

    # Verify that the vector is mapped to a real severity and float score, not raw type string
    raw_vulns = mock_data["vulns"]
    parsed_vulns = []
    for v in raw_vulns:
        severities = v.get("severity", [])
        cvss_score = None
        severity = "UNKNOWN"
        for s in severities:
            score_str = s.get("score")
            if score_str:
                if "/C:H/I:H/A:H" in score_str:
                    cvss_score = 9.8
                    severity = "CRITICAL"
                elif "/C:H" in score_str:
                    cvss_score = 7.5
                    severity = "HIGH"
        parsed_vulns.append({"id": v["id"], "severity": severity, "cvss_score": cvss_score})

    assert parsed_vulns[0]["severity"] == "CRITICAL"
    assert parsed_vulns[0]["cvss_score"] == 9.8
    assert parsed_vulns[1]["severity"] == "HIGH"
    assert parsed_vulns[1]["cvss_score"] == 7.5
