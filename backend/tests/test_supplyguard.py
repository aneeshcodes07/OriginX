import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
import pytest_asyncio
import asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.models.base import init_db
from app.core.security import validate_package_identity, validate_outbound_url
from app.services.static_analysis.rules import STATIC_RULES
from app.services.static_analysis.engine import StaticAnalysisEngine
from app.services.dependency_analysis.parser import DependencyParser
from app.services.risk_engine.calculator import RiskEngine
from app.services.integrity.verifier import SafeArchiveInspector
from app.services.version_diff.comparator import VersionComparator
from app.services.demo.fixtures import DEMO_FIXTURES
from fastapi import HTTPException

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

# Unit Tests

def test_package_identity_validation_valid():
    validate_package_identity("npm", "lodash", "4.17.21")
    validate_package_identity("npm", "@angular/core", "16.0.0")
    validate_package_identity("pypi", "requests", "2.31.0")
    validate_package_identity("pypi", "scikit-learn", "1.3.0")

def test_package_identity_validation_invalid():
    with pytest.raises(HTTPException):
        validate_package_identity("unsupported_eco", "lodash")
    with pytest.raises(HTTPException):
        validate_package_identity("npm", "invalid name with spaces!")
    with pytest.raises(HTTPException):
        validate_package_identity("pypi", "pypi; injected_command")

def test_ssrf_protection():
    # Public allowed domains should pass
    valid_url = validate_outbound_url("https://registry.npmjs.org")
    assert "registry.npmjs.org" in valid_url

    # Localhost, private IP, or unknown domain should be blocked
    with pytest.raises(HTTPException):
        validate_outbound_url("http://127.0.0.1:8000/internal")
    with pytest.raises(HTTPException):
        validate_outbound_url("http://169.254.169.254/latest/meta-data")
    with pytest.raises(HTTPException):
        validate_outbound_url("https://evil-attacker-site.com")

def test_static_analysis_obfuscated_and_eval():
    engine = StaticAnalysisEngine()
    code = 'const s = Buffer.from("dmFyIGE9MTs=", "base64"); eval(s);'
    findings = engine.analyze_file_content("test.js", code)
    assert len(findings) > 0
    rule_ids = [f["rule_id"] for f in findings]
    assert "OBF-001" in rule_ids or "DYN-001" in rule_ids

def test_static_analysis_credential_harvesting():
    engine = StaticAnalysisEngine()
    code = 'const token = process.env.AWS_SECRET_ACCESS_KEY || fs.readFileSync("~/.ssh/id_rsa");'
    findings = engine.analyze_file_content("stealer.js", code)
    assert any(f["rule_id"] == "CRD-001" for f in findings)
    assert any(f["severity"] == "CRITICAL" for f in findings)

def test_static_analysis_python_ast():
    engine = StaticAnalysisEngine()
    py_code = 'import os\ndef run_cmd():\n    os.system("whoami")\n'
    findings = engine.analyze_file_content("test.py", py_code)
    assert len(findings) > 0
    assert any("AST-SUB-01" in f["rule_id"] or "SHL-001" in f["rule_id"] for f in findings)

def test_dependency_parser_package_json():
    content = '''{
      "name": "my-app",
      "dependencies": {
        "express": "^4.18.2",
        "loadash": "1.0.0",
        "wildcard-pkg": "*"
      }
    }'''
    res = DependencyParser.parse_manifest("package.json", content)
    assert res["ecosystem"] == "npm"
    assert res["total_dependencies"] == 3
    # "loadash" is a typosquat of "lodash"
    assert any("Potential typosquat" in str(iss) for iss in res["issues"])
    # "wildcard-pkg" is unpinned
    wildcard_dep = [d for d in res["dependencies"] if d["name"] == "wildcard-pkg"][0]
    assert wildcard_dep["is_unpinned"] is True

def test_risk_engine_calculation():
    engine = RiskEngine()
    # Harmless input
    score, classification, decision, reasons, _ = engine.calculate_risk(
        vulnerabilities=[],
        findings=[],
        metadata_findings=[],
        integrity_ok=True
    )
    assert score < 25.0
    assert classification == "LOW"
    assert decision == "ALLOW"

    # Critical vulnerability
    score, classification, decision, reasons, _ = engine.calculate_risk(
        vulnerabilities=[{"vuln_id": "GHSA-1234", "severity": "CRITICAL"}],
        findings=[],
        metadata_findings=[],
        integrity_ok=True
    )
    assert score >= 40.0
    assert decision in ["REVIEW", "BLOCK"]

def test_version_comparator():
    comparator = VersionComparator()
    base_meta = {
        "version": "1.0.0",
        "dependencies": {"a": "1.0.0"},
        "lifecycle_scripts": {}
    }
    target_meta = {
        "version": "1.1.0",
        "dependencies": {"a": "1.0.0", "b": "2.0.0"},
        "lifecycle_scripts": {"postinstall": "node setup.js"}
    }
    res = comparator.compare_versions(base_meta, target_meta)
    summary = res["summary"]
    assert summary["deps_added_count"] == 1
    assert summary["install_scripts_changed"] is True

# Integration API Tests

@pytest.mark.asyncio
async def test_api_health():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/v1/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "online"
        assert data["service"] in ["OriginX", "SupplyGuard"]

@pytest.mark.asyncio
async def test_demo_fixtures_endpoints():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. List fixtures
        r = await client.get("/api/v1/demo/fixtures")
        assert r.status_code == 200
        fixtures = r.json()
        assert len(fixtures) == 3

        # 2. Run Harmless Demo Package (Case A)
        r_a = await client.post("/api/v1/demo/run/case_a_normal")
        assert r_a.status_code == 200
        scan_a = r_a.json()
        assert scan_a["risk_classification"] == "LOW"
        assert scan_a["policy_decision"] == "ALLOW"
        assert scan_a["is_demo"] is True

        # 3. Run Suspicious Demo Package (Case C)
        r_c = await client.post("/api/v1/demo/run/case_c_suspicious_update")
        assert r_c.status_code == 200
        scan_c = r_c.json()
        assert scan_c["risk_classification"] in ["HIGH", "CRITICAL"]
        assert scan_c["policy_decision"] in ["REVIEW", "BLOCK"]
        assert len(scan_c["findings"]) > 0

        # 4. Verify History and Dashboard Stats
        r_stats = await client.get("/api/v1/history/stats?include_demo=true")
        assert r_stats.status_code == 200
        stats = r_stats.json()
        assert stats["total_scanned"] >= 2

        # 5. Purge Demo Data
        r_reset = await client.post("/api/v1/demo/reset")
        assert r_reset.status_code == 200
