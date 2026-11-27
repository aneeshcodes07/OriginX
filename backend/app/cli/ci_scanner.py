import argparse
import json
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from app.services.dependency_analysis.parser import DependencyParser
from app.services.risk_engine.calculator import RiskEngine

def main():
    parser = argparse.ArgumentParser(description="OriginX CI/CD Scanner CLI")
    parser.add_argument("--manifest", required=True, help="Path to manifest (package.json, requirements.txt)")
    parser.add_argument("--policy-fail", default="BLOCK", choices=["BLOCK", "REVIEW"], help="Exit with non-zero on policy outcome")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"[!] Error: Manifest '{args.manifest}' does not exist.")
        sys.exit(1)

    with open(manifest_path, "r", encoding="utf-8") as f:
        content = f.read()

    print(f"[*] OriginX scanning manifest: {manifest_path.name}")
    parsed = DependencyParser.parse_manifest(manifest_path.name, content)

    print(f"[+] Discovered {parsed.get('total_dependencies', 0)} dependencies.")
    issues = parsed.get("issues", [])
    if issues:
        print(f"[!] Identified {len(issues)} structural manifest issues:")
        for iss in issues:
            print(f"    - {iss}")

    # Calculate policy assessment
    engine = RiskEngine()
    score, classification, decision, reasons, breakdown = engine.calculate_risk(
        vulnerabilities=[],
        findings=[],
        metadata_findings=[{"rule_id": "DEP-UNPINNED", "title": iss, "severity": "MEDIUM", "evidence_excerpt": iss} for iss in issues],
        integrity_ok=True
    )

    report = {
        "manifest": str(manifest_path),
        "total_dependencies": parsed.get("total_dependencies", 0),
        "issues": issues,
        "risk_score": score,
        "classification": classification,
        "decision": decision,
        "reasons": reasons,
        "breakdown": breakdown
    }

    report_file = Path("originx-report.json")
    with open(report_file, "w", encoding="utf-8") as rf:
        json.dump(report, rf, indent=2)

    print(f"[+] Saved scan report to {report_file.resolve()}")
    print(f"[*] OriginX Policy Decision: {decision} (Score: {score}/100, Class: {classification})")

    if args.policy_fail == "BLOCK" and decision == "BLOCK":
        print("[X] CI Gate Failed: OriginX policy evaluated to BLOCK.")
        sys.exit(1)
    elif args.policy_fail == "REVIEW" and decision in ["BLOCK", "REVIEW"]:
        print("[X] CI Gate Failed: OriginX policy evaluated to REVIEW or BLOCK.")
        sys.exit(1)

    print("[✓] CI Gate Passed: No blocking supply-chain risks detected.")
    sys.exit(0)

if __name__ == "__main__":
    main()
