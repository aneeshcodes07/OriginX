import argparse
import asyncio
import os
import sys
import json

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.services.dependency_analysis.parser import DependencyParser
from app.services.vulnerability_intelligence.osv import OSVService
from app.services.registries.npm import NPMRegistryClient
from app.services.registries.pypi import PyPIRegistryClient
from app.services.static_analysis.engine import StaticAnalysisEngine
from app.services.risk_engine.calculator import RiskEngine

async def run_cli():
    parser = argparse.ArgumentParser(
        prog="originx",
        description="OriginX: Software Supply Chain Security Intelligence CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 'scan' command
    scan_parser = subparsers.add_parser("scan", help="Scan a package or manifest file")
    scan_parser.add_argument("target", help="Package name (e.g. 'lodash') or path to manifest (e.g. 'package.json')")
    scan_parser.add_argument("--ecosystem", choices=["npm", "pypi"], default="npm", help="Ecosystem when scanning a package name")
    scan_parser.add_argument("--version", default="latest", help="Version to scan (default: latest)")
    scan_parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(2)

    target = args.target

    # Case 1: Target is a manifest file on disk
    if os.path.isfile(target):
        try:
            with open(target, "r", encoding="utf-8") as f:
                content = f.read()
            parsed = DependencyParser.parse_manifest(os.path.basename(target), content)
            osv = OSVService()
            discovered_vulns = []
            
            for dep in parsed["dependencies"][:15]:
                name = dep["name"]
                ver = dep["version"].replace("^", "").replace("~", "").strip()
                if ver and ver != "*":
                    v_res = await osv.query_vulnerabilities(name, parsed["ecosystem"], ver)
                    discovered_vulns.extend(v_res.get("vulnerabilities", []))

            risk_eng = RiskEngine()
            score, classification, decision, reasons, _ = risk_eng.calculate_risk(
                vulnerabilities=discovered_vulns,
                findings=[],
                metadata_findings=[],
                integrity_ok=True
            )

            result = {
                "target": target,
                "type": "manifest",
                "ecosystem": parsed["ecosystem"],
                "dependencies_found": len(parsed["dependencies"]),
                "known_vulnerabilities_count": len(discovered_vulns),
                "risk_score": score,
                "risk_classification": classification,
                "policy_decision": decision,
                "reasons": reasons
            }

            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print("=" * 60)
                print(f"OriginX Scan Result: {target}")
                print(f"Ecosystem: {parsed['ecosystem']}")
                print(f"Dependencies: {len(parsed['dependencies'])}")
                print(f"Vulnerabilities: {len(discovered_vulns)}")
                print(f"Risk Score: {score}/100 ({classification})")
                print(f"Policy Decision: {decision}")
                if reasons:
                    print("Reasons:")
                    for r in reasons:
                        print(f"  - {r}")
                print("=" * 60)

            if decision == "BLOCK":
                sys.exit(1)
            sys.exit(0)

        except Exception as e:
            sys.stderr.write(f"Error scanning manifest: {str(e)}\n")
            sys.exit(2)

    # Case 2: Target is a package name
    else:
        try:
            if args.ecosystem == "npm":
                client = NPMRegistryClient()
                raw_meta = await client.get_package_metadata(target)
                v = client.resolve_version(raw_meta, args.version)
                details = client.extract_version_details(raw_meta, v)
            else:
                client = PyPIRegistryClient()
                raw_meta = await client.get_package_metadata(target)
                v = client.resolve_version(raw_meta, args.version)
                details = client.extract_version_details(raw_meta, v)

            osv = OSVService()
            v_res = await osv.query_vulnerabilities(target, args.ecosystem, v)
            vulns = v_res.get("vulnerabilities", [])

            risk_eng = RiskEngine()
            score, classification, decision, reasons, _ = risk_eng.calculate_risk(
                vulnerabilities=vulns,
                findings=[],
                metadata_findings=[],
                integrity_ok=True
            )

            res_obj = {
                "target": target,
                "version": v,
                "ecosystem": args.ecosystem,
                "license": details.get("license"),
                "dependencies_count": len(details.get("dependencies", {})),
                "vulnerabilities_count": len(vulns),
                "risk_score": score,
                "risk_classification": classification,
                "policy_decision": decision,
                "policy_reasons": reasons
            }

            if args.json:
                print(json.dumps(res_obj, indent=2))
            else:
                print("=" * 60)
                print(f"OriginX Package Scan: {target}@{v} ({args.ecosystem})")
                print(f"License: {details.get('license')}")
                print(f"Vulnerabilities: {len(vulns)}")
                print(f"Risk Score: {score}/100 ({classification})")
                print(f"Policy Decision: {decision}")
                if reasons:
                    print("Reasons:")
                    for r in reasons:
                        print(f"  - {r}")
                print("=" * 60)

            if decision == "BLOCK":
                sys.exit(1)
            sys.exit(0)

        except Exception as e:
            sys.stderr.write(f"Error scanning package: {str(e)}\n")
            sys.exit(2)

if __name__ == "__main__":
    asyncio.run(run_cli())
