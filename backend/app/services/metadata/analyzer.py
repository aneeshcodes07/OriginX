from typing import Dict, Any, List, Optional
from datetime import datetime
from dateutil import parser as date_parser

class MetadataAnalyzer:
    def analyze_metadata(
        self,
        details: Dict[str, Any],
        ecosystem: str
    ) -> List[Dict[str, Any]]:
        findings = []
        
        # 1. Check Missing Repository
        repo_url = details.get("repo_url")
        if not repo_url or str(repo_url).strip() in ["", "null", "none"]:
            findings.append({
                "rule_id": "META-NO-REPO",
                "title": "Missing or Unlinked Source Code Repository",
                "severity": "LOW",
                "evidence_excerpt": "repository: null / unconfigured",
                "explanation": "Package metadata does not declare a public source code repository (GitHub, GitLab, etc.).",
                "risk_reason": "While some packages omit repository links legitimately, absence of verifiable public source code reduces provenance auditability.",
                "confidence": "HIGH",
                "recommended_action": "Verify if the package publisher provides a legitimate independent source repository."
            })
            
        # 2. Check License
        license_str = str(details.get("license") or "UNKNOWN").upper()
        if license_str in ["UNLICENSED", "UNKNOWN", "SEE LICENSE IN LICENSE"]:
            findings.append({
                "rule_id": "META-UNLICENSED",
                "title": "Unclear or Unlicensed Distribution",
                "severity": "INFO",
                "evidence_excerpt": f"license: {details.get('license')}",
                "explanation": "Package has no standard SPDX license declared.",
                "risk_reason": "Unlicensed packages can introduce legal and compliance exposure in enterprise environments.",
                "confidence": "HIGH",
                "recommended_action": "Check the root LICENSE file in the package archive."
            })

        # 3. Check Dormancy / Timing Anomaly
        published_at_str = details.get("published_at")
        all_versions = details.get("all_versions", [])
        if published_at_str and len(all_versions) > 1:
            try:
                current_pub = date_parser.parse(published_at_str)
                # If we have time map (npm provides time per version)
                time_map = details.get("time_map") or {}
                if time_map:
                    # Find previous version timestamp
                    prev_versions = [v for v in all_versions if v != details.get("version")]
                    if prev_versions:
                        last_v = prev_versions[-1]
                        last_v_time_str = time_map.get(last_v)
                        if last_v_time_str:
                            prev_pub = date_parser.parse(last_v_time_str)
                            dormant_days = (current_pub - prev_pub).days
                            if dormant_days > 730:  # > 2 years dormant
                                findings.append({
                                    "rule_id": "META-DORMANT-REVIVAL",
                                    "title": f"Dormant Package Revival (> {dormant_days} days inactive)",
                                    "severity": "MEDIUM",
                                    "evidence_excerpt": f"Previous release: {last_v} ({last_v_time_str[:10]}), New release after {dormant_days} days of dormancy",
                                    "explanation": f"Package was dormant for over {dormant_days // 365} years before this release.",
                                    "risk_reason": "Account takeovers frequently target long-unmaintained packages with existing download volumes.",
                                    "confidence": "MEDIUM",
                                    "recommended_action": "Carefully inspect release notes and changes between versions for account takeover signs."
                                })
            except Exception:
                pass

        # 4. Check Sudden Dependency Count
        deps = details.get("dependencies", {})
        if len(deps) > 25:
            findings.append({
                "rule_id": "META-HEAVY-DEPS",
                "title": f"High Direct Dependency Count ({len(deps)} direct dependencies)",
                "severity": "LOW",
                "evidence_excerpt": f"{len(deps)} direct dependencies declared",
                "explanation": "Package introduces an unusually high number of direct dependencies.",
                "risk_reason": "Large dependency graphs expand the software supply-chain attack surface.",
                "confidence": "HIGH",
                "recommended_action": "Audit sub-dependencies for vulnerability and maintainer reputation."
            })
            
        # 5. Check Lifecycle scripts (npm)
        scripts = details.get("lifecycle_scripts", {})
        if scripts:
            for s_name, s_cmd in scripts.items():
                findings.append({
                    "rule_id": "META-INSTALL-SCRIPT",
                    "title": f"Installation-Time Lifecycle Hook Present ('{s_name}')",
                    "severity": "HIGH",
                    "evidence_excerpt": f'"{s_name}": "{s_cmd}"',
                    "explanation": f"Package executes system command during install hook '{s_name}'.",
                    "risk_reason": "Automatic installation scripts run with developer/CI privileges upon package install.",
                    "confidence": "HIGH",
                    "recommended_action": "Review script commands to verify necessity. Run installation with '--ignore-scripts' in CI."
                })

        return findings
