import difflib
import json
from typing import Dict, Any, List, Optional
from app.services.static_analysis.engine import StaticAnalysisEngine
from app.services.capability_analysis.delta_engine import CapabilityDeltaEngine
from app.services.correlation.engine import EvidenceCorrelationEngine
from app.services.risk_engine.calculator import RiskEngine

class VersionComparator:
    def __init__(self):
        self.static_engine = StaticAnalysisEngine()
        self.delta_engine = CapabilityDeltaEngine()
        self.correlation_engine = EvidenceCorrelationEngine()
        self.risk_engine = RiskEngine()

    def compare_versions(
        self,
        base_meta: Dict[str, Any],
        target_meta: Dict[str, Any],
        base_files: Optional[Dict[str, str]] = None,
        target_files: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Calculates side-by-side comparison between two versions.
        Evaluates files, dependencies, lifecycle scripts, metadata, diffs,
        behavioural capabilities, evidence correlations, and risk scores.
        """
        # 1. Compare Dependencies
        base_deps = base_meta.get("dependencies", {})
        target_deps = target_meta.get("dependencies", {})
        
        added_deps = [d for d in target_deps if d not in base_deps]
        removed_deps = [d for d in base_deps if d not in target_deps]
        changed_deps = [
            {"name": d, "old_version": base_deps[d], "new_version": target_deps[d]}
            for d in target_deps if d in base_deps and target_deps[d] != base_deps[d]
        ]

        # 2. Compare Lifecycle Scripts
        base_scripts = base_meta.get("lifecycle_scripts", {})
        target_scripts = target_meta.get("lifecycle_scripts", {})
        
        added_scripts = {s: target_scripts[s] for s in target_scripts if s not in base_scripts}
        removed_scripts = {s: base_scripts[s] for s in base_scripts if s not in target_scripts}
        modified_scripts = {
            s: {"old": base_scripts[s], "new": target_scripts[s]}
            for s in target_scripts if s in base_scripts and target_scripts[s] != base_scripts[s]
        }
        install_scripts_changed = bool(added_scripts or modified_scripts)

        # 3. Compare Files (if file content available)
        base_files = base_files or {}
        target_files = target_files or {}

        # Normalize root version directories (e.g. PyPI tarballs have 'urllib3-1.26.4/...' vs 'urllib3-1.26.5/...')
        def strip_package_root(files_dict: Dict[str, str]) -> Dict[str, str]:
            if not files_dict:
                return {}
            keys = list(files_dict.keys())
            # Check if all files share a common single root folder prefix ending with '/'
            first_parts = [k.split("/", 1)[0] for k in keys if "/" in k]
            if first_parts and len(set(first_parts)) == 1 and len(first_parts) == len(keys):
                root_prefix = first_parts[0] + "/"
                return {k[len(root_prefix):]: v for k, v in files_dict.items()}
            return files_dict

        norm_base_files = strip_package_root(base_files)
        norm_target_files = strip_package_root(target_files)
        
        added_files = [f for f in norm_target_files if f not in norm_base_files]
        removed_files = [f for f in norm_base_files if f not in norm_target_files]
        modified_files = []
        file_diffs = []
        added_file_analyses = []
        all_new_findings = []

        # 3a. Analyse Newly Added Files
        for f in added_files:
            file_content = norm_target_files[f]
            findings = self.static_engine.analyze_file_content(f, file_content)
            total_lines = len(file_content.splitlines())
            
            analysis_entry = {
                "file_path": f,
                "total_lines": total_lines,
                "findings": findings
            }
            added_file_analyses.append(analysis_entry)
            all_new_findings.extend(findings)

        # 3b. Analyse Modified Files
        for f in norm_target_files:
            if f in norm_base_files:
                if norm_target_files[f] != norm_base_files[f]:
                    modified_files.append(f)
                    
                    base_content = norm_base_files[f]
                    target_content = norm_target_files[f]

                    # Generate line diff
                    base_lines = base_content.splitlines()
                    target_lines = target_content.splitlines()
                    diff = list(difflib.unified_diff(
                        base_lines,
                        target_lines,
                        fromfile=f"a/{f}",
                        tofile=f"b/{f}",
                        lineterm="",
                        n=3
                    ))

                    # 1. Analyse complete baseline file and complete target file
                    baseline_findings = self.static_engine.analyze_file_content(f, base_content)
                    target_findings = self.static_engine.analyze_file_content(f, target_content)

                    def normalize_evidence(ev: Optional[str]) -> str:
                        if not ev:
                            return ""
                        return "".join(ev.split()).lower()

                    baseline_signatures = {
                        (bf["rule_id"], normalize_evidence(bf.get("evidence_excerpt")))
                        for bf in baseline_findings
                    }

                    new_findings_in_file = []
                    preexisting_findings_in_file = []

                    for tf in target_findings:
                        sig = (tf["rule_id"], normalize_evidence(tf.get("evidence_excerpt")))
                        if sig in baseline_signatures:
                            preexisting_findings_in_file.append(tf)
                        else:
                            new_findings_in_file.append(tf)

                    all_new_findings.extend(new_findings_in_file)

                    file_diffs.append({
                        "file_path": f,
                        "diff_lines": diff[:150],  # cap diff view for performance
                        "total_added_lines": sum(1 for line in diff if line.startswith("+") and not line.startswith("+++")),
                        "total_removed_lines": sum(1 for line in diff if line.startswith("-") and not line.startswith("---")),
                        "new_findings": new_findings_in_file,
                        "preexisting_findings": preexisting_findings_in_file
                    })

        total_files = max(1, len(set(list(base_files.keys()) + list(target_files.keys()))))
        files_changed_count = len(added_files) + len(removed_files) + len(modified_files)
        change_percentage = round((files_changed_count / total_files) * 100, 1) if base_files or target_files else 0.0

        # 4. Behavioural Capability Extraction & Delta
        capability_delta = self.delta_engine.compute_delta(
            base_files=base_files,
            target_files=target_files,
            base_meta=base_meta,
            target_meta=target_meta
        )

        # 5. Evidence Correlation
        correlations = self.correlation_engine.correlate_signals(
            capabilities=capability_delta["target_capabilities"],
            new_capabilities=capability_delta["newly_introduced_capabilities"],
            static_findings=all_new_findings,
            vulnerabilities=[],
            metadata_findings=[],
            integrity_ok=True
        )

        # 6. Risk Scoring
        score, classification, decision, policy_reasons, breakdown = self.risk_engine.calculate_risk(
            vulnerabilities=[],
            findings=all_new_findings,
            metadata_findings=[],
            integrity_ok=True,
            correlations=correlations,
            new_capabilities=capability_delta["newly_introduced_capabilities"]
        )

        findings_by_severity = {
            "CRITICAL": sum(1 for f in all_new_findings if f.get("severity") == "CRITICAL"),
            "HIGH": sum(1 for f in all_new_findings if f.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for f in all_new_findings if f.get("severity") == "MEDIUM"),
            "LOW": sum(1 for f in all_new_findings if f.get("severity") == "LOW"),
            "INFO": sum(1 for f in all_new_findings if f.get("severity") == "INFO")
        }

        summary = {
            "base_version": base_meta.get("version"),
            "target_version": target_meta.get("version"),
            "files_added_count": len(added_files),
            "files_removed_count": len(removed_files),
            "files_modified_count": len(modified_files),
            "files_changed_percentage": change_percentage,
            "deps_added_count": len(added_deps),
            "deps_removed_count": len(removed_deps),
            "deps_changed_count": len(changed_deps),
            "install_scripts_changed": install_scripts_changed,
            "metadata_changes": {
                "license_changed": base_meta.get("license") != target_meta.get("license"),
                "base_license": base_meta.get("license"),
                "target_license": target_meta.get("license"),
                "author_changed": base_meta.get("author") != target_meta.get("author"),
                "repo_url_changed": base_meta.get("repo_url") != target_meta.get("repo_url")
            },
            "security_analysis": {
                "total_new_findings": len(all_new_findings),
                "findings_by_severity": findings_by_severity,
                "added_files_analyzed_count": len(added_files),
                "modified_files_analyzed_count": len(modified_files),
                "risk_score": score,
                "risk_classification": classification,
                "policy_decision": decision,
                "policy_reasons": policy_reasons,
                "model_version": breakdown["model_version"]
            },
            "capabilities_summary": capability_delta["summary"],
            "correlation_summary": {
                "total_correlations": len(correlations),
                "patterns": [c["pattern_type"] for c in correlations]
            }
        }

        diff_details = {
            "added_files": added_files,
            "removed_files": removed_files,
            "modified_files": modified_files,
            "added_dependencies": added_deps,
            "removed_dependencies": removed_deps,
            "changed_dependencies": changed_deps,
            "added_scripts": added_scripts,
            "modified_scripts": modified_scripts,
            "removed_scripts": removed_scripts,
            "file_diffs": file_diffs,
            "added_file_analyses": added_file_analyses,
            "new_findings": all_new_findings,
            "capabilities": capability_delta,
            "correlations": correlations,
            "risk_assessment": breakdown
        }

        return {
            "summary": summary,
            "diff_details": diff_details
        }
