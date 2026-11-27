from typing import Dict, Any, List, Optional, Set
from app.services.capability_analysis.models import CapabilityCategory, CapabilityFinding
from app.services.capability_analysis.engine import CapabilityExtractionEngine

class CapabilityDeltaEngine:
    """
    Computes behavioural capability differences across package versions.
    Generates:
    - newly_introduced_capabilities
    - removed_capabilities
    - unchanged_capabilities
    - changed_capability_evidence
    """

    def __init__(self):
        self.extractor = CapabilityExtractionEngine()

    def compute_delta(
        self,
        base_files: Dict[str, str],
        target_files: Dict[str, str],
        base_meta: Optional[Dict[str, Any]] = None,
        target_meta: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        # Extract capabilities for both versions
        base_capabilities = self.extractor.extract_capabilities(base_files, base_meta)
        target_capabilities = self.extractor.extract_capabilities(target_files, target_meta)

        # Normalize capability identities by category
        # Category set for high-level classification
        base_categories: Set[str] = {c.category.value for c in base_capabilities}
        target_categories: Set[str] = {c.category.value for c in target_capabilities}

        new_categories = target_categories - base_categories
        removed_categories = base_categories - target_categories
        unchanged_categories = target_categories.intersection(base_categories)

        # Group findings by category
        base_by_cat: Dict[str, List[CapabilityFinding]] = {}
        for c in base_capabilities:
            base_by_cat.setdefault(c.category.value, []).append(c)

        target_by_cat: Dict[str, List[CapabilityFinding]] = {}
        for c in target_capabilities:
            target_by_cat.setdefault(c.category.value, []).append(c)

        # Detailed breakdown
        newly_introduced: List[Dict[str, Any]] = []
        for cat in new_categories:
            findings = target_by_cat.get(cat, [])
            newly_introduced.append({
                "category": cat,
                "capability_name": findings[0].capability_name if findings else cat,
                "confidence": findings[0].confidence if findings else "HIGH",
                "finding_count": len(findings),
                "introducing_files": list({f.file_path for f in findings}),
                "evidence_items": [f.to_dict() for f in findings]
            })

        removed: List[Dict[str, Any]] = []
        for cat in removed_categories:
            findings = base_by_cat.get(cat, [])
            removed.append({
                "category": cat,
                "capability_name": findings[0].capability_name if findings else cat,
                "finding_count": len(findings),
                "removed_from_files": list({f.file_path for f in findings})
            })

        unchanged: List[Dict[str, Any]] = []
        changed_evidence: List[Dict[str, Any]] = []

        for cat in unchanged_categories:
            b_findings = base_by_cat.get(cat, [])
            t_findings = target_by_cat.get(cat, [])

            b_files = {f.file_path for f in b_findings}
            t_files = {f.file_path for f in t_findings}

            entry = {
                "category": cat,
                "capability_name": t_findings[0].capability_name if t_findings else cat,
                "base_count": len(b_findings),
                "target_count": len(t_findings),
                "files": list(t_files)
            }
            unchanged.append(entry)

            # If introduced in new files even if category is unchanged overall
            new_files_for_cat = t_files - b_files
            if new_files_for_cat:
                changed_evidence.append({
                    "category": cat,
                    "newly_affected_files": list(new_files_for_cat),
                    "evidence_items": [f.to_dict() for f in t_findings if f.file_path in new_files_for_cat]
                })

        return {
            "summary": {
                "total_base_capabilities": len(base_categories),
                "total_target_capabilities": len(target_categories),
                "newly_introduced_count": len(new_categories),
                "removed_count": len(removed_categories),
                "unchanged_count": len(unchanged_categories)
            },
            "newly_introduced_categories": list(new_categories),
            "removed_categories": list(removed_categories),
            "unchanged_categories": list(unchanged_categories),
            "newly_introduced_capabilities": newly_introduced,
            "removed_capabilities": removed,
            "unchanged_capabilities": unchanged,
            "changed_capability_evidence": changed_evidence,
            "base_capabilities": [c.to_dict() for c in base_capabilities],
            "target_capabilities": [c.to_dict() for c in target_capabilities]
        }
