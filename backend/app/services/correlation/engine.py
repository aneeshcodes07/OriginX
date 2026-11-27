import uuid
from typing import Dict, Any, List, Optional

class EvidenceCorrelationEngine:
    """
    Combines independent security signals into explainable correlation narratives.
    Identifies multi-vector threat patterns:
    - Credential Stealer: Credential Access + Outbound Network (+ Dormant/Maintainer anomaly)
    - Dropper / Reverse Shell: Process Execution + Outbound Network + Dynamic Code Execution
    - Supply-Chain Trojan: Install Hook + Binary Execution or Shell Spawning
    - Tampering: Hash Integrity Failure + Unsigned / New release
    """

    def correlate_signals(
        self,
        capabilities: List[Dict[str, Any]],
        new_capabilities: List[Dict[str, Any]],
        static_findings: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]],
        metadata_findings: List[Dict[str, Any]],
        integrity_ok: bool = True
    ) -> List[Dict[str, Any]]:
        correlations: List[Dict[str, Any]] = []

        all_cap_cats = {c.get("category") for c in capabilities}
        new_cap_cats = {c.get("category") for c in new_capabilities}
        static_rule_ids = {f.get("rule_id") for f in static_findings if not f.get("is_false_positive")}

        # 1. Pattern: Credential Harvesting & Exfiltration Pipeline
        has_cred = "CREDENTIAL_ACCESS" in all_cap_cats or "CRD-001" in static_rule_ids
        has_net = "NETWORK_OUTBOUND" in all_cap_cats or "NET-001" in static_rule_ids
        is_new_cred = "CREDENTIAL_ACCESS" in new_cap_cats

        if has_cred and has_net:
            reasoning = [
                "Package contains code accessing system/cloud credentials or secret tokens.",
                "Package initiates outbound network or socket connections."
            ]
            conf = "HIGH" if is_new_cred else "MEDIUM"
            if is_new_cred:
                reasoning.append("Credential access capability was newly introduced in this release.")

            correlations.append({
                "correlation_id": f"CORR-EXFIL-{uuid.uuid4().hex[:8]}",
                "pattern_type": "CREDENTIAL_HARVESTING_PIPELINE",
                "title": "Potential Credential Harvesting & Exfiltration Channel",
                "confidence": conf,
                "severity": "CRITICAL" if is_new_cred else "HIGH",
                "evidence_summary": "Simultaneous presence of sensitive secret access and outbound network primitives.",
                "related_signals": [
                    {"type": "capability", "category": "CREDENTIAL_ACCESS"},
                    {"type": "capability", "category": "NETWORK_OUTBOUND"}
                ],
                "reasoning": reasoning
            })

        # 2. Pattern: Remote Dropper or Command & Control (C2)
        has_proc = "PROCESS_EXECUTION" in all_cap_cats or "SHL-001" in static_rule_ids or "AST-SUB-01" in static_rule_ids
        has_dyn = "DYNAMIC_CODE_EXECUTION" in all_cap_cats or "DYN-001" in static_rule_ids or "AST-DYN-01" in static_rule_ids
        is_dlx = "DLX-001" in static_rule_ids

        if (has_proc and has_net and has_dyn) or is_dlx:
            correlations.append({
                "correlation_id": f"CORR-DROP-{uuid.uuid4().hex[:8]}",
                "pattern_type": "REMOTE_CODE_EXECUTION_DROPPER",
                "title": "Remote Dropper / Shell Execution Architecture",
                "confidence": "HIGH",
                "severity": "CRITICAL",
                "evidence_summary": "Chained network communication, process spawning, and runtime dynamic string evaluation.",
                "related_signals": [
                    {"type": "capability", "category": "PROCESS_EXECUTION"},
                    {"type": "capability", "category": "NETWORK_OUTBOUND"},
                    {"type": "capability", "category": "DYNAMIC_CODE_EXECUTION"}
                ],
                "reasoning": [
                    "Package executes host system processes.",
                    "Package initiates outbound network requests.",
                    "Package evaluates dynamic code at runtime (eval/Function/compile).",
                    "This combination is characteristic of secondary stage droppers."
                ]
            })

        # 3. Pattern: Install-Time Host Compromise Hook
        has_install = "INSTALL_TIME_EXECUTION" in all_cap_cats or any("INSTALL" in m.get("rule_id", "") for m in metadata_findings)
        has_bin = "BINARY_EXECUTION" in all_cap_cats or "BIN-001" in static_rule_ids

        if has_install and (has_proc or has_bin):
            correlations.append({
                "correlation_id": f"CORR-HOOK-{uuid.uuid4().hex[:8]}",
                "pattern_type": "INSTALL_TIME_EXPLOIT_HOOK",
                "title": "Automated Lifecycle Installation Script Spawning Commands",
                "confidence": "HIGH",
                "severity": "HIGH",
                "evidence_summary": "Package invokes native commands or bundled binaries during npm/pip installation without user invocation.",
                "related_signals": [
                    {"type": "capability", "category": "INSTALL_TIME_EXECUTION"},
                    {"type": "capability", "category": "PROCESS_EXECUTION" if has_proc else "BINARY_EXECUTION"}
                ],
                "reasoning": [
                    "Package registers preinstall or postinstall scripts in manifest.",
                    "Installation phase executes external shell processes or binaries automatically."
                ]
            })

        # 4. Pattern: Tampered or Forged Release
        if not integrity_ok:
            correlations.append({
                "correlation_id": f"CORR-TAMPER-{uuid.uuid4().hex[:8]}",
                "pattern_type": "CRYPTOGRAPHIC_INTEGRITY_TAMPERING",
                "title": "Package Checksum Integrity Mismatch",
                "confidence": "HIGH",
                "severity": "CRITICAL",
                "evidence_summary": "Downloaded tarball cryptographic digest differs from registry ledger.",
                "related_signals": [
                    {"type": "integrity", "status": "mismatch"}
                ],
                "reasoning": [
                    "Cryptographic digest calculated on archive does not match published sha256/shasum.",
                    "Potential upstream supply-chain poisoning, CDN tampering, or MITM alteration."
                ]
            })

        return correlations
