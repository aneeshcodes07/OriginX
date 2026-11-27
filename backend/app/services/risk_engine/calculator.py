from typing import List, Dict, Any, Tuple, Optional

class RiskEngine:
    """
    SupplyGuard Explainable Risk Assessment Engine (v2.0.0).
    Produces normalized 0-100 risk score and evaluates policy decisions (ALLOW, REVIEW, BLOCK).

    Enhancements in v2.0.0:
    - Model versioning (`ENGINE_VERSION = "2.0.0"`).
    - Multi-signal compounding via Evidence Correlation.
    - Contextual behavioral capability scoring (isolated network outbound does not produce false high score).
    - Policy weights configuration support.
    - Avoids double-counting correlated findings.
    """
    ENGINE_VERSION = "2.0.0"

    DEFAULT_POLICY_WEIGHTS = {
        "integrity_failure": 50.0,
        "vuln_critical": 40.0,
        "vuln_high": 25.0,
        "vuln_medium": 15.0,
        "vuln_low": 5.0,
        "static_critical": 35.0,
        "static_high": 20.0,
        "static_medium": 10.0,
        "static_low": 3.0,
        "correlation_critical": 30.0,
        "correlation_high": 15.0,
        "new_cap_credential": 25.0,
        "new_cap_process": 20.0,
        "new_cap_install": 15.0,
        "new_cap_benign": 0.0  # FILESYSTEM_READ / NETWORK_OUTBOUND alone do not trigger alerts
    }

    def calculate_risk(
        self,
        vulnerabilities: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        metadata_findings: List[Dict[str, Any]],
        integrity_ok: bool = True,
        correlations: Optional[List[Dict[str, Any]]] = None,
        new_capabilities: Optional[List[Dict[str, Any]]] = None,
        policy_weights: Optional[Dict[str, float]] = None
    ) -> Tuple[float, str, str, List[str], Dict[str, Any]]:
        weights = {**self.DEFAULT_POLICY_WEIGHTS, **(policy_weights or {})}
        raw_score = 0.0
        contributing_signals = []
        policy_reasons = []

        # 1. Package Integrity
        if not integrity_ok:
            w = weights.get("integrity_failure", 50.0)
            raw_score += w
            contributing_signals.append({
                "factor": "Package Integrity Verification Failure",
                "weight": w,
                "evidence": "Archive hash does not match registry-published cryptographic digest."
            })
            policy_reasons.append("Archive checksum mismatch with registry metadata.")

        # 2. Known Vulnerabilities
        vuln_score = 0.0
        seen_vulns = set()
        for v in vulnerabilities:
            vid = v.get("vuln_id")
            if vid in seen_vulns:
                continue
            seen_vulns.add(vid)

            sev = str(v.get("severity", "MEDIUM")).upper()
            if "CRITICAL" in sev:
                pts = weights.get("vuln_critical", 40.0)
            elif "HIGH" in sev:
                pts = weights.get("vuln_high", 25.0)
            elif "MEDIUM" in sev:
                pts = weights.get("vuln_medium", 15.0)
            elif "LOW" in sev:
                pts = weights.get("vuln_low", 5.0)
            else:
                pts = 10.0

            vuln_score += pts
            contributing_signals.append({
                "factor": f"Known Vulnerability ({vid} - {sev})",
                "weight": pts,
                "evidence": v.get("summary") or "Vulnerability reported in OSV intelligence database."
            })
            if pts >= 25.0:
                policy_reasons.append(f"Contains high/critical vulnerability {vid}.")

        # Cap vulnerability contribution to 50 max
        raw_score += min(50.0, vuln_score)

        # 3. Static Analysis Findings
        static_score = 0.0
        seen_static_rules = set()
        for f in findings:
            if f.get("is_false_positive"):
                continue
            rid = f.get("rule_id")
            sev = f.get("severity", "MEDIUM").upper()

            if rid in seen_static_rules:
                weight = 3.0  # Diminishing weight for duplicates
            else:
                seen_static_rules.add(rid)
                if sev == "CRITICAL":
                    weight = weights.get("static_critical", 35.0)
                    policy_reasons.append(f"Critical static finding: {f.get('title')}")
                elif sev == "HIGH":
                    weight = weights.get("static_high", 20.0)
                    policy_reasons.append(f"High risk pattern: {f.get('title')}")
                elif sev == "MEDIUM":
                    weight = weights.get("static_medium", 10.0)
                else:
                    weight = weights.get("static_low", 3.0)

            # Dampen confidence if finding is marked LOW confidence
            if f.get("confidence") == "LOW":
                weight = weight * 0.4

            static_score += weight
            contributing_signals.append({
                "factor": f"Static Finding ({rid}: {f.get('title')})",
                "weight": round(weight, 1),
                "evidence": f.get("evidence_excerpt") or f.get("explanation")
            })

        raw_score += min(50.0, static_score)

        # 4. Metadata Anomalies
        for m in metadata_findings:
            sev = m.get("severity", "LOW").upper()
            w = 15.0 if sev == "HIGH" else 8.0 if sev == "MEDIUM" else 3.0
            raw_score += w
            contributing_signals.append({
                "factor": f"Metadata: {m.get('title')}",
                "weight": w,
                "evidence": m.get("evidence_excerpt")
            })
            if "INSTALL-SCRIPT" in m.get("rule_id", ""):
                policy_reasons.append("Installation lifecycle hook present.")

        # 5. Newly Introduced Capabilities (contextual)
        new_caps = new_capabilities or []
        for nc in new_caps:
            cat = nc.get("category")
            if cat == "CREDENTIAL_ACCESS":
                w = weights.get("new_cap_credential", 25.0)
                raw_score += w
                contributing_signals.append({
                    "factor": "New Behaviour: Credential Access Introduced",
                    "weight": w,
                    "evidence": f"Version introduced access to secret keys in {len(nc.get('introducing_files', []))} files."
                })
            elif cat == "PROCESS_EXECUTION":
                w = weights.get("new_cap_process", 20.0)
                raw_score += w
                contributing_signals.append({
                    "factor": "New Behaviour: Process Spawning Introduced",
                    "weight": w,
                    "evidence": f"Version introduced system process execution in {len(nc.get('introducing_files', []))} files."
                })
            elif cat == "INSTALL_TIME_EXECUTION":
                w = weights.get("new_cap_install", 15.0)
                raw_score += w
                contributing_signals.append({
                    "factor": "New Behaviour: Install Lifecycle Hook Added",
                    "weight": w,
                    "evidence": "Version added install or postinstall scripts."
                })

        # 6. Evidence Correlations (compounding multi-signal factor)
        corrs = correlations or []
        for c in corrs:
            c_sev = c.get("severity", "HIGH").upper()
            w = weights.get("correlation_critical", 30.0) if c_sev == "CRITICAL" else weights.get("correlation_high", 15.0)
            raw_score += w
            contributing_signals.append({
                "factor": f"Correlated Threat: {c.get('title')}",
                "weight": w,
                "evidence": c.get("evidence_summary")
            })
            policy_reasons.append(f"Correlated threat detected: {c.get('title')}")

        # Final Score Normalization (0.0 to 100.0)
        final_score = round(min(100.0, max(0.0, raw_score)), 1)

        # Classification & Policy Decision
        if final_score >= 70.0:
            classification = "CRITICAL"
            decision = "BLOCK"
        elif final_score >= 40.0:
            classification = "HIGH"
            decision = "REVIEW" if final_score < 60.0 else "BLOCK"
        elif final_score >= 20.0:
            classification = "MEDIUM"
            decision = "REVIEW" if policy_reasons else "ALLOW"
        else:
            classification = "LOW"
            decision = "ALLOW"

        breakdown = {
            "model_version": self.ENGINE_VERSION,
            "raw_score": raw_score,
            "normalized_score": final_score,
            "classification": classification,
            "decision": decision,
            "contributing_signals": contributing_signals,
            "total_signals_considered": len(contributing_signals)
        }

        return final_score, classification, decision, policy_reasons, breakdown
