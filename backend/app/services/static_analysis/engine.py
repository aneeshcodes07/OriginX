import ast
import os
import re
from typing import List, Dict, Any, Optional
from app.services.static_analysis.rules import STATIC_RULES

SUSPICIOUS_EXTENSIONS = {
    ".exe": "Windows Executable binary",
    ".dll": "Dynamic Link Library binary",
    ".so": "Shared Object binary (Linux/Unix)",
    ".dylib": "Dynamic Library binary (macOS)",
    ".bin": "Raw binary payload",
    ".cmd": "Windows Command script",
    ".ps1": "PowerShell script"
}

# Heuristics for minified or bundled files
MINIFIED_CHUNK_SIZE = 1000
MINIFIED_OVERLAP = 100

class StaticAnalysisEngine:
    def __init__(self):
        self.rules = STATIC_RULES

    def _is_minified_or_bundled(self, content: str, lines: List[str]) -> bool:
        """
        Detects whether content is likely minified or bundled JavaScript/TypeScript.
        Typically features very long lines (> 500 chars), high density, or bundle markers.
        """
        if any("/* webpackUniversalModuleDefinition */" in line or "/* bundle */" in line for line in lines[:5]):
            return True
        if len(lines) > 0:
            max_line_len = max(len(l) for l in lines[:50])
            if max_line_len > 600:
                return True
        return False

    def _evaluate_context_confidence(
        self,
        rule_id: str,
        match_text: str,
        line: str,
        file_path: str,
        default_confidence: str
    ) -> tuple[str, str]:
        """
        Adjusts confidence and explanation based on context to reduce false positives.
        e.g., standard env config reading vs direct sensitive file exfiltration;
        minified bundle artifact vs standalone exploit script.
        """
        confidence = default_confidence
        note = ""

        # Context analysis for CRD-001 (Credentials)
        if rule_id == "CRD-001":
            # If it's just process.env.PORT or process.env.NODE_ENV, it's normal (though CRD-001 regex targets SECRET/TOKEN/keys)
            # Check if reference is in comments or test fixtures
            if re.search(r"^\s*(?://|/\*|\*|#)", line):
                confidence = "LOW"
                note = " (Detected in comment or documentation)"
            elif "test" in file_path.lower() or "spec" in file_path.lower() or "fixture" in file_path.lower():
                confidence = "MEDIUM"
                note = " (Detected in test suite or fixture)"

        # Context analysis for DYN-001 (Dynamic Code Evaluation)
        elif rule_id == "DYN-001":
            # Common template or build tool pattern: Function('return this')() or eval('this')
            if re.search(r"(?:eval|Function)\s*\(\s*['\"](?:return\s+)?this['\"]\s*\)", line):
                confidence = "LOW"
                note = " (Matches common global-this discovery shim)"
            elif "test" in file_path.lower() or "spec" in file_path.lower():
                confidence = "MEDIUM"
                note = " (Detected in test suite or mock)"

        # Context analysis for NET-001 (Outbound Network)
        elif rule_id == "NET-001":
            # Connecting to localhost/loopback (127.0.0.1 or 0.0.0.0) is common in dev tooling
            if "127.0.0.1" in match_text or "0.0.0.0" in match_text:
                confidence = "LOW"
                note = " (Localhost/loopback IP detected; often used for local dev servers or tests)"

        # Context analysis for SHL-001 (Shell execution)
        elif rule_id == "SHL-001":
            if "test" in file_path.lower() or "fixture" in file_path.lower():
                confidence = "MEDIUM"
                note = " (Detected in test suite or helper script)"

        return confidence, note

    def analyze_file_content(
        self,
        file_path: str,
        content: str
    ) -> List[Dict[str, Any]]:
        findings = []
        lines = content.splitlines()
        is_minified = self._is_minified_or_bundled(content, lines)

        # 1. Regex Rule Scanner across lines
        for rule in self.rules:
            rule_id = rule["id"]
            rule_regex = rule["regex"]

            for line_idx, line in enumerate(lines, 1):
                # For minified files with gigantic lines, scan in overlapping chunks
                # to ensure regexes with character lookaheads match across long single lines
                if len(line) > MINIFIED_CHUNK_SIZE:
                    matched = False
                    start = 0
                    while start < len(line):
                        chunk = line[start : start + MINIFIED_CHUNK_SIZE + MINIFIED_OVERLAP]
                        match = rule_regex.search(chunk)
                        if match:
                            matched_text = match.group(0)
                            evidence = matched_text.strip()
                            if len(evidence) > 140:
                                evidence = evidence[:137] + "..."

                            conf, note = self._evaluate_context_confidence(
                                rule_id, matched_text, chunk, file_path, rule["confidence"]
                            )

                            findings.append({
                                "rule_id": rule_id,
                                "title": rule["title"],
                                "severity": rule["severity"],
                                "file_path": file_path,
                                "line_number": line_idx,
                                "evidence_excerpt": evidence,
                                "explanation": rule["explanation"] + note,
                                "risk_reason": rule["risk_reason"],
                                "confidence": conf,
                                "recommended_action": rule["recommended_action"],
                                "is_false_positive": False,
                                "analyst_note": None
                            })
                            matched = True
                            break
                        start += MINIFIED_CHUNK_SIZE
                    if matched:
                        break
                else:
                    match = rule_regex.search(line)
                    if match:
                        matched_text = match.group(0)
                        evidence = matched_text.strip()
                        if len(evidence) > 140:
                            evidence = evidence[:137] + "..."

                        conf, note = self._evaluate_context_confidence(
                            rule_id, matched_text, line, file_path, rule["confidence"]
                        )

                        findings.append({
                            "rule_id": rule_id,
                            "title": rule["title"],
                            "severity": rule["severity"],
                            "file_path": file_path,
                            "line_number": line_idx,
                            "evidence_excerpt": evidence,
                            "explanation": rule["explanation"] + note,
                            "risk_reason": rule["risk_reason"],
                            "confidence": conf,
                            "recommended_action": rule["recommended_action"],
                            "is_false_positive": False,
                            "analyst_note": None
                        })
                        break  # Record highest-relevance finding per rule per file

        # 2. Syntax-aware AST inspection for Python files
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        # Detect eval() or exec()
                        if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
                            line_no = getattr(node, "lineno", 1)
                            # Check if not already added by regex
                            if not any(f["rule_id"] == "AST-DYN-01" and f["line_number"] == line_no for f in findings):
                                findings.append({
                                    "rule_id": "AST-DYN-01",
                                    "title": f"Python AST: Direct Call to Builtin '{node.func.id}()'",
                                    "severity": "HIGH",
                                    "file_path": file_path,
                                    "line_number": line_no,
                                    "evidence_excerpt": f"{node.func.id}(...)",
                                    "explanation": f"Syntactic abstract syntax tree confirms direct invocation of Python's dynamic '{node.func.id}' primitive.",
                                    "risk_reason": "Dynamic execution permits uncontrolled runtime string execution.",
                                    "confidence": "HIGH",
                                    "recommended_action": "Verify if dynamic execution is strictly needed or can be replaced with static calls.",
                                    "is_false_positive": False,
                                    "analyst_note": None
                                })
                        # Detect subprocess or os.system
                        elif isinstance(node.func, ast.Attribute):
                            attr_name = node.func.attr
                            if attr_name in ["system", "popen", "spawn"]:
                                line_no = getattr(node, "lineno", 1)
                                if not any(f["rule_id"] == "AST-SUB-01" and f["line_number"] == line_no for f in findings):
                                    findings.append({
                                        "rule_id": "AST-SUB-01",
                                        "title": f"Python AST: System Command Invocation via '.{attr_name}()'",
                                        "severity": "HIGH",
                                        "file_path": file_path,
                                        "line_number": line_no,
                                        "evidence_excerpt": f"os.{attr_name}(...)",
                                        "explanation": f"AST indicates operating system command invocation via '.{attr_name}'.",
                                        "risk_reason": "Spawning system shell commands from package code introduces arbitrary execution risks.",
                                        "confidence": "HIGH",
                                        "recommended_action": "Ensure parameters are sanitized and shell=True is avoided.",
                                        "is_false_positive": False,
                                        "analyst_note": None
                                    })
            except Exception:
                # Syntax error or unparseable Python snippet - pass safely
                pass

        return findings

    def analyze_package_files(
        self,
        files_dict: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        all_findings = []
        
        for file_path, content in files_dict.items():
            # Check for binary file extensions inside text dictionary / archive listing
            _, ext = os.path.splitext(file_path.lower())
            if ext in SUSPICIOUS_EXTENSIONS:
                all_findings.append({
                    "rule_id": "BIN-001",
                    "title": f"Unexpected Binary Executable Present ({ext})",
                    "severity": "HIGH",
                    "file_path": file_path,
                    "line_number": 1,
                    "evidence_excerpt": f"Binary file: {os.path.basename(file_path)} ({SUSPICIOUS_EXTENSIONS[ext]})",
                    "explanation": f"Package contains compiled binary executable or script ({ext}) in what should be a source distribution.",
                    "risk_reason": "Pre-compiled binaries in script packages frequently hide trojanized code or native backdoors.",
                    "confidence": "HIGH",
                    "recommended_action": "Do not execute. Disassemble or inspect why compiled binaries are included in this distribution.",
                    "is_false_positive": False,
                    "analyst_note": None
                })
                
            findings = self.analyze_file_content(file_path, content)
            all_findings.extend(findings)
            
        return all_findings
