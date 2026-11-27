import os
from typing import Dict, Any, List, Optional
from app.services.capability_analysis.models import CapabilityCategory, CapabilityFinding
from app.services.capability_analysis.python_extractor import PythonCapabilityExtractor
from app.services.capability_analysis.javascript_extractor import JavaScriptCapabilityExtractor

BINARY_EXTENSIONS = {
    ".exe": "Windows PE Executable binary",
    ".dll": "Windows Dynamic Link Library",
    ".so": "Linux ELF Shared Object binary",
    ".dylib": "macOS Mach-O Dynamic Library",
    ".bin": "Raw binary executable payload",
    ".node": "Pre-compiled Node.js native addon binary",
    ".cmd": "Windows Command script",
    ".ps1": "Windows PowerShell script",
    ".sh": "Unix shell script"
}

class CapabilityExtractionEngine:
    """
    Dedicated behavioral capability extraction engine for SupplyGuard.
    Analyzes Python, JavaScript/TypeScript, package metadata, and binary artifacts.
    """

    def __init__(self):
        self.py_extractor = PythonCapabilityExtractor()
        self.js_extractor = JavaScriptCapabilityExtractor()

    def extract_capabilities(
        self,
        files_dict: Dict[str, str],
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[CapabilityFinding]:
        findings: List[CapabilityFinding] = []
        metadata = metadata or {}

        # 1. Inspect package metadata for INSTALL_TIME_EXECUTION
        # (preinstall, install, postinstall lifecycle hooks)
        lifecycle_scripts = metadata.get("lifecycle_scripts", {})
        for hook, cmd in lifecycle_scripts.items():
            findings.append(CapabilityFinding(
                capability_id="CAP_INSTALL_HOOK",
                capability_name="Install-Time Lifecycle Execution Hook",
                category=CapabilityCategory.INSTALL_TIME_EXECUTION,
                file_path="package.json (scripts)",
                line_number=1,
                evidence_excerpt=f"{hook}: '{cmd}'",
                detection_method="metadata_inspection",
                confidence="HIGH",
                explanation=f"Package registers automatic install-time lifecycle hook '{hook}'."
            ))

        # 2. Inspect files by language and extension
        for file_path, content in files_dict.items():
            lower_path = file_path.lower()
            _, ext = os.path.splitext(lower_path)

            # Check for BINARY_EXECUTION
            if ext in BINARY_EXTENSIONS:
                findings.append(CapabilityFinding(
                    capability_id="CAP_BINARY_PAYLOAD",
                    capability_name="Binary or Executable Payload",
                    category=CapabilityCategory.BINARY_EXECUTION,
                    file_path=file_path,
                    line_number=1,
                    evidence_excerpt=f"Executable binary file: {os.path.basename(file_path)} ({BINARY_EXTENSIONS[ext]})",
                    detection_method="binary_inspection",
                    confidence="HIGH",
                    explanation=f"Package includes pre-compiled binary or executable file ({ext})."
                ))

            # Code inspection
            if ext == ".py":
                py_findings = self.py_extractor.extract(file_path, content)
                findings.extend(py_findings)
            elif ext in [".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"]:
                js_findings = self.js_extractor.extract(file_path, content)
                findings.extend(js_findings)

        return findings
