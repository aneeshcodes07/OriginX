import re
from typing import List, Dict, Any, Optional

STATIC_RULES = [
    {
        "id": "OBF-001",
        "title": "Base64 or Hex Obfuscated Payload with Dynamic Execution",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "obfuscation",
        "regex": re.compile(
            r"((?:Buffer\.from|atob|base64\.b64decode|codecs\.decode)\s*\(\s*['\"][A-Za-z0-9+/=]{24,}['\"].*?(?:eval|exec|run|Function|spawn))|"
            r"((?:eval|exec|Function)\s*\(\s*(?:Buffer\.from|atob|base64\.b64decode).*?\))",
            re.IGNORECASE | re.DOTALL
        ),
        "explanation": "Detected encoded payload (Base64/Hex) directly piped into dynamic execution primitives (eval/exec/Function).",
        "risk_reason": "Attackers frequently encode malicious stages to bypass simple string scanners and execute arbitrary code at runtime.",
        "recommended_action": "Inspect the decoded string content to verify whether this is legitimate bundling/packing or hidden payload delivery."
    },
    {
        "id": "OBF-002",
        "title": "High-Entropy Hex / CharCode Obfuscated String Array",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "obfuscation",
        "regex": re.compile(
            r"(\\x[0-9a-fA-F]{2}){8,}|(String\.fromCharCode\s*\(\s*(\d+\s*,\s*){6,}\d+\s*\))",
            re.IGNORECASE
        ),
        "explanation": "Detected concentrated sequence of hexadecimal escape characters or long String.fromCharCode transformations.",
        "risk_reason": "Heavy hex escape sequences or character-code arrays are often used to conceal URLs, hostnames, or command strings.",
        "recommended_action": "Examine the decoded string array and verify whether it represents minification or deliberate obfuscation."
    },
    {
        "id": "DYN-001",
        "title": "Dynamic Code Evaluation Primitive (eval / Function constructor)",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "dynamic_execution",
        "regex": re.compile(
            r"\b(eval\s*\([^\)]+\)|new\s+Function\s*\([^\)]+\)|compile\s*\([^\)]+,\s*['\"]<string>['\"],\s*['\"]exec['\"]\))",
            re.IGNORECASE
        ),
        "explanation": "Code invokes runtime string compilation through eval() or new Function().",
        "risk_reason": "Dynamic execution bypasses static type safety and dependency trees, allowing arbitrary logic to execute that cannot be vetted at build time.",
        "recommended_action": "Refactor dynamic evaluation to static logic or verify strict parameter sanitization."
    },
    {
        "id": "SHL-001",
        "title": "Arbitrary Shell Command Execution via Subprocess",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "subprocess",
        "regex": re.compile(
            r"\b(child_process\.(?:exec|execSync|spawn|spawnSync)\s*\([^\)]+\)|subprocess\.(?:Popen|run|call|check_output)\s*\([^\)]+shell\s*=\s*True|os\.system\s*\([^\)]+\)|os\.popen\s*\([^\)]+\))",
            re.IGNORECASE
        ),
        "explanation": "Package launches shell or system subprocess commands directly on the host operating system.",
        "risk_reason": "Supply-chain attacks frequently spawn background processes (curl, bash, powershell, sh) to drop reverse shells or download external binaries.",
        "recommended_action": "Audit the exact command arguments to verify necessity and ensure user input cannot control the executed binary."
    },
    {
        "id": "CRD-001",
        "title": "Credential & Secret File Harvesting Pattern",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "credential_access",
        "regex": re.compile(
            r"(\.(?:aws|ssh|docker|kube)\/(?:credentials|config|id_rsa)|\.env|\/etc\/(?:passwd|shadow)|(?:AWS_SECRET_ACCESS_KEY|NPM_TOKEN|GITHUB_TOKEN|DISCORD_TOKEN|SLACK_TOKEN|SSH_AUTH_SOCK))",
            re.IGNORECASE
        ),
        "explanation": "Detected direct reference to sensitive credentials paths or secret environment variable tokens.",
        "risk_reason": "Known malware families (e.g. LofyGang, W4SP Stealer) scan developer disks and environment variables for cloud credentials and API keys.",
        "recommended_action": "Immediately verify why the package references sensitive secret paths. If unexpected, block the package."
    },
    {
        "id": "NET-001",
        "title": "Raw Socket / Suspicious Outbound Network Connection",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "category": "network",
        "regex": re.compile(
            r"(net\.createConnection|socket\.connect\s*\(\s*\d+\s*,\s*['\"][0-9\.]+['\"]|urllib\.request\.urlopen\s*\(\s*['\"]https?:\/\/(?:\d{1,3}\.){3}\d{1,3})",
            re.IGNORECASE
        ),
        "explanation": "Package creates raw TCP socket connections or connects to hardcoded numeric IP addresses.",
        "risk_reason": "Packages in typical libraries rarely communicate via raw sockets to raw IP addresses unless connecting to Command & Control (C2) infrastructure.",
        "recommended_action": "Verify if network functionality is an intended core feature of this library or an unauthorized telemetry/C2 channel."
    },
    {
        "id": "DLX-001",
        "title": "Download and Execute Binary Delivery Pattern",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "category": "download_execute",
        "regex": re.compile(
            r"(curl\s+-[fsSLk]+.*?\|\s*(?:bash|sh|powershell|cmd)|wget\s+-[qO].*?\|\s*(?:sh|bash)|Invoke-WebRequest.*?\|\s*Invoke-Expression)",
            re.IGNORECASE
        ),
        "explanation": "Detected classic download-and-execute pipeline chaining web fetch directly into shell interpreter.",
        "risk_reason": "This is a signature pattern for droppers and secondary stage downloaders in software supply-chain compromises.",
        "recommended_action": "Block the package version immediately and investigate the remote payload endpoint."
    },
    {
        "id": "INS-001",
        "title": "Lifecycle Installation Script Execution Hook",
        "severity": "HIGH",
        "confidence": "HIGH",
        "category": "install_script",
        "regex": re.compile(
            r"(\b(?:preinstall|postinstall|install)\b\s*:\s*['\"][^'\"]+(?:node|sh|bash|curl|wget|python|powershell)[^'\"]*['\"])",
            re.IGNORECASE
        ),
        "explanation": "Package specifies install-time hooks that automatically execute code when the package is installed.",
        "risk_reason": "Over 70% of npm malware utilizes postinstall or preinstall hooks to execute malicious stages without user interaction.",
        "recommended_action": "Inspect the lifecycle script command line. Prefer running installations with --ignore-scripts in untrusted contexts."
    }
]
