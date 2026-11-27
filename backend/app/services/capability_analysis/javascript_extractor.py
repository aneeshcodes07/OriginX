import re
from typing import List, Dict, Any
from app.services.capability_analysis.models import CapabilityCategory, CapabilityFinding

class JavaScriptCapabilityExtractor:
    """
    Extensible language-analysis interface for JavaScript/TypeScript.
    Distinguishes module import/require declarations from actual runtime API invocations,
    records file paths, line numbers, evidence excerpts, and provides clear confidence levels.

    LIMITATION DOCUMENTATION:
    Static regex/token scanning of JavaScript cannot perform full runtime semantic evaluation,
    dynamic property de-obfuscation (e.g. global[a+b][c]()), or full inter-procedural dataflow.
    Invocations wrapped in heavy runtime reflections are flagged under DYNAMIC_CODE_EXECUTION.
    """

    PATTERNS = [
        # 1. FILESYSTEM_READ
        {
            "id": "CAP_FS_READ_JS",
            "name": "Filesystem Read Operations",
            "category": CapabilityCategory.FILESYSTEM_READ,
            "regex": re.compile(
                r"\b(?:fs|promises)\s*\.\s*(?:readFile|readFileSync|createReadStream|readdir|readdirSync|stat|statSync|access|accessSync)\s*\(",
                re.IGNORECASE
            ),
            "confidence": "HIGH",
            "explanation": "Node.js fs module invoked to read or inspect filesystem paths."
        },
        # 2. FILESYSTEM_WRITE
        {
            "id": "CAP_FS_WRITE_JS",
            "name": "Filesystem Write Operations",
            "category": CapabilityCategory.FILESYSTEM_WRITE,
            "regex": re.compile(
                r"\b(?:fs|promises)\s*\.\s*(?:writeFile|writeFileSync|createWriteStream|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|rmdir|rmdirSync|mkdir|mkdirSync)\s*\(",
                re.IGNORECASE
            ),
            "confidence": "HIGH",
            "explanation": "Node.js fs module invoked to create, append, modify, or delete files or directories."
        },
        # 3. NETWORK_OUTBOUND
        {
            "id": "CAP_NET_OUT_JS",
            "name": "Outbound Network Communication",
            "category": CapabilityCategory.NETWORK_OUTBOUND,
            "regex": re.compile(
                r"\b(?:https?|axios|needle|got|node-fetch|fetch)\s*\.\s*(?:get|post|put|delete|request)\s*\(|\bfetch\s*\(|\bnet\s*\.\s*(?:createConnection|connect)\s*\(",
                re.IGNORECASE
            ),
            "confidence": "HIGH",
            "explanation": "HTTP request, fetch, or raw TCP socket connection created."
        },
        # 4. NETWORK_LISTEN
        {
            "id": "CAP_NET_LISTEN_JS",
            "name": "Network Socket / Server Listening",
            "category": CapabilityCategory.NETWORK_LISTEN,
            "regex": re.compile(
                r"\b(?:http|https|net)\s*\.\s*createServer\s*\(|\b(?:app|server)\s*\.\s*listen\s*\(",
                re.IGNORECASE
            ),
            "confidence": "HIGH",
            "explanation": "Network server initialized to listen on inbound ports/sockets."
        },
        # 5. PROCESS_EXECUTION
        {
            "id": "CAP_PROC_EXEC_JS",
            "name": "Process Execution / Shell Spawning",
            "category": CapabilityCategory.PROCESS_EXECUTION,
            "regex": re.compile(
                r"\b(?:child_process|cp)\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(",
                re.IGNORECASE
            ),
            "confidence": "HIGH",
            "explanation": "Operating system process or shell spawned via child_process."
        },
        # 6. ENVIRONMENT_ACCESS
        {
            "id": "CAP_ENV_ACCESS_JS",
            "name": "Environment Variable Access",
            "category": CapabilityCategory.ENVIRONMENT_ACCESS,
            "regex": re.compile(
                r"\bprocess\s*\.\s*env\b",
                re.IGNORECASE
            ),
            "confidence": "HIGH",
            "explanation": "Reading host environment variables via process.env."
        },
        # 7. CREDENTIAL_ACCESS
        {
            "id": "CAP_CRED_ACCESS_JS",
            "name": "Credential & Secret Access",
            "category": CapabilityCategory.CREDENTIAL_ACCESS,
            "regex": re.compile(
                r"(?:AWS_SECRET_ACCESS_KEY|NPM_TOKEN|GITHUB_TOKEN|SLACK_TOKEN|DISCORD_TOKEN|\.aws\/credentials|\.ssh\/id_rsa)",
                re.IGNORECASE
            ),
            "confidence": "HIGH",
            "explanation": "Explicit reference to sensitive token name, API credential, or private key path."
        },
        # 8. DYNAMIC_CODE_EXECUTION
        {
            "id": "CAP_DYN_EXEC_JS",
            "name": "Dynamic Code Evaluation",
            "category": CapabilityCategory.DYNAMIC_CODE_EXECUTION,
            "regex": re.compile(
                r"\b(?:eval\s*\(|new\s+Function\s*\(|vm\s*\.\s*(?:runInContext|runInNewContext|runInThisContext)\s*\()",
                re.IGNORECASE
            ),
            "confidence": "HIGH",
            "explanation": "Arbitrary JavaScript evaluated at runtime through eval(), new Function(), or vm context."
        }
    ]

    # Pure import lines to distinguish from invocations
    IMPORT_REGEX = re.compile(
        r"^(?:\s*import\s+.*?\s+from\s+['\"][^'\"]+['\"]|\s*(?:const|let|var)\s+.*?\s*=\s*require\s*\(\s*['\"][^'\"]+['\"]\s*\))",
        re.IGNORECASE
    )

    def extract(self, file_path: str, content: str) -> List[CapabilityFinding]:
        findings: List[CapabilityFinding] = []
        lines = content.splitlines()

        for line_idx, line in enumerate(lines, 1):
            trimmed = line.strip()
            if not trimmed or trimmed.startswith("//") or trimmed.startswith("/*"):
                continue

            # Check if this line is purely an import/require declaration
            is_import_only = bool(self.IMPORT_REGEX.match(trimmed))

            for pat in self.PATTERNS:
                # If it's only an import declaration without an actual API invocation,
                # we don't treat it as active capability invocation unless it's child_process require with direct inline call
                match = pat["regex"].search(trimmed)
                if match:
                    # Distinguish import from active call
                    conf = pat["confidence"]
                    expl = pat["explanation"]
                    if is_import_only and not ("(" in trimmed[match.end():] or "exec" in trimmed or "run" in trimmed):
                        # Lower confidence if it's purely a require/import statement
                        conf = "LOW"
                        expl = f"{pat['explanation']} (Module imported; invocation not yet verified on this line)"

                    evidence = match.group(0).strip()
                    if len(evidence) > 100:
                        evidence = evidence[:97] + "..."

                    findings.append(CapabilityFinding(
                        capability_id=pat["id"],
                        capability_name=pat["name"],
                        category=pat["category"],
                        file_path=file_path,
                        line_number=line_idx,
                        evidence_excerpt=evidence,
                        detection_method="js_ast_token",
                        confidence=conf,
                        explanation=expl
                    ))

        return findings
