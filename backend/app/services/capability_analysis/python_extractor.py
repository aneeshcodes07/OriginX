import ast
import re
from typing import List, Dict, Any, Optional
from app.services.capability_analysis.models import CapabilityCategory, CapabilityFinding

class PythonCapabilityExtractor:
    """
    AST-driven capability extractor for Python code.
    Inspects imports, function calls, attribute access, and arguments.
    """

    # Imports to inspect
    FS_READ_MODULES = {"pathlib", "os", "shutil", "glob", "tarfile", "zipfile"}
    FS_WRITE_MODULES = {"pathlib", "os", "shutil", "tempfile"}
    NET_OUTBOUND_MODULES = {"urllib", "requests", "httpx", "http.client", "aiohttp", "socket", "ftplib", "smtplib"}
    NET_LISTEN_MODULES = {"socket", "socketserver", "asyncio", "http.server", "flask", "fastapi", "tornado"}
    PROCESS_MODULES = {"subprocess", "os", "multiprocessing", "concurrent.futures"}
    ENV_MODULES = {"os", "environ", "dotenv"}

    def extract(self, file_path: str, content: str) -> List[CapabilityFinding]:
        findings: List[CapabilityFinding] = []
        try:
            tree = ast.parse(content)
        except Exception:
            # Fallback to regex-based line scanning if syntax cannot be parsed
            return self._regex_fallback(file_path, content)

        # Track imported aliases: name -> original
        imported_symbols: Dict[str, str] = {}
        imported_modules: Dict[str, str] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    asname = alias.asname or name
                    imported_modules[asname] = name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for alias in node.names:
                    full_name = f"{mod}.{alias.name}" if mod else alias.name
                    asname = alias.asname or alias.name
                    imported_symbols[asname] = full_name

        # Walk AST calls and expressions
        for node in ast.walk(tree):
            # 1. Function / Method Calls
            if isinstance(node, ast.Call):
                call_name, base_obj = self._resolve_call(node.func, imported_symbols, imported_modules)
                lineno = getattr(node, "lineno", 1)

                # DYNAMIC_CODE_EXECUTION: eval(), exec(), compile()
                if call_name in ["eval", "exec"]:
                    findings.append(CapabilityFinding(
                        capability_id="CAP_DYN_EXEC_PY",
                        capability_name="Dynamic Code Execution",
                        category=CapabilityCategory.DYNAMIC_CODE_EXECUTION,
                        file_path=file_path,
                        line_number=lineno,
                        evidence_excerpt=f"{call_name}(...)",
                        detection_method="python_ast",
                        confidence="HIGH",
                        explanation=f"Direct call to Python dynamic execution builtin '{call_name}()'."
                    ))

                # PROCESS_EXECUTION: subprocess.*, os.system, os.popen, os.spawn*
                if call_name in ["os.system", "os.popen"] or call_name.startswith("os.spawn") or call_name.startswith("subprocess."):
                    findings.append(CapabilityFinding(
                        capability_id="CAP_PROC_EXEC_PY",
                        capability_name="Process & Subprocess Execution",
                        category=CapabilityCategory.PROCESS_EXECUTION,
                        file_path=file_path,
                        line_number=lineno,
                        evidence_excerpt=f"{call_name}(...)",
                        detection_method="python_ast",
                        confidence="HIGH",
                        explanation=f"Process invocation detected via '{call_name}()'."
                    ))

                # FILESYSTEM_READ: open() with 'r' or default, os.listdir, os.walk, os.scandir, Path.read_*
                if call_name == "open":
                    # Check mode argument if present
                    mode = "r"
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                        mode = node.args[1].value
                    for kw in node.keywords:
                        if kw.arg == "mode" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                            mode = kw.value.value
                    if any(m in mode for m in ["w", "a", "+", "x"]):
                        findings.append(CapabilityFinding(
                            capability_id="CAP_FS_WRITE_PY",
                            capability_name="Filesystem Write Operations",
                            category=CapabilityCategory.FILESYSTEM_WRITE,
                            file_path=file_path,
                            line_number=lineno,
                            evidence_excerpt=f"open(..., mode='{mode}')",
                            detection_method="python_ast",
                            confidence="HIGH",
                            explanation=f"Filesystem write access initiated via open() with mode '{mode}'."
                        ))
                    else:
                        findings.append(CapabilityFinding(
                            capability_id="CAP_FS_READ_PY",
                            capability_name="Filesystem Read Operations",
                            category=CapabilityCategory.FILESYSTEM_READ,
                            file_path=file_path,
                            line_number=lineno,
                            evidence_excerpt=f"open(..., mode='{mode}')",
                            detection_method="python_ast",
                            confidence="HIGH",
                            explanation=f"Filesystem read access initiated via open() with mode '{mode}'."
                        ))

                if call_name in ["os.listdir", "os.walk", "os.scandir"] or (base_obj and "read_text" in call_name or "read_bytes" in call_name):
                    findings.append(CapabilityFinding(
                        capability_id="CAP_FS_READ_PY",
                        capability_name="Filesystem Read Operations",
                        category=CapabilityCategory.FILESYSTEM_READ,
                        file_path=file_path,
                        line_number=lineno,
                        evidence_excerpt=f"{call_name}(...)",
                        detection_method="python_ast",
                        confidence="HIGH",
                        explanation=f"Filesystem read/enumeration operation via '{call_name}()'."
                    ))

                if call_name in ["os.remove", "os.unlink", "os.mkdir", "os.makedirs", "os.rmdir", "shutil.rmtree", "shutil.copy"] or (base_obj and "write_text" in call_name or "write_bytes" in call_name):
                    findings.append(CapabilityFinding(
                        capability_id="CAP_FS_WRITE_PY",
                        capability_name="Filesystem Write Operations",
                        category=CapabilityCategory.FILESYSTEM_WRITE,
                        file_path=file_path,
                        line_number=lineno,
                        evidence_excerpt=f"{call_name}(...)",
                        detection_method="python_ast",
                        confidence="HIGH",
                        explanation=f"Filesystem mutation/write operation via '{call_name}()'."
                    ))

                # NETWORK_OUTBOUND: requests.get/post, httpx.get/post, urllib.request.urlopen, socket.connect
                if any(call_name.startswith(p) for p in ["requests.", "httpx.", "urllib.request.", "aiohttp.", "http.client."]) or call_name.endswith(".connect"):
                    findings.append(CapabilityFinding(
                        capability_id="CAP_NET_OUT_PY",
                        capability_name="Outbound Network Communication",
                        category=CapabilityCategory.NETWORK_OUTBOUND,
                        file_path=file_path,
                        line_number=lineno,
                        evidence_excerpt=f"{call_name}(...)",
                        detection_method="python_ast",
                        confidence="HIGH",
                        explanation=f"Outbound network request initiated via '{call_name}()'."
                    ))

                # NETWORK_LISTEN: socket.bind, socket.listen, server.serve_forever
                if call_name.endswith(".bind") or call_name.endswith(".listen") or "serve_forever" in call_name:
                    findings.append(CapabilityFinding(
                        capability_id="CAP_NET_LISTEN_PY",
                        capability_name="Network Socket Listening",
                        category=CapabilityCategory.NETWORK_LISTEN,
                        file_path=file_path,
                        line_number=lineno,
                        evidence_excerpt=f"{call_name}(...)",
                        detection_method="python_ast",
                        confidence="HIGH",
                        explanation=f"Network server socket binding or listening initiated via '{call_name}()'."
                    ))

            # 2. Attribute / Subscript Access: Environment and Credentials
            # os.environ, os.getenv
            elif isinstance(node, ast.Attribute):
                lineno = getattr(node, "lineno", 1)
                if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
                    findings.append(CapabilityFinding(
                        capability_id="CAP_ENV_ACCESS_PY",
                        capability_name="Environment Variable Access",
                        category=CapabilityCategory.ENVIRONMENT_ACCESS,
                        file_path=file_path,
                        line_number=lineno,
                        evidence_excerpt="os.environ",
                        detection_method="python_ast",
                        confidence="HIGH",
                        explanation="Environment access via os.environ table."
                    ))

            # Check for credential patterns in constants (API keys, secrets, token names)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value
                lineno = getattr(node, "lineno", 1)
                if re.search(r"(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|SLACK_TOKEN|DISCORD_TOKEN|\.aws\/credentials|\.ssh\/id_rsa)", val, re.IGNORECASE):
                    findings.append(CapabilityFinding(
                        capability_id="CAP_CRED_ACCESS_PY",
                        capability_name="Credential & Secret Access",
                        category=CapabilityCategory.CREDENTIAL_ACCESS,
                        file_path=file_path,
                        line_number=lineno,
                        evidence_excerpt=val[:60],
                        detection_method="python_ast",
                        confidence="HIGH",
                        explanation="Reference to sensitive token, cloud credential, or private key path."
                    ))

        return findings

    def _resolve_call(self, func_node: ast.AST, symbols: Dict[str, str], modules: Dict[str, str]) -> tuple[str, Optional[str]]:
        if isinstance(func_node, ast.Name):
            orig = symbols.get(func_node.id, func_node.id)
            return orig, None
        elif isinstance(func_node, ast.Attribute):
            base_name, _ = self._resolve_call(func_node.value, symbols, modules)
            full_name = f"{base_name}.{func_node.attr}"
            return full_name, base_name
        return "call", None

    def _regex_fallback(self, file_path: str, content: str) -> List[CapabilityFinding]:
        findings = []
        for line_idx, line in enumerate(content.splitlines(), 1):
            if "os.system" in line or "subprocess." in line:
                findings.append(CapabilityFinding(
                    capability_id="CAP_PROC_EXEC_PY",
                    capability_name="Process & Subprocess Execution",
                    category=CapabilityCategory.PROCESS_EXECUTION,
                    file_path=file_path,
                    line_number=line_idx,
                    evidence_excerpt=line.strip()[:80],
                    detection_method="regex_fallback",
                    confidence="MEDIUM",
                    explanation="Regex matched subprocess/system execution call."
                ))
        return findings
