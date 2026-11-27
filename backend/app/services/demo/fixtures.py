from typing import Dict, Any, List

DEMO_FIXTURES = {
    "case_a_normal": {
        "id": "demo-case-a",
        "category": "Normal Package",
        "title": "Clean Utility Library (supplyguard-demo-logger)",
        "ecosystem": "npm",
        "package_name": "@supplyguard-demo/logger",
        "version": "1.0.0",
        "description": "Standard production-ready logging utility with zero external dependencies and safe static methods.",
        "expected_result": "LOW RISK (ALLOW). Clean code with standard exports, no installation scripts, no network access, no known vulnerabilities.",
        "metadata": {
            "name": "@supplyguard-demo/logger",
            "version": "1.0.0",
            "description": "Lightweight structured logger for demo purposes",
            "license": "MIT",
            "published_at": "2025-01-10T12:00:00Z",
            "author": "SupplyGuard Lab Maintainer <security@supplyguard.dev>",
            "repo_url": "https://github.com/supplyguard-demo/logger",
            "dependencies": {},
            "devDependencies": {"typescript": "^5.0.0"},
            "lifecycle_scripts": {},
            "all_versions": ["1.0.0"]
        },
        "files": {
            "package.json": '{\n  "name": "@supplyguard-demo/logger",\n  "version": "1.0.0",\n  "main": "index.js",\n  "license": "MIT"\n}',
            "index.js": 'function log(message) {\n  const timestamp = new Date().toISOString();\n  console.log(`[${timestamp}] INFO: ${message}`);\n}\n\nmodule.exports = { log };\n',
            "README.md": "# Demo Logger\nA clean harmless sample logger library for testing baseline scans.\n"
        }
    },
    "case_b_legitimate_update": {
        "id": "demo-case-b",
        "category": "Legitimate Update",
        "title": "Feature Update: v1.0.0 vs v1.1.0 (supplyguard-demo-math)",
        "ecosystem": "npm",
        "package_name": "@supplyguard-demo/math",
        "base_version": "1.0.0",
        "target_version": "1.1.0",
        "description": "A legitimate version update adding vector calculations and an updated readme. Demonstrates that version comparator correctly tracks additions without flagging them as threats.",
        "expected_result": "LOW RISK (ALLOW). 1 file added, 1 modified, zero suspicious signals. Demonstrates false-alarm resistance.",
        "base": {
            "metadata": {
                "name": "@supplyguard-demo/math",
                "version": "1.0.0",
                "description": "Math utility functions",
                "license": "Apache-2.0",
                "published_at": "2024-06-01T10:00:00Z",
                "author": "Math Core Team <dev@mathdemo.org>",
                "repo_url": "https://github.com/mathdemo/core",
                "dependencies": {},
                "lifecycle_scripts": {}
            },
            "files": {
                "package.json": '{\n  "name": "@supplyguard-demo/math",\n  "version": "1.0.0",\n  "main": "index.js",\n  "license": "Apache-2.0"\n}',
                "index.js": 'function add(a, b) {\n  return a + b;\n}\nmodule.exports = { add };\n'
            }
        },
        "target": {
            "metadata": {
                "name": "@supplyguard-demo/math",
                "version": "1.1.0",
                "description": "Math utility functions with vector support",
                "license": "Apache-2.0",
                "published_at": "2024-08-15T14:30:00Z",
                "author": "Math Core Team <dev@mathdemo.org>",
                "repo_url": "https://github.com/mathdemo/core",
                "dependencies": {},
                "lifecycle_scripts": {}
            },
            "files": {
                "package.json": '{\n  "name": "@supplyguard-demo/math",\n  "version": "1.1.0",\n  "main": "index.js",\n  "license": "Apache-2.0"\n}',
                "index.js": 'function add(a, b) {\n  return a + b;\n}\nfunction multiply(a, b) {\n  return a * b;\n}\nmodule.exports = { add, multiply };\n',
                "vector.js": 'function dotProduct(v1, v2) {\n  return v1.reduce((acc, val, i) => acc + val * v2[i], 0);\n}\nmodule.exports = { dotProduct };\n'
            }
        }
    },
    "case_c_suspicious_update": {
        "id": "demo-case-c",
        "category": "Suspicious Simulated Update",
        "title": "Supply Chain Compromise Simulation (supplyguard-demo-auth v1.0.0 vs v1.0.1)",
        "ecosystem": "npm",
        "package_name": "@supplyguard-demo/auth-helper",
        "base_version": "1.0.0",
        "target_version": "1.0.1",
        "description": "Controlled simulation of a compromised update. Harmlessly incorporates three classic supply-chain signals: 1) Newly added postinstall script; 2) Suspicious simulated base64 decode with dynamic eval pattern; 3) Simulated sensitive credential search pattern. No destructive actions are performed.",
        "expected_result": "HIGH RISK (BLOCK / REVIEW). Correctly triggers INS-001 (install hook), OBF-001 (encoded eval), and CRD-001 (credential path detection).",
        "base": {
            "metadata": {
                "name": "@supplyguard-demo/auth-helper",
                "version": "1.0.0",
                "description": "Token verification utilities",
                "license": "MIT",
                "published_at": "2024-01-15T09:00:00Z",
                "author": "Alice Auth <alice@auth.internal>",
                "repo_url": "https://github.com/auth-demo/helper",
                "dependencies": {},
                "lifecycle_scripts": {}
            },
            "files": {
                "package.json": '{\n  "name": "@supplyguard-demo/auth-helper",\n  "version": "1.0.0",\n  "main": "index.js",\n  "license": "MIT"\n}',
                "index.js": 'function verifyToken(token) {\n  return token && token.length > 10;\n}\nmodule.exports = { verifyToken };\n'
            }
        },
        "target": {
            "metadata": {
                "name": "@supplyguard-demo/auth-helper",
                "version": "1.0.1",
                "description": "Token verification utilities (patched)",
                "license": "MIT",
                "published_at": "2025-02-01T22:15:00Z",
                "author": "Alice Auth <alice@auth.internal>",
                "repo_url": "https://github.com/auth-demo/helper",
                "dependencies": {"unpinned-pkg": "*"},
                "lifecycle_scripts": {
                    "postinstall": "node ./scripts/check-env.js"
                }
            },
            "files": {
                "package.json": '{\n  "name": "@supplyguard-demo/auth-helper",\n  "version": "1.0.1",\n  "main": "index.js",\n  "scripts": {\n    "postinstall": "node ./scripts/check-env.js"\n  },\n  "dependencies": {\n    "unpinned-pkg": "*"\n  },\n  "license": "MIT"\n}',
                "index.js": 'function verifyToken(token) {\n  return token && token.length > 10;\n}\nmodule.exports = { verifyToken };\n',
                "scripts/check-env.js": '// SupplyGuard Demo Test Fixture - Safe Harmless Indicators\n// Simulates suspicious supply chain patterns without performing destructive acts\nconst dummyPayload = Buffer.from("VEVTVF9ERU1PX1BBWUxPQUQ=", "base64").toString("utf-8");\ntry {\n  eval(dummyPayload); // Harmless test trigger for dynamic execution detection\n} catch(e) {}\n\n// Harmless string reference to simulate credential-hunting pattern check\nconst simulatedSearch = process.env["NPM_TOKEN"] || "~/.ssh/id_rsa";\n'
            }
        }
    }
}
