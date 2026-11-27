import json
import re
from typing import Dict, Any, List, Optional

POPULAR_PACKAGES = [
    "express", "lodash", "react", "react-dom", "axios", "chalk", "debug",
    "commander", "moment", "request", "tslib", "vue", "next", "webpack",
    "requests", "numpy", "pandas", "flask", "django", "urllib3", "scipy",
    "torch", "pytest", "setuptools", "wheel", "boto3", "click"
]

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

class DependencyParser:
    """
    Parses package.json, package-lock.json, requirements.txt, pyproject.toml
    and extracts structured dependency trees, unpinned warnings, and typosquatting signals.
    """

    @staticmethod
    def detect_typosquatting(name: str) -> Optional[str]:
        clean = name.lower().strip()
        for pop in POPULAR_PACKAGES:
            if clean != pop and levenshtein_distance(clean, pop) == 1:
                return f"Potential typosquat of popular package '{pop}' (distance=1)"
        return None

    @classmethod
    def parse_manifest(cls, filename: str, content: str) -> Dict[str, Any]:
        fn = filename.lower()
        dependencies: List[Dict[str, Any]] = []
        issues: List[Dict[str, Any]] = []
        ecosystem = "unknown"

        if fn.endswith("package.json"):
            ecosystem = "npm"
            try:
                data = json.loads(content)
                deps = data.get("dependencies", {})
                dev_deps = data.get("devDependencies", {})
                opt_deps = data.get("optionalDependencies", {})

                for name, ver in deps.items():
                    typo = cls.detect_typosquatting(name)
                    is_unpinned = ver.strip() in ["*", "latest"] or ver.startswith("^") or ver.startswith(">=")
                    dep_obj = {
                        "name": name,
                        "version": ver,
                        "dep_type": "direct",
                        "depth": 1,
                        "is_unpinned": is_unpinned,
                        "typosquat_warning": typo
                    }
                    dependencies.append(dep_obj)
                    if typo:
                        issues.append({"package": name, "reason": typo, "severity": "HIGH"})
                    if ver.strip() in ["*", "latest"]:
                        issues.append({"package": name, "reason": f"Wildcard version '{ver}' leaves package open to unexpected upstream changes.", "severity": "MEDIUM"})

                for name, ver in dev_deps.items():
                    typo = cls.detect_typosquatting(name)
                    dependencies.append({
                        "name": name,
                        "version": ver,
                        "dep_type": "dev",
                        "depth": 1,
                        "is_unpinned": False,
                        "typosquat_warning": typo
                    })

                for name, ver in opt_deps.items():
                    dependencies.append({
                        "name": name,
                        "version": ver,
                        "dep_type": "optional",
                        "depth": 1,
                        "is_unpinned": False,
                        "typosquat_warning": None
                    })

            except json.JSONDecodeError:
                issues.append({"package": "package.json", "reason": "Failed to parse JSON content.", "severity": "HIGH"})

        elif fn.endswith("package-lock.json"):
            ecosystem = "npm"
            try:
                data = json.loads(content)
                # npm lockfile v2/v3 has 'packages' map
                packages = data.get("packages", {})
                if packages:
                    for pkg_path, pkg_info in packages.items():
                        if not pkg_path:  # root
                            continue
                        clean_name = pkg_path.replace("node_modules/", "")
                        # only get last component for name
                        actual_name = clean_name.split("node_modules/")[-1]
                        depth = pkg_path.count("node_modules/")
                        dependencies.append({
                            "name": actual_name,
                            "version": pkg_info.get("version", "unknown"),
                            "dep_type": "transitive" if depth > 1 else "direct",
                            "depth": depth,
                            "is_unpinned": False,
                            "typosquat_warning": cls.detect_typosquatting(actual_name)
                        })
                else:
                    # fallback to older 'dependencies' tree
                    deps = data.get("dependencies", {})
                    for name, info in deps.items():
                        dependencies.append({
                            "name": name,
                            "version": info.get("version", "unknown"),
                            "dep_type": "direct",
                            "depth": 1,
                            "is_unpinned": False,
                            "typosquat_warning": cls.detect_typosquatting(name)
                        })
            except json.JSONDecodeError:
                issues.append({"package": "package-lock.json", "reason": "Failed to parse lockfile JSON.", "severity": "HIGH"})

        elif fn.endswith("requirements.txt"):
            ecosystem = "pypi"
            lines = content.splitlines()
            for line in lines:
                l = line.strip()
                if not l or l.startswith("#") or l.startswith("-r") or l.startswith("-i"):
                    continue
                # Match pip spec like package==1.2.3 or package>=1.0
                match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=><~^!].*)?$", l)
                if match:
                    pname = match.group(1)
                    pver = match.group(2) or "*"
                    typo = cls.detect_typosquatting(pname)
                    is_unpinned = (pver == "*" or ">=" in pver or "~=" in pver)
                    dependencies.append({
                        "name": pname,
                        "version": pver,
                        "dep_type": "direct",
                        "depth": 1,
                        "is_unpinned": is_unpinned,
                        "typosquat_warning": typo
                    })
                    if typo:
                        issues.append({"package": pname, "reason": typo, "severity": "HIGH"})
                    if pver == "*":
                        issues.append({"package": pname, "reason": "Unpinned wildcard package version.", "severity": "MEDIUM"})

        elif fn.endswith("pyproject.toml"):
            ecosystem = "pypi"
            # Simple line parser for pyproject dependencies
            lines = content.splitlines()
            in_deps = False
            for line in lines:
                l = line.strip()
                if "dependencies" in l and "=" in l:
                    in_deps = True
                    continue
                if in_deps:
                    if l.startswith("]"):
                        in_deps = False
                        continue
                    m = re.search(r"['\"]([a-zA-Z0-9_.-]+)(.*?)['\"]", l)
                    if m:
                        name = m.group(1)
                        ver = m.group(2) or "*"
                        dependencies.append({
                            "name": name,
                            "version": ver.strip(),
                            "dep_type": "direct",
                            "depth": 1,
                            "is_unpinned": ver.strip() in ["", "*"],
                            "typosquat_warning": cls.detect_typosquatting(name)
                        })

        return {
            "ecosystem": ecosystem,
            "filename": filename,
            "total_dependencies": len(dependencies),
            "dependencies": dependencies,
            "issues": issues
        }
