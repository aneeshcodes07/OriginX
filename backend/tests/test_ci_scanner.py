import subprocess
import sys
import json
from pathlib import Path

def test_ci_scanner_allow_exit_code():
    """Verify that a clean package manifest exits with code 0 (ALLOW)."""
    manifest_path = Path("frontend/package.json")
    res = subprocess.run(
        [sys.executable, "backend/app/cli/ci_scanner.py", "--manifest", str(manifest_path), "--policy-fail", "BLOCK"],
        capture_output=True,
        text=True
    )
    assert res.returncode == 0
    assert "ALLOW" in res.stdout
    assert Path("originx-report.json").exists() or Path("supplyguard-report.json").exists()
    Path("originx-report.json").unlink(missing_ok=True)
    Path("supplyguard-report.json").unlink(missing_ok=True)


def test_ci_scanner_missing_manifest_fails():
    """Verify that a missing manifest exits with non-zero code."""
    res = subprocess.run(
        [sys.executable, "backend/app/cli/ci_scanner.py", "--manifest", "non_existent_file.json"],
        capture_output=True,
        text=True
    )
    assert res.returncode != 0
