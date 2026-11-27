import pytest
from app.services.version_diff.comparator import VersionComparator

def test_version_prefixed_root_normalization():
    """
    Regression test: PyPI sdist tarballs frequently pack files into a versioned root
    directory (e.g. 'pkg-1.0.0/foo.py' vs 'pkg-1.1.0/foo.py').
    Comparator must normalize common root directory prefix to accurately identify modified
    vs added/removed files rather than falsely declaring all files as 100% added and removed.
    """
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    base_files = {
        "urllib3-1.0.0/setup.py": "version = '1.0.0'\n",
        "urllib3-1.0.0/urllib3/util.py": "def connect(): return True\n"
    }
    target_files = {
        "urllib3-1.1.0/setup.py": "version = '1.1.0'\n",
        "urllib3-1.1.0/urllib3/util.py": "def connect(): return True\n"
    }

    res = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    summary = res["summary"]
    diff = res["diff_details"]

    assert summary["files_added_count"] == 0
    assert summary["files_removed_count"] == 0
    assert summary["files_modified_count"] == 1
    assert "setup.py" in diff["modified_files"]


def test_zero_difference_comparison():
    """
    Identical versions should correctly report 0 added, 0 removed, 0 modified files
    with risk score 0.0 and decision ALLOW.
    """
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.0.0"}

    files = {"index.js": "console.log('identical');\n"}
    res = comparator.compare_versions(base_meta, target_meta, files, files)
    summary = res["summary"]

    assert summary["files_added_count"] == 0
    assert summary["files_removed_count"] == 0
    assert summary["files_modified_count"] == 0
    assert summary["security_analysis"]["risk_score"] == 0.0
    assert summary["security_analysis"]["policy_decision"] == "ALLOW"
