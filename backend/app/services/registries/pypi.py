from typing import Dict, Any, Optional, List
import httpx
from app.core.config import settings
from app.core.security import validate_outbound_url

class PyPIRegistryClient:
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = (base_url or settings.PYPI_REGISTRY_URL).rstrip("/")
        validate_outbound_url(self.base_url)

    async def get_package_metadata(self, package_name: str) -> Dict[str, Any]:
        """
        Retrieves real package metadata from PyPI JSON API.
        """
        url = f"{self.base_url}/{package_name}/json"
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                url,
                headers={"Accept": "application/json", "User-Agent": "OriginX-Security-Scanner/1.0"}
            )
            if resp.status_code == 404:
                raise ValueError(f"Package '{package_name}' not found on PyPI registry.")
            if resp.status_code != 200:
                raise RuntimeError(f"PyPI registry returned error {resp.status_code}: {resp.text[:200]}")
            return resp.json()

    def resolve_version(self, metadata: Dict[str, Any], requested_version: Optional[str] = None) -> str:
        info = metadata.get("info", {})
        releases = metadata.get("releases", {})
        
        if not requested_version or requested_version == "latest":
            latest = info.get("version")
            if latest:
                return latest
            if releases:
                return list(releases.keys())[-1]
            raise ValueError("No releases available for this PyPI package.")
            
        if requested_version in releases:
            return requested_version
            
        raise ValueError(f"Version '{requested_version}' does not exist on PyPI for '{info.get('name')}'. Available versions: {list(releases.keys())[-10:]}")

    def extract_version_details(self, metadata: Dict[str, Any], version: str) -> Dict[str, Any]:
        info = metadata.get("info", {})
        releases = metadata.get("releases", {})
        files = releases.get(version, [])
        
        # Pick primary distribution (wheel or source tar.gz)
        primary_file = None
        for f in files:
            if f.get("packagetype") == "sdist":
                primary_file = f
                break
        if not primary_file and files:
            primary_file = files[0]
            
        published_at = primary_file.get("upload_time_iso_8601") if primary_file else None
        tarball_url = primary_file.get("url") if primary_file else None
        digests = primary_file.get("digests", {}) if primary_file else {}
        sha256 = digests.get("sha256")
        
        # Parse dependencies from requires_dist
        requires_dist = info.get("requires_dist") or []
        dependencies = {}
        for req in requires_dist:
            # req example: "requests>=2.25.0; extra == 'dev'"
            parts = req.split(";")
            spec = parts[0].strip()
            dependencies[spec] = parts[1].strip() if len(parts) > 1 else "*"
            
        project_urls = info.get("project_urls") or {}
        repo_url = project_urls.get("Source") or project_urls.get("Repository") or project_urls.get("Homepage") or info.get("home_page")

        return {
            "name": info.get("name"),
            "version": version,
            "description": info.get("summary", ""),
            "license": info.get("license") or "UNKNOWN",
            "published_at": published_at,
            "tarball_url": tarball_url,
            "sha256": sha256,
            "author": info.get("author"),
            "author_email": info.get("author_email"),
            "maintainer": info.get("maintainer"),
            "repo_url": repo_url,
            "dependencies": dependencies,
            "devDependencies": {},
            "lifecycle_scripts": {},  # PyPI packages use setup.py / build hooks
            "all_versions": list(releases.keys()),
            "requires_python": info.get("requires_python"),
            "yanked": info.get("yanked", False),
            "yanked_reason": info.get("yanked_reason")
        }
