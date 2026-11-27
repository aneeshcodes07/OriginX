from typing import Dict, Any, Optional, List
from datetime import datetime
import httpx
from app.core.config import settings
from app.core.security import validate_outbound_url

class NPMRegistryClient:
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = (base_url or settings.NPM_REGISTRY_URL).rstrip("/")
        validate_outbound_url(self.base_url)

    async def get_package_metadata(self, package_name: str) -> Dict[str, Any]:
        """
        Retrieves real package metadata from npm registry.
        Supports scoped packages like @angular/core.
        """
        encoded_name = package_name.replace("/", "%2F")
        url = f"{self.base_url}/{encoded_name}"
        
        async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                url,
                headers={"Accept": "application/json", "User-Agent": "OriginX-Security-Scanner/1.0"}
            )
            if resp.status_code == 404:
                raise ValueError(f"Package '{package_name}' not found on npm registry.")
            if resp.status_code != 200:
                raise RuntimeError(f"npm registry returned error {resp.status_code}: {resp.text[:200]}")
            return resp.json()

    def resolve_version(self, metadata: Dict[str, Any], requested_version: Optional[str] = None) -> str:
        dist_tags = metadata.get("dist-tags", {})
        versions = metadata.get("versions", {})
        
        if not requested_version or requested_version == "latest":
            latest = dist_tags.get("latest")
            if latest and latest in versions:
                return latest
            # If no 'latest' tag, pick the latest key in versions
            if versions:
                return list(versions.keys())[-1]
            raise ValueError("No versions available for this package.")
            
        if requested_version in versions:
            return requested_version
            
        # Check if version exists in dist-tags
        if requested_version in dist_tags:
            return dist_tags[requested_version]
            
        raise ValueError(f"Version '{requested_version}' does not exist on npm for '{metadata.get('name')}'. Available versions: {list(versions.keys())[-10:]}")

    def extract_version_details(self, metadata: Dict[str, Any], version: str) -> Dict[str, Any]:
        ver_data = metadata.get("versions", {}).get(version, {})
        time_data = metadata.get("time", {})
        published_at = time_data.get(version)
        
        dist = ver_data.get("dist", {})
        tarball_url = dist.get("tarball")
        shasum = dist.get("shasum")
        integrity = dist.get("integrity")
        
        maintainers = metadata.get("maintainers", [])
        author = ver_data.get("author") or metadata.get("author")
        
        # Parse scripts
        scripts = ver_data.get("scripts", {})
        lifecycle_scripts = {}
        for s_name in ["preinstall", "install", "postinstall", "prepublish", "prepare"]:
            if s_name in scripts:
                lifecycle_scripts[s_name] = scripts[s_name]
                
        # Parse dependencies
        dependencies = ver_data.get("dependencies", {})
        dev_dependencies = ver_data.get("devDependencies", {})
        peer_dependencies = ver_data.get("peerDependencies", {})
        
        # Repository
        repository = ver_data.get("repository") or metadata.get("repository")
        repo_url = repository.get("url") if isinstance(repository, dict) else str(repository) if repository else None

        return {
            "name": metadata.get("name"),
            "version": version,
            "description": ver_data.get("description") or metadata.get("description", ""),
            "license": ver_data.get("license") or "UNLICENSED",
            "published_at": published_at,
            "tarball_url": tarball_url,
            "shasum": shasum,
            "integrity": integrity,
            "author": author,
            "maintainers": maintainers,
            "repo_url": repo_url,
            "dependencies": dependencies,
            "devDependencies": dev_dependencies,
            "peerDependencies": peer_dependencies,
            "lifecycle_scripts": lifecycle_scripts,
            "all_versions": list(metadata.get("versions", {}).keys()),
            "dist_tags": metadata.get("dist-tags", {}),
            "unpacked_size": dist.get("unpackedSize"),
            "file_count": dist.get("fileCount")
        }
