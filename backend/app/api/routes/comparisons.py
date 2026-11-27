import logging
import uuid
from typing import Dict, Any, Tuple
from urllib.parse import urljoin
import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.base import get_db
from app.models.entities import VersionComparison
from app.schemas.all_schemas import VersionComparisonRequest, VersionComparisonResponse
from app.core.config import settings
from app.core.security import validate_package_identity, validate_outbound_url
from app.services.registries.npm import NPMRegistryClient
from app.services.registries.pypi import PyPIRegistryClient
from app.services.integrity.verifier import SafeArchiveInspector
from app.services.version_diff.comparator import VersionComparator

logger = logging.getLogger("supplyguard.comparisons")

router = APIRouter()

npm_client = NPMRegistryClient()
pypi_client = PyPIRegistryClient()
comparator = VersionComparator()

# Magic byte signatures for supported archive formats
VALID_ARCHIVE_SIGNATURES = [
    b"\x1f\x8b",            # gzip (.tgz, .tar.gz)
    b"PK\x03\x04",          # zip (.zip, .whl)
    b"PK\x05\x06",          # zip empty
    b"PK\x07\x08",          # zip spanned
    b"\x42\x5a\x68",        # bzip2 (.tar.bz2)
    b"\xfd7zXZ\x00",        # xz (.tar.xz)
]

async def fetch_archive_safely(
    client: httpx.AsyncClient,
    initial_url: str,
    version_label: str,
    package_name: str,
    max_redirects: int = 5
) -> Tuple[bytes, str]:
    """
    Downloads package tarball with SSRF protection on every hop,
    including redirect locations. Enforces size, status code, and content validation.
    """
    current_url = initial_url
    logger.info(
        "Initiating archive download: package=%s version=%s initial_url=%s",
        package_name, version_label, initial_url
    )

    for hop in range(max_redirects + 1):
        # Validate URL and resolve DNS against forbidden CIDRs and allowlists
        validate_outbound_url(current_url)

        try:
            resp = await client.get(
                current_url,
                headers={"User-Agent": "OriginX-Security-Scanner/1.0"},
                follow_redirects=False
            )
        except httpx.TimeoutException as e:
            logger.error(
                "Timeout downloading archive: package=%s version=%s url=%s error=%s",
                package_name, version_label, current_url, str(e)
            )
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail=f"Timeout downloading archive for version '{version_label}' from '{current_url}'."
            )
        except httpx.RequestError as e:
            logger.error(
                "Network request error downloading archive: package=%s version=%s url=%s error=%s",
                package_name, version_label, current_url, str(e)
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to connect to archive source for version '{version_label}': {str(e)}"
            )

        # Handle redirect hops with SSRF validation on the target location
        if resp.is_redirect:
            redirect_target = resp.headers.get("location")
            if not redirect_target:
                logger.error(
                    "Redirect missing Location header: package=%s version=%s url=%s status=%s",
                    package_name, version_label, current_url, resp.status_code
                )
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=f"Archive download redirect for version '{version_label}' returned status {resp.status_code} without Location header."
                )

            next_url = urljoin(str(resp.url), redirect_target)
            logger.info(
                "Archive download redirect hop %d: package=%s version=%s next_url=%s",
                hop + 1, package_name, version_label, next_url
            )
            current_url = next_url
            continue

        # Terminal response validation
        if resp.status_code != 200:
            logger.error(
                "Archive download failed: package=%s version=%s url=%s status=%d body=%s",
                package_name, version_label, current_url, resp.status_code, resp.text[:200]
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Registry returned HTTP {resp.status_code} while downloading archive for version '{version_label}'."
            )

        content = resp.content
        content_len = len(content)

        if content_len == 0:
            logger.error(
                "Downloaded empty archive: package=%s version=%s url=%s",
                package_name, version_label, current_url
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Archive for version '{version_label}' is empty (0 bytes received)."
            )

        if content_len > settings.MAX_ARCHIVE_SIZE_BYTES:
            logger.error(
                "Archive exceeds size limit: package=%s version=%s size=%d max=%d",
                package_name, version_label, content_len, settings.MAX_ARCHIVE_SIZE_BYTES
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Archive for version '{version_label}' ({content_len} bytes) exceeds maximum allowed limit of {settings.MAX_ARCHIVE_SIZE_BYTES} bytes."
            )

        # Validate file header / signature or standard tar magic
        is_tar = content_len >= 512 and (
            content[257:262] == b"ustar" or any(content.startswith(sig) for sig in VALID_ARCHIVE_SIGNATURES)
        )
        if not is_tar and not any(content.startswith(sig) for sig in VALID_ARCHIVE_SIGNATURES):
            logger.error(
                "Invalid archive signature: package=%s version=%s header=%r",
                package_name, version_label, content[:16]
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Archive for version '{version_label}' does not have a recognized valid archive header or format."
            )

        filename = current_url.split("/")[-1].split("?")[0] or f"{package_name}-{version_label}.tgz"
        logger.info(
            "Archive successfully downloaded: package=%s version=%s filename=%s size_bytes=%d",
            package_name, version_label, filename, content_len
        )
        return content, filename

    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"Exceeded maximum redirects ({max_redirects}) downloading archive for version '{version_label}'."
    )


@router.post("", response_model=VersionComparisonResponse)
async def create_version_comparison(
    req: VersionComparisonRequest,
    db: AsyncSession = Depends(get_db)
):
    validate_package_identity(req.ecosystem, req.package_name, req.base_version)
    validate_package_identity(req.ecosystem, req.package_name, req.target_version)

    logger.info(
        "Starting version comparison: ecosystem=%s package=%s base=%s target=%s",
        req.ecosystem, req.package_name, req.base_version, req.target_version
    )

    # 1. Fetch metadata for both versions
    try:
        if req.ecosystem.lower() == "npm":
            raw_meta = await npm_client.get_package_metadata(req.package_name)
            base_meta = npm_client.extract_version_details(raw_meta, req.base_version)
            target_meta = npm_client.extract_version_details(raw_meta, req.target_version)
        else:
            raw_meta = await pypi_client.get_package_metadata(req.package_name)
            base_meta = pypi_client.extract_version_details(raw_meta, req.base_version)
            target_meta = pypi_client.extract_version_details(raw_meta, req.target_version)
    except ValueError as ve:
        logger.warning(
            "Version or package resolution failed: package=%s error=%s",
            req.package_name, str(ve)
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except Exception as e:
        logger.error(
            "Metadata fetch error: package=%s error=%s",
            req.package_name, str(e), exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to retrieve metadata for '{req.package_name}': {str(e)}"
        )

    base_tarball_url = base_meta.get("tarball_url")
    target_tarball_url = target_meta.get("tarball_url")

    if not base_tarball_url:
        logger.error(
            "Missing tarball URL for base version: package=%s version=%s",
            req.package_name, req.base_version
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No archive URL found in registry metadata for base version '{req.base_version}'."
        )

    if not target_tarball_url:
        logger.error(
            "Missing tarball URL for target version: package=%s version=%s",
            req.package_name, req.target_version
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"No archive URL found in registry metadata for target version '{req.target_version}'."
        )

    # 2. Safely download and inspect archives
    async with httpx.AsyncClient(timeout=settings.HTTP_TIMEOUT_SECONDS) as client:
        # Base version archive
        base_bytes, base_filename = await fetch_archive_safely(
            client=client,
            initial_url=base_tarball_url,
            version_label=req.base_version,
            package_name=req.package_name
        )
        logger.info(
            "Extracting base archive: filename=%s size_bytes=%d",
            base_filename, len(base_bytes)
        )
        base_files, base_archive_meta = SafeArchiveInspector.safely_read_archive(
            base_filename, base_bytes
        )
        logger.info(
            "Base archive extracted: file_count=%d analyzed_text_files=%d",
            base_archive_meta.get("file_count", 0), len(base_files)
        )

        # Target version archive
        target_bytes, target_filename = await fetch_archive_safely(
            client=client,
            initial_url=target_tarball_url,
            version_label=req.target_version,
            package_name=req.package_name
        )
        logger.info(
            "Extracting target archive: filename=%s size_bytes=%d",
            target_filename, len(target_bytes)
        )
        target_files, target_archive_meta = SafeArchiveInspector.safely_read_archive(
            target_filename, target_bytes
        )
        logger.info(
            "Target archive extracted: file_count=%d analyzed_text_files=%d",
            target_archive_meta.get("file_count", 0), len(target_files)
        )

    # 3. Compare using VersionComparator without executing any code
    result = comparator.compare_versions(
        base_meta=base_meta,
        target_meta=target_meta,
        base_files=base_files,
        target_files=target_files
    )

    summary = result["summary"]
    diff_details = result["diff_details"]

    # Record archive sizes and extracted counts in summary and diff details
    summary["archive_inspection"] = {
        "status": "complete",
        "base": {
            "archive_size_bytes": base_archive_meta.get("archive_size_bytes", len(base_bytes)),
            "extracted_file_count": base_archive_meta.get("file_count", 0),
            "analyzed_file_count": len(base_files),
            "sha256": base_archive_meta.get("sha256")
        },
        "target": {
            "archive_size_bytes": target_archive_meta.get("archive_size_bytes", len(target_bytes)),
            "extracted_file_count": target_archive_meta.get("file_count", 0),
            "analyzed_file_count": len(target_files),
            "sha256": target_archive_meta.get("sha256")
        }
    }
    diff_details["base_archive_meta"] = base_archive_meta
    diff_details["target_archive_meta"] = target_archive_meta

    comp_rec = VersionComparison(
        id=str(uuid.uuid4()),
        package_name=req.package_name,
        ecosystem=req.ecosystem.lower(),
        base_version=req.base_version,
        target_version=req.target_version,
        files_added_count=summary["files_added_count"],
        files_removed_count=summary["files_removed_count"],
        files_modified_count=summary["files_modified_count"],
        deps_added_count=summary["deps_added_count"],
        deps_removed_count=summary["deps_removed_count"],
        install_scripts_changed=summary["install_scripts_changed"],
        summary_json=summary,
        diff_details_json=diff_details
    )

    db.add(comp_rec)
    await db.commit()
    await db.refresh(comp_rec)
    return comp_rec

@router.get("/{comparison_id}", response_model=VersionComparisonResponse)
async def get_comparison(
    comparison_id: str,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(VersionComparison).where(VersionComparison.id == comparison_id)
    res = await db.execute(stmt)
    comp = res.scalar_one_or_none()
    if not comp:
        raise HTTPException(status_code=404, detail="Version comparison not found.")
    return comp
