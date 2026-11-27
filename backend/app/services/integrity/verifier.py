import hashlib
import io
import os
import tarfile
import tempfile
import zipfile
from typing import Dict, Any, List, Tuple
from fastapi import HTTPException
from app.core.config import settings

class SafeArchiveInspector:
    """
    Safely inspects and extracts .tgz, .tar.gz, .whl, and .zip archives
    without executing any code. Protects against:
    - Path traversal attacks (Zip Slip)
    - Archive bombs / zip bombs
    - Symlink abuse / out-of-boundary references
    - Max file count & size limits
    """

    @staticmethod
    def compute_sha256(content_bytes: bytes) -> str:
        return hashlib.sha256(content_bytes).hexdigest()

    @staticmethod
    def compute_sha512(content_bytes: bytes) -> str:
        return hashlib.sha512(content_bytes).hexdigest()

    @classmethod
    def safely_read_archive(
        cls,
        filename: str,
        archive_bytes: bytes
    ) -> Tuple[Dict[str, str], Dict[str, Any]]:
        """
        Extracts textual files into an in-memory dictionary {filepath: content_str}
        strictly bounded by configured resource limits.
        """
        if len(archive_bytes) > settings.MAX_ARCHIVE_SIZE_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"Archive size ({len(archive_bytes)} bytes) exceeds maximum allowable limit of {settings.MAX_ARCHIVE_SIZE_BYTES} bytes."
            )

        fn_lower = filename.lower()
        extracted_files: Dict[str, str] = {}
        total_extracted_size = 0
        file_count = 0
        file_listing: List[str] = []

        if fn_lower.endswith(".zip") or fn_lower.endswith(".whl"):
            # Handle ZIP / WHL
            try:
                with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
                    for info in zf.infolist():
                        file_count += 1
                        if file_count > settings.MAX_ARCHIVE_FILES:
                            raise HTTPException(status_code=400, detail="Archive exceeds maximum allowed file count limit.")
                            
                        # Path traversal protection
                        target_path = info.filename
                        if ".." in target_path or target_path.startswith("/") or target_path.startswith("\\"):
                            raise HTTPException(status_code=400, detail=f"Unsafe file path detected in archive: '{target_path}'.")
                            
                        # Check path depth
                        if len(target_path.replace("\\", "/").split("/")) > settings.MAX_RECURSION_DEPTH:
                            raise HTTPException(status_code=400, detail=f"File nesting depth exceeded for '{target_path}'.")
                            
                        file_listing.append(target_path)
                        total_extracted_size += info.file_size
                        if total_extracted_size > settings.MAX_EXTRACTED_SIZE_BYTES:
                            raise HTTPException(status_code=400, detail="Archive exceeds maximum allowable uncompressed size (zip bomb protection).")

                        # Read text contents of analyzable files
                        if any(target_path.endswith(ext) for ext in [".js", ".mjs", ".cjs", ".ts", ".py", ".json", ".sh", ".bat", ".toml", ".txt", ".md", ".yml", ".yaml"]):
                            if info.file_size < 1024 * 1024:  # max 1MB per analyzed text file
                                try:
                                    raw = zf.read(info)
                                    extracted_files[target_path] = raw.decode("utf-8", errors="replace")
                                except Exception:
                                    pass
            except zipfile.BadZipFile:
                raise HTTPException(status_code=400, detail="Corrupted or invalid ZIP/WHL archive structure.")

        elif fn_lower.endswith(".tgz") or fn_lower.endswith(".tar.gz") or fn_lower.endswith(".tar"):
            # Handle Tarball / TGZ
            try:
                with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as tf:
                    for member in tf.getmembers():
                        file_count += 1
                        if file_count > settings.MAX_ARCHIVE_FILES:
                            raise HTTPException(status_code=400, detail="Archive exceeds maximum allowed file count limit.")

                        target_path = member.name
                        # Path traversal & symlink protection
                        if ".." in target_path or target_path.startswith("/") or target_path.startswith("\\"):
                            raise HTTPException(status_code=400, detail=f"Unsafe path in tarball: '{target_path}'.")
                            
                        if member.issym() or member.islnk():
                            # Check link target
                            link_target = member.linkname
                            if ".." in link_target or link_target.startswith("/"):
                                raise HTTPException(status_code=400, detail=f"Dangerous symlink target '{link_target}' in archive.")

                        file_listing.append(target_path)
                        total_extracted_size += member.size
                        if total_extracted_size > settings.MAX_EXTRACTED_SIZE_BYTES:
                            raise HTTPException(status_code=400, detail="Tarball exceeds maximum allowable uncompressed size.")

                        if member.isfile() and any(target_path.endswith(ext) for ext in [".js", ".mjs", ".cjs", ".ts", ".py", ".json", ".sh", ".bat", ".toml", ".txt", ".md", ".yml", ".yaml"]):
                            if member.size < 1024 * 1024:
                                try:
                                    f_obj = tf.extractfile(member)
                                    if f_obj:
                                        raw = f_obj.read()
                                        extracted_files[target_path] = raw.decode("utf-8", errors="replace")
                                except Exception:
                                    pass
            except (tarfile.TarError, EOFError, OSError) as e:
                raise HTTPException(status_code=400, detail=f"Corrupted or invalid Tar archive: {str(e)}")
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported package archive format: '{filename}'. Supported extensions: .tgz, .tar.gz, .whl, .zip."
            )

        archive_meta = {
            "filename": filename,
            "archive_size_bytes": len(archive_bytes),
            "total_extracted_size_bytes": total_extracted_size,
            "file_count": file_count,
            "file_listing": file_listing[:100],
            "sha256": cls.compute_sha256(archive_bytes)
        }

        return extracted_files, archive_meta
