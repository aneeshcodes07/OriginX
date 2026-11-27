import time
import uuid
import httpx
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload

from app.models.base import get_db
from app.models.entities import Scan, Finding, Vulnerability, Dependency
from app.schemas.all_schemas import (
    ScanCreateRequest, ScanResponse, FindingResponse, FalsePositiveUpdateRequest
)
from app.core.security import validate_package_identity
from app.core.config import settings
from app.services.registries.npm import NPMRegistryClient
from app.services.registries.pypi import PyPIRegistryClient
from app.services.vulnerability_intelligence.osv import OSVService
from app.services.static_analysis.engine import StaticAnalysisEngine
from app.services.metadata.analyzer import MetadataAnalyzer
from app.services.integrity.verifier import SafeArchiveInspector
from app.services.risk_engine.calculator import RiskEngine

router = APIRouter()

npm_client = NPMRegistryClient()
pypi_client = PyPIRegistryClient()
osv_service = OSVService()
static_engine = StaticAnalysisEngine()
metadata_analyzer = MetadataAnalyzer()
risk_engine = RiskEngine()

@router.post("/package", response_model=ScanResponse)
async def scan_package(
    req: ScanCreateRequest,
    db: AsyncSession = Depends(get_db)
):
    start_time = time.time()
    validate_package_identity(req.ecosystem, req.package_name, req.version)

    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        package_name=req.package_name,
        ecosystem=req.ecosystem.lower(),
        version=req.version or "latest",
        scan_type="registry",
        status="running",
        stage="Retrieving package metadata from public registry",
        is_demo=False
    )
    db.add(scan)
    await db.commit()

    try:
        # 1. Fetch registry metadata
        if req.ecosystem.lower() == "npm":
            raw_meta = await npm_client.get_package_metadata(req.package_name)
            resolved_version = npm_client.resolve_version(raw_meta, req.version)
            details = npm_client.extract_version_details(raw_meta, resolved_version)
        else:
            raw_meta = await pypi_client.get_package_metadata(req.package_name)
            resolved_version = pypi_client.resolve_version(raw_meta, req.version)
            details = pypi_client.extract_version_details(raw_meta, resolved_version)

        scan.version = resolved_version
        scan.stage = "Checking known vulnerabilities via OSV.dev"
        await db.commit()

        # 2. Vulnerability Intelligence
        vuln_res = await osv_service.query_vulnerabilities(
            package_name=req.package_name,
            ecosystem=req.ecosystem,
            version=resolved_version
        )
        parsed_vulns = vuln_res.get("vulnerabilities", [])

        # 3. Download & Inspect Archive contents safely
        scan.stage = "Downloading and inspecting package contents without code execution"
        await db.commit()

        extracted_files = {}
        integrity_ok = True
        tarball_url = details.get("tarball_url")

        if tarball_url:
            try:
                async with httpx.AsyncClient(timeout=15.0) as http_client:
                    t_resp = await http_client.get(tarball_url, headers={"User-Agent": "OriginX-Security-Scanner/1.0"})
                    if t_resp.status_code == 200:
                        archive_bytes = t_resp.content
                        fn = tarball_url.split("/")[-1].split("?")[0]
                        extracted_files, archive_meta = SafeArchiveInspector.safely_read_archive(fn, archive_bytes)
                        
                        # Verify integrity if hash provided
                        expected_sha256 = details.get("sha256")
                        if expected_sha256 and archive_meta["sha256"] != expected_sha256:
                            integrity_ok = False
            except Exception as e:
                # If download fails or archive cannot be parsed, note in coverage
                details["archive_error"] = str(e)

        # 4. Run Static Analysis on extracted files
        scan.stage = "Running static analysis rules"
        await db.commit()
        static_findings = static_engine.analyze_package_files(extracted_files)

        # 5. Metadata Anomaly Analysis
        meta_findings = metadata_analyzer.analyze_metadata(details, req.ecosystem)
        all_findings = static_findings + meta_findings

        # 6. Risk Scoring and Policy Evaluation
        scan.stage = "Evaluating risk model and security policies"
        await db.commit()

        score, classification, decision, reasons, breakdown = risk_engine.calculate_risk(
            vulnerabilities=parsed_vulns,
            findings=all_findings,
            metadata_findings=[],
            integrity_ok=integrity_ok
        )

        # Save findings to DB
        for f in all_findings:
            finding_rec = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan.id,
                rule_id=f["rule_id"],
                title=f["title"],
                severity=f["severity"],
                file_path=f.get("file_path"),
                line_number=f.get("line_number"),
                evidence_excerpt=f.get("evidence_excerpt"),
                explanation=f["explanation"],
                risk_reason=f["risk_reason"],
                confidence=f.get("confidence", "HIGH"),
                recommended_action=f["recommended_action"]
            )
            db.add(finding_rec)

        # Save vulnerabilities to DB
        for v in parsed_vulns:
            vuln_rec = Vulnerability(
                id=str(uuid.uuid4()),
                scan_id=scan.id,
                vuln_id=v["vuln_id"],
                summary=v.get("summary"),
                details=v.get("details"),
                severity=v.get("severity", "UNKNOWN"),
                affected_range=v.get("affected_range"),
                fixed_version=v.get("fixed_version"),
                source_url=v.get("source_url"),
                published_at=v.get("published_at")
            )
            db.add(vuln_rec)

        # Save dependencies to DB
        deps_dict = details.get("dependencies", {})
        for dname, dver in deps_dict.items():
            dep_rec = Dependency(
                id=str(uuid.uuid4()),
                scan_id=scan.id,
                name=dname,
                version=str(dver),
                dep_type="direct"
            )
            db.add(dep_rec)

        # Finalize scan record
        scan.status = "completed"
        scan.stage = "Analysis complete"
        scan.risk_score = score
        scan.risk_classification = classification
        scan.policy_decision = decision
        scan.policy_reasons = reasons
        scan.duration_ms = int((time.time() - start_time) * 1000)
        scan.coverage_summary = {
            "metadata_analyzed": True,
            "vulnerabilities_checked": vuln_res.get("service_status") == "ok",
            "vulnerability_service_status": vuln_res.get("service_status"),
            "static_analysis_files_count": len(extracted_files),
            "dynamic_sandbox": "skipped (sandbox not configured)",
            "integrity_verified": integrity_ok
        }
        scan.metadata_summary = {
            "description": details.get("description"),
            "license": details.get("license"),
            "published_at": details.get("published_at"),
            "author": details.get("author"),
            "repo_url": details.get("repo_url"),
            "direct_dependencies_count": len(deps_dict),
            "tarball_url": details.get("tarball_url"),
            "sha256": details.get("sha256"),
            "shasum": details.get("shasum"),
            "lifecycle_scripts": details.get("lifecycle_scripts")
        }

        await db.commit()

        # Reload with relationships
        stmt = (
            select(Scan)
            .where(Scan.id == scan.id)
            .options(
                selectinload(Scan.findings),
                selectinload(Scan.vulnerabilities),
                selectinload(Scan.dependencies)
            )
        )
        res = await db.execute(stmt)
        return res.scalar_one()

    except Exception as e:
        scan.status = "failed"
        scan.stage = f"Scan failed: {str(e)}"
        scan.error_message = str(e)
        scan.duration_ms = int((time.time() - start_time) * 1000)
        await db.commit()
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/archive", response_model=ScanResponse)
async def scan_archive(
    file: UploadFile = File(...),
    ecosystem: str = Query("npm", pattern="^(npm|pypi)$"),
    db: AsyncSession = Depends(get_db)
):
    start_time = time.time()
    filename = file.filename or "unknown.tar.gz"
    contents = await file.read()

    # Safely unpack in memory
    extracted_files, archive_meta = SafeArchiveInspector.safely_read_archive(filename, contents)

    # Deduce package name and version from manifest if present
    pkg_name = filename.split(".")[0]
    pkg_ver = "1.0.0"
    deps_dict = {}
    license_val = "UNKNOWN"
    lifecycle_scripts = {}

    if "package.json" in extracted_files or "package/package.json" in extracted_files:
        p_json_key = "package.json" if "package.json" in extracted_files else "package/package.json"
        try:
            import json
            pj = json.loads(extracted_files[p_json_key])
            pkg_name = pj.get("name", pkg_name)
            pkg_ver = pj.get("version", pkg_ver)
            deps_dict = pj.get("dependencies", {})
            license_val = pj.get("license", "UNKNOWN")
            lifecycle_scripts = pj.get("scripts", {})
        except Exception:
            pass

    scan = Scan(
        id=str(uuid.uuid4()),
        package_name=pkg_name,
        ecosystem=ecosystem.lower(),
        version=pkg_ver,
        scan_type="archive",
        status="running",
        stage="Static analysis of uploaded archive",
        is_demo=False
    )
    db.add(scan)
    await db.commit()

    # Static analysis
    static_findings = static_engine.analyze_package_files(extracted_files)

    # Vulnerability check if standard name/version was parsed
    vuln_res = await osv_service.query_vulnerabilities(pkg_name, ecosystem, pkg_ver)
    parsed_vulns = vuln_res.get("vulnerabilities", [])

    # Calculate risk
    score, classification, decision, reasons, breakdown = risk_engine.calculate_risk(
        vulnerabilities=parsed_vulns,
        findings=static_findings,
        metadata_findings=[],
        integrity_ok=True
    )

    for f in static_findings:
        finding_rec = Finding(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            rule_id=f["rule_id"],
            title=f["title"],
            severity=f["severity"],
            file_path=f.get("file_path"),
            line_number=f.get("line_number"),
            evidence_excerpt=f.get("evidence_excerpt"),
            explanation=f["explanation"],
            risk_reason=f["risk_reason"],
            confidence=f.get("confidence", "HIGH"),
            recommended_action=f["recommended_action"]
        )
        db.add(finding_rec)

    for v in parsed_vulns:
        vuln_rec = Vulnerability(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            vuln_id=v["vuln_id"],
            summary=v.get("summary"),
            details=v.get("details"),
            severity=v.get("severity", "UNKNOWN"),
            affected_range=v.get("affected_range"),
            fixed_version=v.get("fixed_version"),
            source_url=v.get("source_url")
        )
        db.add(vuln_rec)

    for dname, dver in deps_dict.items():
        dep_rec = Dependency(
            id=str(uuid.uuid4()),
            scan_id=scan.id,
            name=dname,
            version=str(dver),
            dep_type="direct"
        )
        db.add(dep_rec)

    scan.status = "completed"
    scan.stage = "Archive analysis complete"
    scan.risk_score = score
    scan.risk_classification = classification
    scan.policy_decision = decision
    scan.policy_reasons = reasons
    scan.duration_ms = int((time.time() - start_time) * 1000)
    scan.coverage_summary = {
        "upload_filename": filename,
        "files_analyzed": len(extracted_files),
        "total_extracted_size_bytes": archive_meta["total_extracted_size_bytes"],
        "sha256": archive_meta["sha256"]
    }
    scan.metadata_summary = {
        "license": license_val,
        "direct_dependencies_count": len(deps_dict),
        "lifecycle_scripts": lifecycle_scripts
    }

    await db.commit()

    stmt = (
        select(Scan)
        .where(Scan.id == scan.id)
        .options(
            selectinload(Scan.findings),
            selectinload(Scan.vulnerabilities),
            selectinload(Scan.dependencies)
        )
    )
    res = await db.execute(stmt)
    return res.scalar_one()

@router.get("", response_model=List[ScanResponse])
async def list_scans(
    ecosystem: Optional[str] = None,
    risk: Optional[str] = None,
    search: Optional[str] = None,
    is_demo: Optional[bool] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Scan).options(
        selectinload(Scan.findings),
        selectinload(Scan.vulnerabilities),
        selectinload(Scan.dependencies)
    ).order_by(desc(Scan.created_at))

    if ecosystem:
        stmt = stmt.where(Scan.ecosystem == ecosystem.lower())
    if risk:
        stmt = stmt.where(Scan.risk_classification == risk.upper())
    if is_demo is not None:
        stmt = stmt.where(Scan.is_demo == is_demo)
    if search:
        stmt = stmt.where(Scan.package_name.ilike(f"%{search}%"))

    stmt = stmt.offset(offset).limit(limit)
    res = await db.execute(stmt)
    return res.scalars().all()

@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan_by_id(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(Scan)
        .where(Scan.id == scan_id)
        .options(
            selectinload(Scan.findings),
            selectinload(Scan.vulnerabilities),
            selectinload(Scan.dependencies)
        )
    )
    res = await db.execute(stmt)
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return scan

@router.patch("/{scan_id}/findings/{finding_id}", response_model=FindingResponse)
async def update_finding_false_positive(
    scan_id: str,
    finding_id: str,
    req: FalsePositiveUpdateRequest,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Finding).where(Finding.id == finding_id, Finding.scan_id == scan_id)
    res = await db.execute(stmt)
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    finding.is_false_positive = req.is_false_positive
    if req.analyst_note is not None:
        finding.analyst_note = req.analyst_note

    await db.commit()
    await db.refresh(finding)
    return finding

@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Scan).where(Scan.id == scan_id)
    res = await db.execute(stmt)
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    await db.delete(scan)
    await db.commit()
    return None
