import uuid
import time
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from sqlalchemy.orm import selectinload

from app.models.base import get_db
from app.models.entities import Scan, Finding, Vulnerability, Dependency, VersionComparison
from app.schemas.all_schemas import ScanResponse, VersionComparisonResponse
from app.services.demo.fixtures import DEMO_FIXTURES
from app.services.static_analysis.engine import StaticAnalysisEngine
from app.services.version_diff.comparator import VersionComparator
from app.services.risk_engine.calculator import RiskEngine

router = APIRouter()
static_engine = StaticAnalysisEngine()
comparator = VersionComparator()
risk_engine = RiskEngine()

@router.get("/fixtures")
async def list_demo_fixtures():
    """
    Returns metadata for the controlled demo fixtures.
    """
    items = []
    for key, data in DEMO_FIXTURES.items():
        items.append({
            "fixture_key": key,
            "id": data["id"],
            "category": data["category"],
            "title": data["title"],
            "ecosystem": data["ecosystem"],
            "package_name": data["package_name"],
            "version": data.get("version") or f"{data.get('base_version')} -> {data.get('target_version')}",
            "description": data["description"],
            "expected_result": data["expected_result"]
        })
    return items

@router.post("/run/{fixture_key}", response_model=ScanResponse)
async def run_demo_fixture(
    fixture_key: str,
    db: AsyncSession = Depends(get_db)
):
    if fixture_key not in DEMO_FIXTURES:
        raise HTTPException(status_code=404, detail=f"Demo fixture '{fixture_key}' not found.")

    fixture = DEMO_FIXTURES[fixture_key]
    start_time = time.time()

    if fixture_key == "case_a_normal":
        meta = fixture["metadata"]
        files = fixture["files"]
        
        # Real static analysis on harmless fixture
        findings = static_engine.analyze_package_files(files)
        # Real risk engine calculation
        score, classification, decision, reasons, breakdown = risk_engine.calculate_risk(
            vulnerabilities=[],
            findings=findings,
            metadata_findings=[],
            integrity_ok=True
        )

        scan = Scan(
            id=str(uuid.uuid4()),
            package_name=fixture["package_name"],
            ecosystem="npm",
            version="1.0.0",
            scan_type="demo",
            status="completed",
            stage="Analysis complete (Controlled Demo Fixture)",
            risk_score=score,
            risk_classification=classification,
            policy_decision=decision,
            policy_reasons=reasons,
            is_demo=True,
            duration_ms=int((time.time() - start_time) * 1000),
            coverage_summary={
                "demo_label": "DEMO DATA (Safe Fixture)",
                "files_analyzed": len(files),
                "simulated_test": fixture["title"]
            },
            metadata_summary=meta
        )
        db.add(scan)
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

    elif fixture_key in ["case_b_legitimate_update", "case_c_suspicious_update"]:
        target = fixture["target"]
        files = target["files"]
        meta = target["metadata"]

        # Real static analysis on target files
        findings = static_engine.analyze_package_files(files)
        
        # Also include install script finding if present
        meta_findings = []
        if meta.get("lifecycle_scripts"):
            for sname, scmd in meta["lifecycle_scripts"].items():
                meta_findings.append({
                    "rule_id": "META-INSTALL-SCRIPT",
                    "title": f"Installation-Time Lifecycle Hook Present ('{sname}')",
                    "severity": "HIGH",
                    "file_path": "package.json",
                    "line_number": 1,
                    "evidence_excerpt": f'"{sname}": "{scmd}"',
                    "explanation": f"Package executes system command during install hook '{sname}'.",
                    "risk_reason": "Lifecycle scripts execute code during npm install before import.",
                    "confidence": "HIGH",
                    "recommended_action": "Audit installation scripts.",
                    "is_false_positive": False
                })

        all_findings = findings + meta_findings

        score, classification, decision, reasons, breakdown = risk_engine.calculate_risk(
            vulnerabilities=[],
            findings=all_findings,
            metadata_findings=[],
            integrity_ok=True
        )

        scan = Scan(
            id=str(uuid.uuid4()),
            package_name=fixture["package_name"],
            ecosystem="npm",
            version=fixture["target_version"],
            scan_type="demo",
            status="completed",
            stage="Analysis complete (Controlled Demo Fixture)",
            risk_score=score,
            risk_classification=classification,
            policy_decision=decision,
            policy_reasons=reasons,
            is_demo=True,
            duration_ms=int((time.time() - start_time) * 1000),
            coverage_summary={
                "demo_label": "DEMO DATA (Safe Fixture)",
                "files_analyzed": len(files),
                "simulated_test": fixture["title"]
            },
            metadata_summary=meta
        )
        db.add(scan)
        await db.commit()

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

@router.post("/reset")
async def reset_demo_data(db: AsyncSession = Depends(get_db)):
    """
    Deletes all records marked with is_demo=True from the database.
    Leaves real user scans intact.
    """
    stmt = delete(Scan).where(Scan.is_demo == True)
    res = await db.execute(stmt)
    await db.commit()
    return {"message": "Demo records successfully purged.", "deleted_count": res.rowcount}
