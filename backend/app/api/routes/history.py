from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from sqlalchemy.orm import selectinload

from app.models.base import get_db
from app.models.entities import Scan, Finding, Vulnerability
from app.schemas.all_schemas import DashboardStatsResponse, ScanResponse

router = APIRouter()

@router.get("/stats", response_model=DashboardStatsResponse)
async def get_dashboard_stats(
    include_demo: bool = Query(False),
    db: AsyncSession = Depends(get_db)
):
    """
    Computes genuine statistics aggregated from persisted database scan records.
    Never fabricates metrics. If 0 records exist, zeroes are returned.
    """
    base_filter = []
    if not include_demo:
        base_filter.append(Scan.is_demo == False)

    # 1. Total Scans
    scan_count_query = select(func.count(Scan.id))
    if base_filter:
        scan_count_query = scan_count_query.where(*base_filter)
    total_scans = (await db.execute(scan_count_query)).scalar() or 0

    # 2. Risk Distribution
    risk_dist_query = select(Scan.risk_classification, func.count(Scan.id))
    if base_filter:
        risk_dist_query = risk_dist_query.where(*base_filter)
    risk_dist_query = risk_dist_query.group_by(Scan.risk_classification)
    risk_rows = (await db.execute(risk_dist_query)).all()
    risk_distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for r_class, count in risk_rows:
        if r_class in risk_distribution:
            risk_distribution[r_class] = count

    # 3. Findings Severity Counts
    finding_filter = []
    if not include_demo:
        finding_filter.append(Scan.is_demo == False)
    
    high_findings_query = (
        select(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.severity.in_(["HIGH", "CRITICAL"]))
    )
    if finding_filter:
        high_findings_query = high_findings_query.where(*finding_filter)
    high_findings = (await db.execute(high_findings_query)).scalar() or 0

    med_findings_query = (
        select(func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Finding.severity == "MEDIUM")
    )
    if finding_filter:
        med_findings_query = med_findings_query.where(*finding_filter)
    med_findings = (await db.execute(med_findings_query)).scalar() or 0

    # 4. Known Vulnerabilities Count
    vuln_query = select(func.count(Vulnerability.id)).join(Scan, Vulnerability.scan_id == Scan.id)
    if finding_filter:
        vuln_query = vuln_query.where(*finding_filter)
    known_vulns = (await db.execute(vuln_query)).scalar() or 0

    # 5. Packages requiring review (Policy decision == REVIEW or BLOCK)
    review_query = select(func.count(Scan.id)).where(Scan.policy_decision.in_(["REVIEW", "BLOCK"]))
    if base_filter:
        review_query = review_query.where(*base_filter)
    packages_requiring_review = (await db.execute(review_query)).scalar() or 0

    # 6. Latest scan time
    latest_time_query = select(Scan.created_at).order_by(desc(Scan.created_at)).limit(1)
    if base_filter:
        latest_time_query = latest_time_query.where(*base_filter)
    latest_scan_time = (await db.execute(latest_time_query)).scalar()

    # Determine if all records are demo records
    demo_count_query = select(func.count(Scan.id)).where(Scan.is_demo == True)
    demo_count = (await db.execute(demo_count_query)).scalar() or 0
    is_demo_metrics = (total_scans > 0 and demo_count == total_scans)

    return DashboardStatsResponse(
        total_scanned=total_scans,
        high_risk_findings=high_findings,
        medium_risk_findings=med_findings,
        known_vulnerabilities=known_vulns,
        packages_requiring_review=packages_requiring_review,
        latest_scan_time=latest_scan_time,
        risk_distribution=risk_distribution,
        is_demo_metrics=is_demo_metrics
    )

@router.get("", response_model=List[ScanResponse])
async def get_history(
    ecosystem: Optional[str] = None,
    risk: Optional[str] = None,
    decision: Optional[str] = None,
    is_demo: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(Scan)
        .options(
            selectinload(Scan.findings),
            selectinload(Scan.vulnerabilities),
            selectinload(Scan.dependencies)
        )
        .order_by(desc(Scan.created_at))
    )

    if ecosystem:
        stmt = stmt.where(Scan.ecosystem == ecosystem.lower())
    if risk:
        stmt = stmt.where(Scan.risk_classification == risk.upper())
    if decision:
        stmt = stmt.where(Scan.policy_decision == decision.upper())
    if is_demo is not None:
        stmt = stmt.where(Scan.is_demo == is_demo)
    if search:
        stmt = stmt.where(Scan.package_name.ilike(f"%{search}%"))

    stmt = stmt.offset(offset).limit(limit)
    res = await db.execute(stmt)
    return res.scalars().all()
