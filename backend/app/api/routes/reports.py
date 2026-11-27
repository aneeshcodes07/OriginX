import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.base import get_db
from app.models.entities import Scan, AuditEvent

router = APIRouter()

@router.get("/{scan_id}")
@router.get("/{scan_id}/json")
async def generate_scan_report(
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

    # Record Audit Event for report generation
    audit = AuditEvent(
        id=str(uuid.uuid4()),
        event_type="REPORT_GENERATED",
        user_id="analyst",
        action=f"Generated report for {scan.package_name}@{scan.version}",
        resource_type="report",
        resource_id=scan.id,
        details_json={"scan_id": scan.id, "package": scan.package_name, "version": scan.version}
    )
    db.add(audit)
    await db.commit()

    exec_summary = (
        f"OriginX assessed {scan.package_name}@{scan.version} ({scan.ecosystem}) with an overall "
        f"risk score of {scan.risk_score}/100, categorizing it as {scan.risk_classification} risk. "
        f"The automated policy outcome is {scan.policy_decision}."
    )

    recommended_steps = []
    if scan.policy_decision == "BLOCK":
        recommended_steps.append("Do not deploy this package or version to any environment.")
        recommended_steps.append("Pin previous secure version in lockfiles and CI/CD pipelines.")
        recommended_steps.append("Submit report to security engineering for containment.")
    elif scan.policy_decision == "REVIEW":
        recommended_steps.append("Conduct peer code review on flagged installation scripts and static findings.")
        recommended_steps.append("Run package in an isolated container sandbox before allowing into production.")
    else:
        recommended_steps.append("Package passed all baseline criteria. Proceed with regular deployment.")

    return {
        "report_id": f"REP-{scan.id[:8].upper()}",
        "scan_id": scan.id,
        "generated_at": scan.created_at.isoformat() if scan.created_at else None,
        "is_demo_report": scan.is_demo,
        "executive_summary": exec_summary,
        "package_identity": {
            "name": scan.package_name,
            "ecosystem": scan.ecosystem,
            "version": scan.version,
            "scan_type": scan.scan_type,
            "duration_ms": scan.duration_ms
        },
        "risk_assessment": {
            "score": scan.risk_score,
            "classification": scan.risk_classification,
            "policy_decision": scan.policy_decision,
            "policy_reasons": scan.policy_reasons or []
        },
        "coverage_summary": scan.coverage_summary or {},
        "metadata_summary": scan.metadata_summary or {},
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "title": f.title,
                "severity": f.severity,
                "file_path": f.file_path,
                "line_number": f.line_number,
                "evidence_excerpt": f.evidence_excerpt,
                "explanation": f.explanation,
                "risk_reason": f.risk_reason,
                "confidence": f.confidence,
                "recommended_action": f.recommended_action,
                "is_false_positive": f.is_false_positive
            }
            for f in scan.findings
        ],
        "vulnerabilities": [
            {
                "vuln_id": v.vuln_id,
                "summary": v.summary,
                "severity": v.severity,
                "affected_range": v.affected_range,
                "fixed_version": v.fixed_version,
                "source_url": v.source_url
            }
            for v in scan.vulnerabilities
        ],
        "dependencies": [
            {
                "name": d.name,
                "version": d.version,
                "dep_type": d.dep_type,
                "has_vulnerabilities": d.has_vulnerabilities
            }
            for d in scan.dependencies
        ],
        "recommendations": recommended_steps,
        "recommended_steps": recommended_steps
    }

def generate_pdf_binary(title: str, package_str: str, score_str: str, summary_str: str, reasons: list) -> bytes:
    """
    Generates standard valid %PDF-1.4 binary file with objects, catalog,
    fonts, and xref stream without third-party C dependencies.
    """
    def sanitize(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    lines = [
        f"BT /F1 18 Tf 50 740 Td ({sanitize(title)}) Tj ET",
        f"BT /F1 14 Tf 50 710 Td ({sanitize(package_str)}) Tj ET",
        f"BT /F1 12 Tf 50 680 Td ({sanitize(score_str)}) Tj ET",
        f"BT /F2 10 Tf 50 650 Td ({sanitize(summary_str[:90])}) Tj ET",
        "BT /F1 12 Tf 50 610 Td (Policy Reasons:) Tj ET"
    ]
    y = 590
    for r in reasons[:8]:
        lines.append(f"BT /F2 10 Tf 60 {y} Td (- {sanitize(r[:85])}) Tj ET")
        y -= 20

    stream_content = "\n".join(lines).encode("latin1", errors="replace")
    stream_len = len(stream_content)

    obj4 = b"<< /Length " + str(stream_len).encode() + b" >>\nstream\n" + stream_content + b"\nendstream"
    
    header = b"%PDF-1.4\n"
    obj1 = b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
    obj2 = b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
    obj3 = b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> >> endobj\n"
    obj4_full = b"4 0 obj " + obj4 + b" endobj\n"
    obj5 = b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> endobj\n"
    obj6 = b"6 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"

    o1 = len(header)
    o2 = o1 + len(obj1)
    o3 = o2 + len(obj2)
    o4 = o3 + len(obj3)
    o5 = o4 + len(obj4_full)
    o6 = o5 + len(obj5)
    startxref = o6 + len(obj6)

    xref = (
        f"xref\n0 7\n"
        f"0000000000 65535 f \n"
        f"{o1:010d} 00000 n \n"
        f"{o2:010d} 00000 n \n"
        f"{o3:010d} 00000 n \n"
        f"{o4:010d} 00000 n \n"
        f"{o5:010d} 00000 n \n"
        f"{o6:010d} 00000 n \n"
        f"trailer << /Size 7 /Root 1 0 R >>\n"
        f"startxref\n{startxref}\n%%EOF"
    ).encode()

    return header + obj1 + obj2 + obj3 + obj4_full + obj5 + obj6 + xref

@router.get("/{scan_id}/pdf")
async def download_scan_report_pdf(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Returns valid application/pdf binary stream representing the assessment report.
    """
    data = await generate_scan_report(scan_id, db)
    
    pkg_str = f"Target Package: {data['package_identity']['name']}@{data['package_identity']['version']} ({data['package_identity']['ecosystem']})"
    score_str = f"Risk Score: {data['risk_assessment']['score']}/100 [{data['risk_assessment']['classification']}] - Decision: {data['risk_assessment']['policy_decision']}"
    summary_str = data["executive_summary"]
    reasons = data["risk_assessment"]["policy_reasons"] or ["No blocking indicators identified."]

    pdf_bytes = generate_pdf_binary(
        title=f"OriginX Security Assessment ({data['report_id']})",
        package_str=pkg_str,
        score_str=score_str,
        summary_str=summary_str,
        reasons=reasons
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=\"{data['report_id']}.pdf\""}
    )
