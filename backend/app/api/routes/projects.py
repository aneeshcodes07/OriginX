import uuid
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload
from pydantic import BaseModel

from app.models.base import get_db
from app.models.entities import Project, Scan, AuditEvent
from app.services.dependency_analysis.parser import DependencyParser
from app.services.vulnerability_intelligence.osv import OSVService
from app.services.risk_engine.calculator import RiskEngine

router = APIRouter()
osv_service = OSVService()
risk_engine = RiskEngine()

class ProjectCreateRequest(BaseModel):
    name: str
    description: Optional[str] = None
    ecosystem: str = "npm"

class ProjectUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    ecosystem: Optional[str] = None

class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    ecosystem: str
    latest_risk_score: float
    latest_decision: str
    scans_count: int = 0
    created_at: Any
    updated_at: Any

@router.get("", response_model=List[ProjectResponse])
async def list_projects(
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Project).options(selectinload(Project.scans)).order_by(desc(Project.updated_at)).limit(limit)
    res = await db.execute(stmt)
    projects = res.scalars().all()
    out = []
    for p in projects:
        out.append(ProjectResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            ecosystem=p.ecosystem,
            latest_risk_score=p.latest_risk_score,
            latest_decision=p.latest_decision,
            scans_count=len(p.scans) if p.scans else 0,
            created_at=p.created_at,
            updated_at=p.updated_at
        ))
    return out

@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    req: ProjectCreateRequest,
    db: AsyncSession = Depends(get_db)
):
    proj = Project(
        id=str(uuid.uuid4()),
        name=req.name.strip(),
        description=req.description,
        ecosystem=req.ecosystem.lower()
    )
    db.add(proj)

    # Record Audit Event
    audit = AuditEvent(
        id=str(uuid.uuid4()),
        event_type="PROJECT_CREATED",
        user_id="analyst",
        action=f"Created project '{proj.name}'",
        resource_type="project",
        resource_id=proj.id,
        details_json={"name": proj.name, "ecosystem": proj.ecosystem}
    )
    db.add(audit)

    await db.commit()
    await db.refresh(proj)

    return ProjectResponse(
        id=proj.id,
        name=proj.name,
        description=proj.description,
        ecosystem=proj.ecosystem,
        latest_risk_score=proj.latest_risk_score,
        latest_decision=proj.latest_decision,
        scans_count=0,
        created_at=proj.created_at,
        updated_at=proj.updated_at
    )

@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Project).options(selectinload(Project.scans)).where(Project.id == project_id)
    res = await db.execute(stmt)
    proj = res.scalar_one_or_none()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found.")

    return ProjectResponse(
        id=proj.id,
        name=proj.name,
        description=proj.description,
        ecosystem=proj.ecosystem,
        latest_risk_score=proj.latest_risk_score,
        latest_decision=proj.latest_decision,
        scans_count=len(proj.scans) if proj.scans else 0,
        created_at=proj.created_at,
        updated_at=proj.updated_at
    )

@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    req: ProjectUpdateRequest,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Project).where(Project.id == project_id)
    res = await db.execute(stmt)
    proj = res.scalar_one_or_none()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found.")

    if req.name is not None:
        proj.name = req.name.strip()
    if req.description is not None:
        proj.description = req.description
    if req.ecosystem is not None:
        proj.ecosystem = req.ecosystem.lower()

    audit = AuditEvent(
        id=str(uuid.uuid4()),
        event_type="PROJECT_UPDATED",
        user_id="analyst",
        action=f"Updated project '{proj.name}'",
        resource_type="project",
        resource_id=proj.id,
        details_json={"name": proj.name}
    )
    db.add(audit)

    await db.commit()
    await db.refresh(proj)

    return ProjectResponse(
        id=proj.id,
        name=proj.name,
        description=proj.description,
        ecosystem=proj.ecosystem,
        latest_risk_score=proj.latest_risk_score,
        latest_decision=proj.latest_decision,
        scans_count=0,
        created_at=proj.created_at,
        updated_at=proj.updated_at
    )

@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Project).where(Project.id == project_id)
    res = await db.execute(stmt)
    proj = res.scalar_one_or_none()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found.")

    await db.delete(proj)

    audit = AuditEvent(
        id=str(uuid.uuid4()),
        event_type="PROJECT_DELETED",
        user_id="analyst",
        action=f"Deleted project '{proj.name}'",
        resource_type="project",
        resource_id=project_id,
        details_json={"name": proj.name}
    )
    db.add(audit)

    await db.commit()
    return {"status": "deleted", "project_id": project_id}

@router.post("/scan")
async def scan_project_manifest(
    file: UploadFile = File(...),
    project_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    filename = file.filename or "package.json"
    content_bytes = await file.read()
    try:
        content_str = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Uploaded manifest file is not valid UTF-8 text.")

    # 1. Parse manifest
    parsed = DependencyParser.parse_manifest(filename, content_str)
    dependencies = parsed["dependencies"]
    ecosystem = parsed["ecosystem"]
    issues = parsed["issues"]

    # 2. Check vulnerabilities for top dependencies
    analyzed_count = 0
    skipped_count = max(0, len(dependencies) - 20)
    discovered_vulns = []
    high_risk_deps = []

    for dep in dependencies[:20]:
        analyzed_count += 1
        name = dep["name"]
        ver = dep["version"].replace("^", "").replace("~", "").replace(">=", "").strip()
        if ver and ver != "*":
            vuln_res = await osv_service.query_vulnerabilities(name, ecosystem, ver)
            vulns = vuln_res.get("vulnerabilities", [])
            if vulns:
                dep["has_vulnerabilities"] = True
                dep["vulnerabilities_count"] = len(vulns)
                discovered_vulns.extend(vulns)
                high_risk_deps.append({
                    "package": name,
                    "version": ver,
                    "vulnerabilities": [v["vuln_id"] for v in vulns]
                })

    # Overall project assessment
    total_issues = len(issues) + len(discovered_vulns)
    if any("CRITICAL" in v.get("severity", "") for v in discovered_vulns) or total_issues >= 5:
        overall_status = "CRITICAL"
        recommendation = "Project contains critical vulnerabilities or severe supply chain signals. Immediate remediation required."
    elif len(discovered_vulns) > 0 or len(issues) > 0:
        overall_status = "REVIEW"
        recommendation = "Several dependencies contain vulnerabilities or unpinned/typosquat indicators. Review before production deployment."
    else:
        overall_status = "LOW"
        recommendation = "All analyzed dependencies passed baseline checks with no known vulnerabilities."

    # Update Project if project_id provided
    if project_id:
        p_stmt = select(Project).where(Project.id == project_id)
        p_res = await db.execute(p_stmt)
        p_obj = p_res.scalar_one_or_none()
        if p_obj:
            p_obj.latest_decision = overall_status
            p_obj.latest_risk_score = 80.0 if overall_status == "CRITICAL" else 45.0 if overall_status == "REVIEW" else 10.0
            await db.commit()

    return {
        "project_filename": filename,
        "ecosystem": ecosystem,
        "total_dependencies_discovered": len(dependencies),
        "dependencies_analyzed": analyzed_count,
        "dependencies_skipped": skipped_count,
        "known_vulnerabilities_count": len(discovered_vulns),
        "vulnerabilities": discovered_vulns,
        "high_risk_dependencies": high_risk_deps,
        "typosquat_and_unpinned_issues": issues,
        "dependencies_list": dependencies,
        "overall_assessment": overall_status,
        "recommendation": recommendation
    }
