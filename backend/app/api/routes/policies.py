import uuid
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.models.base import get_db
from app.models.entities import Policy, AuditEvent

router = APIRouter()

DEFAULT_POLICIES_DATA = [
    {
        "id": "POL-001",
        "name": "Block Critical Known Vulnerabilities",
        "description": "Automatically BLOCK dependencies containing published vulnerabilities rated CRITICAL in OSV.dev / NVD.",
        "trigger_type": "vulnerability",
        "action": "BLOCK",
        "is_active": True
    },
    {
        "id": "POL-002",
        "name": "Block Integrity Verification Failure",
        "description": "Automatically BLOCK any package whose downloaded archive hash fails cryptographic verification against registry digest.",
        "trigger_type": "integrity",
        "action": "BLOCK",
        "is_active": True
    },
    {
        "id": "POL-003",
        "name": "Flag Lifecycle Installation Hooks for Review",
        "description": "Trigger mandatory security REVIEW for packages executing preinstall, install, or postinstall hooks.",
        "trigger_type": "install_script",
        "action": "REVIEW",
        "is_active": True
    },
    {
        "id": "POL-004",
        "name": "Block Credential Harvesting Patterns",
        "description": "Automatically BLOCK packages with static signatures matching cloud/SSH credential harvesting (CRD-001).",
        "trigger_type": "code_pattern",
        "action": "BLOCK",
        "is_active": True
    },
    {
        "id": "POL-005",
        "name": "Flag Dormant Package Revivals for Review",
        "description": "Trigger REVIEW if a package was inactive for > 2 years and suddenly pushed a new version under potentially new maintainers.",
        "trigger_type": "maintainer_change",
        "action": "REVIEW",
        "is_active": True
    }
]

class PolicyResponse(BaseModel):
    id: str
    name: str
    description: str
    trigger_type: str
    action: str
    enabled: bool
    version: str

class PolicyUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    action: Optional[str] = None
    enabled: Optional[bool] = None

async def ensure_default_policies_seeded(db: AsyncSession):
    stmt = select(Policy)
    res = await db.execute(stmt)
    existing = res.scalars().all()
    if not existing:
        for pdata in DEFAULT_POLICIES_DATA:
            p = Policy(
                id=pdata["id"],
                name=pdata["name"],
                description=pdata["description"],
                trigger_type=pdata["trigger_type"],
                action=pdata["action"],
                is_active=pdata["is_active"],
                version="2.0.0"
            )
            db.add(p)
        await db.commit()

@router.get("", response_model=List[PolicyResponse])
async def get_policies(db: AsyncSession = Depends(get_db)):
    await ensure_default_policies_seeded(db)
    stmt = select(Policy).order_by(Policy.id)
    res = await db.execute(stmt)
    policies = res.scalars().all()
    return [
        PolicyResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            trigger_type=p.trigger_type,
            action=p.action,
            enabled=p.is_active,
            version=p.version
        )
        for p in policies
    ]

@router.put("/{policy_id}/toggle")
async def toggle_policy(policy_id: str, db: AsyncSession = Depends(get_db)):
    await ensure_default_policies_seeded(db)
    stmt = select(Policy).where(Policy.id == policy_id)
    res = await db.execute(stmt)
    p = res.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found.")

    p.is_active = not p.is_active

    # Audit event
    audit = AuditEvent(
        id=str(uuid.uuid4()),
        event_type="POLICY_TOGGLED",
        user_id="analyst",
        action=f"Toggled policy '{p.name}' to {p.is_active}",
        resource_type="policy",
        resource_id=p.id,
        details_json={"policy_id": p.id, "enabled": p.is_active}
    )
    db.add(audit)

    await db.commit()
    await db.refresh(p)
    return {
        "policy": {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "trigger_type": p.trigger_type,
            "action": p.action,
            "enabled": p.is_active,
            "version": p.version
        },
        "status": "updated"
    }

@router.put("/{policy_id}")
async def update_policy(
    policy_id: str,
    req: PolicyUpdateRequest,
    db: AsyncSession = Depends(get_db)
):
    await ensure_default_policies_seeded(db)
    stmt = select(Policy).where(Policy.id == policy_id)
    res = await db.execute(stmt)
    p = res.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found.")

    if req.name is not None:
        p.name = req.name
    if req.description is not None:
        p.description = req.description
    if req.action is not None:
        if req.action not in ["ALLOW", "REVIEW", "BLOCK"]:
            raise HTTPException(status_code=400, detail="Action must be one of ALLOW, REVIEW, BLOCK.")
        p.action = req.action
    if req.enabled is not None:
        p.is_active = req.enabled

    audit = AuditEvent(
        id=str(uuid.uuid4()),
        event_type="POLICY_UPDATED",
        user_id="analyst",
        action=f"Updated policy '{p.name}'",
        resource_type="policy",
        resource_id=p.id,
        details_json={"action": p.action, "enabled": p.is_active}
    )
    db.add(audit)

    await db.commit()
    await db.refresh(p)
    return {
        "policy": {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "trigger_type": p.trigger_type,
            "action": p.action,
            "enabled": p.is_active,
            "version": p.version
        },
        "status": "updated"
    }
