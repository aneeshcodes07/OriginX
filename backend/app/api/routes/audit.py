from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel

from app.models.base import get_db
from app.models.entities import AuditEvent

router = APIRouter()

class AuditEventResponse(BaseModel):
    id: str
    event_type: str
    user_id: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details_json: Dict[str, Any] = {}
    ip_address: Optional[str] = None
    timestamp: Any

@router.get("", response_model=List[AuditEventResponse])
async def list_audit_events(
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(AuditEvent)
    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)

    stmt = stmt.order_by(desc(AuditEvent.timestamp)).limit(limit)
    res = await db.execute(stmt)
    events = res.scalars().all()

    return [
        AuditEventResponse(
            id=e.id,
            event_type=e.event_type,
            user_id=e.user_id,
            action=e.action,
            resource_type=e.resource_type,
            resource_id=e.resource_id,
            details_json=e.details_json or {},
            ip_address=e.ip_address,
            timestamp=e.timestamp
        )
        for e in events
    ]
