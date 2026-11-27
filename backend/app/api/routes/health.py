import httpx
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.models.base import get_db
from app.core.config import settings

router = APIRouter()

@router.get("/health")
async def check_health(db: AsyncSession = Depends(get_db)):
    # Check Database connection
    db_status = "healthy"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    # Check external registry connectivity
    npm_status = "checking"
    pypi_status = "checking"
    osv_status = "checking"
    
    async with httpx.AsyncClient(timeout=3.0) as client:
        try:
            r = await client.get("https://registry.npmjs.org", headers={"User-Agent": "OriginX-Security-Scanner/1.0"})
            npm_status = "reachable" if r.status_code == 200 else f"status {r.status_code}"
        except Exception:
            npm_status = "unreachable"
            
        try:
            r = await client.get("https://pypi.org/pypi/requests/json", headers={"User-Agent": "OriginX-Security-Scanner/1.0"})
            pypi_status = "reachable" if r.status_code == 200 else f"status {r.status_code}"
        except Exception:
            pypi_status = "unreachable"
            
        try:
            r = await client.get("https://api.osv.dev/v1/vulns/GHSA-w5p7-h5w8-2hfq")
            osv_status = "reachable" if r.status_code in [200, 404] else f"status {r.status_code}"
        except Exception:
            osv_status = "unreachable"

    return {
        "status": "online",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "database": db_status,
        "external_services": {
            "npm_registry": npm_status,
            "pypi_registry": pypi_status,
            "osv_intelligence": osv_status
        }
    }
