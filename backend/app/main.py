import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.models.base import init_db
from app.api.routes import (
    health, scans, comparisons, projects, history, demo, policies, reports, audit, auth
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB tables on startup
    await init_db()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routers
app.include_router(health.router, prefix="/api/v1", tags=["Health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Package & Archive Scans"])
app.include_router(comparisons.router, prefix="/api/v1/comparisons", tags=["Version Comparisons"])
app.include_router(projects.router, prefix="/api/v1/projects", tags=["Project Scans"])
app.include_router(history.router, prefix="/api/v1/history", tags=["History & Dashboard Metrics"])
app.include_router(demo.router, prefix="/api/v1/demo", tags=["Demo Lab"])
app.include_router(policies.router, prefix="/api/v1/policies", tags=["Policies"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(audit.router, prefix="/api/v1/audit", tags=["Audit Trail"])

@app.get("/")
async def root():
    return {
        "product": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "tagline": settings.TAGLINE,
        "description": settings.DESCRIPTION,
        "documentation": "/docs"
    }
