import os
from typing import List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "OriginX"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    TAGLINE: str = "Know What Goes Into Your Software."
    DESCRIPTION: str = "OriginX is an intelligent software supply-chain security platform that analyses dependencies, detects vulnerabilities, identifies suspicious code behaviour, verifies package integrity and evaluates security risks before software reaches production."
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./supplyguard.db")
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
    ]
    
    # Registry URLs
    NPM_REGISTRY_URL: str = "https://registry.npmjs.org"
    PYPI_REGISTRY_URL: str = "https://pypi.org/pypi"
    OSV_API_URL: str = "https://api.osv.dev/v1/query"
    
    # SSRF Protection: Allowed domains for external calls
    ALLOWED_REGISTRY_DOMAINS: List[str] = [
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "registry.yarnpkg.com",
        "api.osv.dev",
    ]
    
    # Limits & Security
    MAX_ARCHIVE_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB max upload
    MAX_EXTRACTED_SIZE_BYTES: int = 60 * 1024 * 1024  # 60 MB uncompressed limit
    MAX_ARCHIVE_FILES: int = 5000
    MAX_RECURSION_DEPTH: int = 8
    SCAN_TIMEOUT_SECONDS: int = 60
    HTTP_TIMEOUT_SECONDS: float = 12.0
    
    # Demo settings
    DEMO_MODE_ENABLED: bool = True

    model_config = {"case_sensitive": True, "env_file": ".env"}

settings = Settings()
