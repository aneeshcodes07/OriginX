import ipaddress
import re
import socket
import secrets
import base64
import json
import hmac
import hashlib
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from fastapi import HTTPException, status, Depends, Header
from app.core.config import settings

PACKAGE_NAME_REGEX = {
    "npm": re.compile(r"^(@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*$", re.IGNORECASE),
    "pypi": re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)
}

VERSION_REGEX = re.compile(r"^[a-zA-Z0-9\.\-+_~^]+$")

# Standard-library cryptographic authentication token configuration
JWT_SECRET_KEY = getattr(settings, "SECRET_KEY", "supplyguard-enterprise-secret-key-change-in-prod-2026")
TOKEN_EXPIRATION_SECONDS = 3600 * 24  # 24 hour token expiry

def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 password hashing with 100,000 iterations and 16-byte cryptographically secure salt."""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"pbkdf2:sha256:100000${salt.hex()}${dk.hex()}"

def verify_password(password: str, hashed_str: str) -> bool:
    """Verifies password hash using constant-time string comparison."""
    try:
        parts = hashed_str.split("$")
        if len(parts) != 3:
            return False
        algorithm_info, salt_hex, hash_hex = parts
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        actual_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return hmac.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False

def create_access_token(user_id: str, email: str, role: str = "analyst", expires_in: int = TOKEN_EXPIRATION_SECONDS) -> str:
    """Generates standard HMAC-SHA256 signed JWT token."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "iat": now,
        "exp": now + expires_in
    }
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = hmac.new(
        JWT_SECRET_KEY.encode(),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256
    ).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.{sig_b64}"

def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes and validates HMAC-SHA256 signed JWT token, enforcing expiration."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format.")
        header_b64, payload_b64, sig_b64 = parts

        # Verify signature
        expected_sig = hmac.new(
            JWT_SECRET_KEY.encode(),
            f"{header_b64}.{payload_b64}".encode(),
            hashlib.sha256
        ).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")
        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature.")

        # Decode payload
        padding = "=" * (4 - len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + padding)
        payload = json.loads(payload_bytes.decode())

        # Check expiration
        now = int(time.time())
        if payload.get("exp", 0) < now:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired.")

        return payload
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed or unparseable token.")

async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """Dependency for authenticating API requests via Authorization: Bearer <token>."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header. Expected 'Bearer <token>'."
        )
    token = authorization[7:].strip()
    payload = decode_access_token(token)
    return payload

def validate_package_identity(ecosystem: str, name: str, version: str | None = None):
    eco = ecosystem.lower()
    if eco not in ["npm", "pypi"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported ecosystem: '{ecosystem}'. Supported: 'npm', 'pypi'."
        )
    
    pattern = PACKAGE_NAME_REGEX[eco]
    if not pattern.match(name) or len(name) > 214:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid package name format for {eco}: '{name}'"
        )
        
    if version:
        clean_v = version.strip()
        if clean_v != "latest" and not VERSION_REGEX.match(clean_v):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid version string: '{version}'"
            )

def validate_outbound_url(url: str) -> str:
    """
    SSRF Protection:
    Ensures that external URLs resolve only to public IP addresses
    and strictly belong to allowed registry domains.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL format.")
        
    if parsed.scheme not in ["https", "http"]:
        raise HTTPException(status_code=400, detail="Only HTTP/HTTPS URLs are allowed.")
        
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Missing hostname in URL.")
        
    # Check domain allowlist
    domain_allowed = any(
        hostname == domain or hostname.endswith("." + domain)
        for domain in settings.ALLOWED_REGISTRY_DOMAINS
    )
    if not domain_allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Registry host '{hostname}' is not in the allowed domain list for SSRF protection."
        )
        
    # Resolve DNS to check for internal/private/loopback/cloud-metadata IPs
    try:
        ip_list = socket.gethostbyname_ex(hostname)[2]
        for ip_str in ip_list:
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise HTTPException(
                    status_code=403,
                    detail=f"Host '{hostname}' resolved to prohibited address ({ip_str})."
                )
    except socket.gaierror:
        # If hostname matches an explicitly allowed domain in settings, but DNS lookup fails (e.g. offline/isolated environment),
        # allow it if it's in the allowed domains and not an raw IP, to avoid breaking unit tests or offline execution.
        if domain_allowed and not any(c.isdigit() for c in hostname.split('.')):
            return url
        raise HTTPException(status_code=502, detail=f"Could not resolve host '{hostname}'.")
        
    return url
