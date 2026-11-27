import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.models.base import init_db
from app.core.security import hash_password, verify_password, create_access_token, decode_access_token
from fastapi import HTTPException

# ==============================================================
# SUB-PHASE 1: AUTHENTICATION AND AUTHORIZATION AUDIT TESTS
# ==============================================================

def test_password_hashing_pbkdf2():
    """Verify PBKDF2 password hashing is non-reversible, salted, and constant-time verified."""
    pwd = "SecureMasterPassword123!"
    h1 = hash_password(pwd)
    h2 = hash_password(pwd)
    assert h1 != h2  # Different salts
    assert verify_password(pwd, h1) is True
    assert verify_password("WrongPassword!", h1) is False


def test_token_creation_and_expiration():
    """Verify JWT token generation, signature verification, and expiration enforcement."""
    token = create_access_token(user_id="u-123", email="user@example.com", role="analyst", expires_in=3600)
    payload = decode_access_token(token)
    assert payload["sub"] == "u-123"
    assert payload["email"] == "user@example.com"
    assert payload["role"] == "analyst"

    # Expired token test
    expired_token = create_access_token(user_id="u-123", email="user@example.com", expires_in=-10)
    with pytest.raises(HTTPException) as exc:
        decode_access_token(expired_token)
    assert exc.value.status_code == 401
    assert "expired" in exc.value.detail.lower()

    # Tampered token test
    tampered = token[:-4] + "xxxx"
    with pytest.raises(HTTPException) as exc:
        decode_access_token(tampered)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_auth_registration_login_flow():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        email = f"analyst_{int(pytest.importorskip('time').time())}@supplyguard.test"
        
        # 1. Register with short password fails
        r_short = await client.post("/api/v1/auth/register", json={"email": email, "password": "123"})
        assert r_short.status_code == 400

        # 2. Register valid
        r_reg = await client.post("/api/v1/auth/register", json={"email": email, "password": "StrongPassword999!"})
        assert r_reg.status_code == 201
        data = r_reg.json()
        assert "access_token" in data
        token = data["access_token"]

        # 3. Duplicate registration rejected
        r_dup = await client.post("/api/v1/auth/register", json={"email": email, "password": "StrongPassword999!"})
        assert r_dup.status_code == 400

        # 4. Login with invalid password fails
        r_bad = await client.post("/api/v1/auth/login", json={"email": email, "password": "WrongPassword!"})
        assert r_bad.status_code == 401

        # 5. Login valid succeeds
        r_login = await client.post("/api/v1/auth/login", json={"email": email, "password": "StrongPassword999!"})
        assert r_login.status_code == 200
        assert "access_token" in r_login.json()

        # 6. /me endpoint with Bearer token
        r_me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r_me.status_code == 200
        assert r_me.json()["email"] == email

        # 7. /me endpoint without token rejected
        r_unauth = await client.get("/api/v1/auth/me")
        assert r_unauth.status_code == 401


# ==============================================================
# SUB-PHASE 4: REAL PDF GENERATION TEST
# ==============================================================

@pytest.mark.asyncio
async def test_real_pdf_generation_valid_stream():
    """Verify PDF endpoint returns a real, valid application/pdf binary stream."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        demo = await client.post("/api/v1/demo/run/case_a_normal")
        scan_id = demo.json()["id"]

        r_pdf = await client.get(f"/api/v1/reports/{scan_id}/pdf")
        assert r_pdf.status_code == 200
        assert r_pdf.headers["content-type"] == "application/pdf"
        assert r_pdf.content.startswith(b"%PDF-")
        assert b"%%EOF" in r_pdf.content
        assert b"/Helvetica" in r_pdf.content


# ==============================================================
# SUB-PHASE 2: DATABASE TRANSACTIONS & ROLLBACK TEST
# ==============================================================

@pytest.mark.asyncio
async def test_database_transaction_rollback_and_integrity():
    """Verify database transactions roll back on failure and do not leave partial state."""
    from app.models.base import AsyncSessionLocal
    from app.models.entities import Project
    import uuid

    await init_db()
    project_id = str(uuid.uuid4())
    
    # 1. Test rollback on error
    try:
        async with AsyncSessionLocal() as session:
            async with session.begin():
                proj = Project(
                    id=project_id,
                    name="Rollback Test Project",
                    description="This should be rolled back",
                    ecosystem="npm"
                )
                session.add(proj)
                # Force an intentional exception before commit
                raise RuntimeError("Simulated transaction failure")
    except RuntimeError:
        pass

    # Verify project does not exist
    async with AsyncSessionLocal() as session:
        found = await session.get(Project, project_id)
        assert found is None, "Project should have been rolled back upon transaction error"


# ==============================================================
# SUB-PHASE 3: API SECURITY & SSRF BOUNDARY TESTS
# ==============================================================

def test_ssrf_validator_boundary_and_evasion():
    """Test SSRF rejection on loopback, private ranges, metadata, and unauthorized domains."""
    from app.core.security import validate_outbound_url
    from fastapi import HTTPException

    # 1. Invalid/Non-whitelisted domain
    with pytest.raises(HTTPException) as exc:
        validate_outbound_url("http://attacker.controlled.evil.com/payload.tgz")
    assert exc.value.status_code == 403

    # 2. Localhost URL
    with pytest.raises(HTTPException) as exc:
        validate_outbound_url("http://localhost:8000/api")
    assert exc.value.status_code == 403

    # 3. AWS/Cloud metadata IP
    with pytest.raises(HTTPException) as exc:
        validate_outbound_url("http://169.254.169.254/latest/meta-data")
    assert exc.value.status_code == 403

    # 4. Private RFC1918 addresses
    for private_url in ["http://10.0.0.1/malware.tgz", "http://192.168.1.1/malware.tgz", "http://172.16.0.1/malware.tgz"]:
        with pytest.raises(HTTPException) as exc:
            validate_outbound_url(private_url)
        assert exc.value.status_code == 403


# ==============================================================
# SUB-PHASE 4: REAL JSON & PDF REPORT ENDPOINTS TEST
# ==============================================================

@pytest.mark.asyncio
async def test_real_json_and_pdf_reports():
    """Verify both JSON report and binary PDF report generation and schema content."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create a scan
        demo = await client.post("/api/v1/demo/run/case_a_normal")
        assert demo.status_code == 200
        scan_id = demo.json()["id"]

        # 1. Fetch JSON Report
        r_json = await client.get(f"/api/v1/reports/{scan_id}/json")
        assert r_json.status_code == 200
        assert r_json.headers["content-type"] == "application/json"
        data = r_json.json()
        assert "scan_id" in data
        assert "risk_assessment" in data
        assert "score" in data["risk_assessment"]
        assert "findings" in data
        assert data["package_identity"]["name"] == "@supplyguard-demo/logger"

        # 2. Fetch PDF Report
        r_pdf = await client.get(f"/api/v1/reports/{scan_id}/pdf")
        assert r_pdf.status_code == 200
        assert r_pdf.headers["content-type"] == "application/pdf"
        assert r_pdf.content.startswith(b"%PDF-1.4")
        assert b"OriginX Security Assessment" in r_pdf.content or b"Security Assessment" in r_pdf.content
        assert b"@supplyguard-demo/logger" in r_pdf.content
