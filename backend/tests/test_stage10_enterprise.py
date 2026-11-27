import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.models.base import init_db

@pytest.mark.asyncio
async def test_project_crud_and_audit():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Create project
        create_res = await client.post("/api/v1/projects", json={
            "name": "Frontend Web App",
            "description": "Production Next.js application dependencies",
            "ecosystem": "npm"
        })
        assert create_res.status_code == 201
        proj = create_res.json()
        assert proj["name"] == "Frontend Web App"
        proj_id = proj["id"]

        # 2. Get project
        get_res = await client.get(f"/api/v1/projects/{proj_id}")
        assert get_res.status_code == 200
        assert get_res.json()["id"] == proj_id

        # 3. List projects
        list_res = await client.get("/api/v1/projects")
        assert list_res.status_code == 200
        assert any(p["id"] == proj_id for p in list_res.json())

        # 4. Update project
        update_res = await client.put(f"/api/v1/projects/{proj_id}", json={
            "description": "Updated description"
        })
        assert update_res.status_code == 200
        assert update_res.json()["description"] == "Updated description"

        # 5. Verify audit event was recorded for creation
        audit_res = await client.get("/api/v1/audit?resource_type=project")
        assert audit_res.status_code == 200
        events = audit_res.json()
        assert any(e["resource_id"] == proj_id for e in events)

        # 6. Delete project
        del_res = await client.delete(f"/api/v1/projects/{proj_id}")
        assert del_res.status_code == 200


@pytest.mark.asyncio
async def test_database_backed_policies():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Get policies
        res = await client.get("/api/v1/policies")
        assert res.status_code == 200
        policies = res.json()
        assert len(policies) >= 5
        pol_id = policies[0]["id"]
        initial_state = policies[0]["enabled"]

        # Toggle policy
        toggle_res = await client.put(f"/api/v1/policies/{pol_id}/toggle")
        assert toggle_res.status_code == 200
        assert toggle_res.json()["policy"]["enabled"] != initial_state

        # Toggle back
        toggle_back = await client.put(f"/api/v1/policies/{pol_id}/toggle")
        assert toggle_back.status_code == 200
        assert toggle_back.json()["policy"]["enabled"] == initial_state


@pytest.mark.asyncio
async def test_download_report_pdf_html():
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create a demo scan first
        demo_res = await client.post("/api/v1/demo/run/case_a_normal")
        assert demo_res.status_code == 200
        scan_id = demo_res.json()["id"]

        # Download report printable HTML / PDF
        rep_res = await client.get(f"/api/v1/reports/{scan_id}/pdf")
        assert rep_res.status_code == 200
        assert rep_res.content.startswith(b"%PDF-") or "Security Assessment" in rep_res.text
        assert "attachment" in rep_res.headers.get("content-disposition", "")
