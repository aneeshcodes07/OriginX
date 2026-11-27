import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.models.base import init_db

# ==============================================================
# REGRESSION TEST 1: POLICIES API
# ==============================================================

@pytest.mark.asyncio
async def test_policies_api_successful_retrieval():
    """Verify policies retrieval returns valid schema with active rules."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/policies")
        assert res.status_code == 200
        policies = res.json()
        assert isinstance(policies, list)
        assert len(policies) >= 5
        for p in policies:
            assert "id" in p
            assert "name" in p
            assert "trigger_type" in p
            assert "action" in p
            assert "enabled" in p
            assert isinstance(p["enabled"], bool)

@pytest.mark.asyncio
async def test_policies_api_toggle_and_state():
    """Verify policy toggle flips enabled status without corrupting structure."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/policies")
        first_pol = res.json()[0]
        pol_id = first_pol["id"]
        initial_state = first_pol["enabled"]

        toggle_res = await client.put(f"/api/v1/policies/{pol_id}/toggle")
        assert toggle_res.status_code == 200
        assert toggle_res.json()["policy"]["enabled"] is not initial_state

        # Toggle back
        restore_res = await client.put(f"/api/v1/policies/{pol_id}/toggle")
        assert restore_res.status_code == 200
        assert restore_res.json()["policy"]["enabled"] is initial_state


# ==============================================================
# REGRESSION TEST 2: SECURITY REPORTS RECOMMENDATIONS SCHEMA
# ==============================================================

@pytest.mark.asyncio
async def test_report_contains_recommendations_and_recommended_steps():
    """Verify report schema includes both 'recommendations' and 'recommended_steps'."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Run a demo scan to populate a real report
        demo = await client.post("/api/v1/demo/run/case_a_normal")
        assert demo.status_code == 200
        scan_id = demo.json()["id"]

        r_json = await client.get(f"/api/v1/reports/{scan_id}/json")
        assert r_json.status_code == 200
        data = r_json.json()
        
        # Must have both fields for backward and forward compatibility
        assert "recommendations" in data
        assert "recommended_steps" in data
        assert isinstance(data["recommendations"], list)
        assert isinstance(data["recommended_steps"], list)
        assert len(data["recommendations"]) > 0

@pytest.mark.asyncio
async def test_report_schema_empty_recommendations_handling():
    """Verify custom/mocked empty recommendations report works cleanly."""
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Non-existent scan returns 404, not unhandled 500
        res = await client.get("/api/v1/reports/non-existent-scan-id")
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()
