"""Tests for Organization Security Portal static frontend delivery and asset integrity."""

import pytest
from fastapi.testclient import TestClient
from app.api.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


class TestFrontendPortal:
    """Test suite for static frontend delivery and template element verification."""

    def test_portal_root_serves_html(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        html = response.text

        # Core required portal sections
        assert "Organization Security Portal" in html
        assert "Security Overview" in html or "kpi-grid" in html
        assert "Live Warehouse Operations" in html
        assert "Security Pipeline Verification" in html
        assert "Detailed Security Analysis" in html
        assert "Active Security Alerts" in html
        assert "Security Event Stream" in html
        assert "Controlled Security Test Scenarios" in html

        # Key DOM hooks referenced by JavaScript client
        assert 'id="kpi-security-status"' in html
        assert 'id="kpi-integrity-score"' in html
        assert 'id="kpi-active-alerts"' in html
        assert 'id="wh-inventory"' in html
        assert 'id="wh-free-capacity"' in html
        assert 'id="stage-sem"' in html
        assert 'id="c1-block"' in html
        assert 'id="c2-block"' in html
        assert 'id="c3-block"' in html
        assert 'id="alerts-container"' in html
        assert 'id="events-container"' in html

    def test_portal_serves_css_stylesheet(self, client):
        response = client.get("/css/style.css")
        assert response.status_code == 200
        assert "text/css" in response.headers.get("content-type", "")
        assert "--bg-main" in response.text
        assert ".portal-header" in response.text
        assert ".badge-normal" in response.text

    def test_portal_serves_js_application(self, client):
        response = client.get("/js/app.js")
        assert response.status_code == 200
        assert "javascript" in response.headers.get("content-type", "")
        assert "refreshDashboard" in response.text
        assert "advanceSimulation" in response.text
        assert "triggerScenario" in response.text

    def test_all_javascript_dom_ids_exist_in_html(self, client):
        """Verify that every DOM ID queried by app.js exists in index.html to prevent null reference errors."""
        import re
        html_resp = client.get("/")
        assert html_resp.status_code == 200
        html = html_resp.text

        js_resp = client.get("/js/app.js")
        assert js_resp.status_code == 200
        js = js_resp.text

        queried_ids = re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", js)
        assert len(queried_ids) >= 50

        missing_ids = [elem_id for elem_id in queried_ids if f'id="{elem_id}"' not in html]
        assert missing_ids == [], f"DOM IDs queried in app.js missing in index.html: {missing_ids}"

