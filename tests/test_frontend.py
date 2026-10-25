"""Tests for Organization Security Portal static frontend delivery and asset integrity."""

import re
import pytest
from fastapi.testclient import TestClient
from app.api.main import app


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


class TestFrontendPortal:
    """Test suite for static frontend delivery, DOM element verification, and contract safety."""

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
        assert 'id="c4-block"' in html
        assert 'id="alerts-container"' in html
        assert 'id="events-container"' in html

    def test_portal_serves_css_stylesheet(self, client):
        response = client.get("/css/style.css")
        assert response.status_code == 200
        assert "text/css" in response.headers.get("content-type", "")
        assert "--bg-main" in response.text
        assert ".portal-header" in response.text
        assert ".badge-normal" in response.text
        assert ".badge-na" in response.text or ".badge-not_applicable" in response.text
        assert ".sensor-card" in response.text

    def test_portal_serves_js_application(self, client):
        response = client.get("/js/app.js")
        assert response.status_code == 200
        assert "javascript" in response.headers.get("content-type", "")
        assert "refreshDashboard" in response.text
        assert "advanceSimulation" in response.text
        assert "seekPlayback" in response.text
        assert "toggleDataSourceMode" in response.text
        assert "triggerScenario" in response.text
        assert "formatNullableNumber" in response.text

    def test_all_javascript_dom_ids_exist_in_html(self, client):
        """Verify that every DOM ID queried by app.js exists in index.html to prevent null reference errors."""
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

    def test_portal_dataset_context_and_playback_elements(self, client):
        """Verify presence of dataset playback banner, multi-sensor array, and seek/step controls."""
        response = client.get("/")
        html = response.text

        assert 'id="source-notice-banner"' in html
        assert 'id="source-description"' in html
        assert 'id="source-badge"' in html
        assert 'id="playback-fill"' in html
        assert 'id="wh-delta-t"' in html
        assert 'id="wh-active-sensors"' in html
        assert 'id="sensor-matrix"' in html
        assert 'id="ops-seek-step"' in html
        assert 'id="btn-seek"' in html
        assert 'id="btn-toggle-mode"' in html
        assert "/operations" in html

    def test_operations_monitor_endpoint(self, client):
        """Verify that the Operations Monitor page is available and properly linked."""
        response = client.get("/operations")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        assert "LIVE OPERATIONS" in response.text or "Sensor Monitor" in response.text

    def test_data_flow_contract_real_dataset_integrity(self, client):
        """Verify backend API responses adhere to the non-fabrication contract for Hohenheim dataset."""
        # Ensure initial state in Hohenheim mode
        client.post("/api/warehouse/mode/hohenheim")
        r_reset = client.post("/api/warehouse/reset")
        assert r_reset.status_code == 200

        r_wh = client.get("/api/warehouse/current")
        assert r_wh.status_code == 200
        wh_data = r_wh.json()
        assert wh_data["source"] == "hohenheim"
        assert wh_data["inventory"] is None
        assert wh_data["capacity"] is None
        assert wh_data["temperature"] is not None
        assert wh_data["humidity"] is not None
        assert len(wh_data["sensors"]) == 9

        r_sec = client.get("/api/security/latest")
        assert r_sec.status_code == 200
        sec_data = r_sec.json()

        # Semantic checks: C1 and C2 must be NOT_APPLICABLE
        c_map = {c["constraint"]: c["status"] for c in sec_data["semantic"]["constraints"]}
        assert c_map["C1"] == "NOT_APPLICABLE"
        assert c_map["C2"] == "NOT_APPLICABLE"
        assert c_map["C3"] in ("PASSED", "WARNING")
        assert c_map["C4"] in ("PASSED", "WARNING", "NOT_APPLICABLE")

        # ML Anomaly detector evaluated features
        ml_features = sec_data["ml"]["features_evaluated"]
        assert len(ml_features) >= 4
        assert "temperature" in ml_features
        assert "inter_sensor_temp_delta" in ml_features


class TestThreePortalArchitecture:
    """Explicit tests for the Three-Portal Architecture routes and transmission delivery."""

    def test_defender_portal_route(self, client):
        """Verify GET / serves Defender Portal with status 200 and required elements."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert "Defender Portal" in resp.text
        assert 'id="joint-classification"' in resp.text
        assert 'id="c1-block"' in resp.text
        assert 'id="ml-score"' in resp.text

    def test_transmitter_portal_route(self, client):
        """Verify GET /transmitter serves Sensor Transmitter with status 200."""
        resp = client.get("/transmitter")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert "Sensor Transmitter" in resp.text
        assert 'id="tx-sensor-matrix"' in resp.text
        assert 'id="tx-step-input"' in resp.text
        assert 'id="btn-transmit"' in resp.text

    def test_simulator_portal_route(self, client):
        """Verify GET /simulator serves Attack Simulator with status 200."""
        resp = client.get("/simulator")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert "Attack Simulator" in resp.text
        assert 'id="attack-scenario-select"' in resp.text
        assert 'id="btn-run-attack"' in resp.text
        assert 'id="metric-total-runs"' in resp.text

    def test_operations_redirect_to_transmitter(self, client):
        """Verify GET /operations redirects (HTTP 307) to /transmitter."""
        resp = client.get("/operations", follow_redirects=False)
        assert resp.status_code == 307
        assert resp.headers.get("location") == "/transmitter"

    def test_warehouse_transmit_endpoint(self, client):
        """Verify POST /api/warehouse/transmit evaluates observation and returns delivery receipt."""
        resp = client.post("/api/warehouse/transmit", json={"step": 0})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "DELIVERED"
        assert "OBS-" in data["observation_id"]
        assert "defender_classification" in data
        assert "risk_score" in data
        assert data["latency_ms"] >= 0

    def test_demo_portal_route(self, client):
        """Verify GET /demo serves the design demo sandbox with favicon and no VIT CSBS badge."""
        resp = client.get("/demo")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert "Demo Sandbox" in resp.text
        assert "demo.css" in resp.text
        assert "favicon.svg" in resp.text
        assert "VIT CSBS" not in resp.text
        assert 'id="demo-telemetry-grid"' in resp.text
        assert 'id="demo-verdict-banner"' in resp.text

    def test_favicon_route(self, client):
        """Verify GET /favicon.svg and /favicon.ico return SVG image content with HTTP 200."""
        for path in ["/favicon.svg", "/favicon.ico"]:
            resp = client.get(path)
            assert resp.status_code == 200
            assert "image/svg+xml" in resp.headers.get("content-type", "")
            assert "<svg" in resp.text


