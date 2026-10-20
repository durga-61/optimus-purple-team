"""Tests for Live Operations & Sensor Monitor (/operations) and Warehouse History API."""

import re
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.api.main import app
from app.api.state import app_state


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_before_each():
    """Ensure every test starts with a clean baseline state."""
    app_state.reset()


class TestOperationsMonitor:
    """Test suite for the Live Operations & Sensor Monitor page and history API."""

    def test_operations_page_loads(self, client):
        """1. Verify /operations loads successfully with required titles, 4 sections, and no security terms."""
        response = client.get("/operations")
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")
        html = response.text

        # Core required titles & subtitles
        assert "LIVE OPERATIONS & SENSOR MONITOR" in html
        assert "Simulated Organizational Environment - Raw Operational Data" in html
        assert "SIMULATED FACILITY" in html

        # Four required sections
        assert "1. Current Observation" in html
        assert "2. Sensor / Operational Metrics" in html
        assert "3. Recent Observation History" in html
        assert "4. Simulation Controls" in html

        # Key DOM hooks for Section 1 (Current Observation)
        assert 'id="ops-wh-id"' in html
        assert 'id="ops-wh-step"' in html
        assert 'id="ops-last-timestamp"' in html
        assert 'id="ops-current-temp"' in html
        assert 'id="ops-current-hum"' in html
        assert 'id="ops-current-occ"' in html
        assert 'id="ops-current-inv"' in html
        assert 'id="ops-current-free-cap"' in html
        assert 'id="ops-current-total-cap"' in html
        assert 'id="ops-current-inbound"' in html
        assert 'id="ops-current-outbound"' in html

        # Key DOM hooks for Section 2 (Metrics & Charts)
        assert 'id="ops-temp"' in html
        assert 'id="ops-humidity"' in html
        assert 'id="ops-occupancy"' in html
        assert 'id="ops-inventory"' in html
        assert 'id="ops-free-capacity"' in html
        assert 'id="ops-total-capacity"' in html
        assert 'id="ops-inbound"' in html
        assert 'id="ops-outbound"' in html
        assert 'id="chart-svg-temp"' in html
        assert 'id="chart-svg-inv"' in html
        assert 'id="chart-svg-hum"' in html
        assert 'id="chart-svg-occ"' in html

        # Key DOM hooks for Section 3 (History Table)
        assert 'id="ops-history-tbody"' in html

        # Key DOM hooks for Section 4 (Controls)
        assert 'id="btn-ops-step"' in html
        assert 'id="btn-ops-reset"' in html
        assert "RUN NEXT OBSERVATION" in html
        assert "RESET SIMULATION" in html

        # Verify no security terminology is present on the page
        forbidden_terms = [
            "security score",
            "risk score",
            "ml anomaly",
            "semantic constraints",
            "c1 capacity",
            "c2 flow",
            "c3 bounds",
            "temporal analysis",
            "structural analysis",
            "attack classification",
            "defender alerts",
            "security portal",
        ]
        lower_html = html.lower()
        for term in forbidden_terms:
            assert term not in lower_html, f"Forbidden security term '{term}' found in operations.html"

    def test_warehouse_history_returns_valid_data(self, client):
        """2. Verify /api/warehouse/history returns valid simulator data."""
        response = client.get("/api/warehouse/history")
        assert response.status_code == 200
        data = response.json()

        assert data["warehouse"] == "W01"
        assert "observations" in data
        assert isinstance(data["observations"], list)
        assert len(data["observations"]) >= 1

        first_obs = data["observations"][0]
        assert "step" in first_obs
        assert "timestamp" in first_obs
        assert "temperature" in first_obs
        assert "humidity" in first_obs
        assert "inventory" in first_obs
        assert "free_capacity" in first_obs
        assert "total_capacity" in first_obs
        assert "occupancy" in first_obs
        assert "inbound" in first_obs
        assert "outbound" in first_obs

        assert first_obs["step"] == 0
        assert first_obs["inventory"] == 42.0
        assert first_obs["free_capacity"] == 8.0
        assert first_obs["total_capacity"] == 50.0

    def test_history_endpoint_does_not_advance_simulation(self, client):
        """3. Verify that polling /api/warehouse/history never advances the simulation step."""
        initial_step = app_state.warehouse.step_count

        for _ in range(5):
            res = client.get("/api/warehouse/history")
            assert res.status_code == 200

        assert app_state.warehouse.step_count == initial_step

    def test_history_endpoint_does_not_invoke_defender_service(self, client):
        """4. Verify that /api/warehouse/history never invokes DefenderService."""
        with patch.object(app_state.defender, "analyze", wraps=app_state.defender.analyze) as mock_analyze:
            res = client.get("/api/warehouse/history")
            assert res.status_code == 200
            assert mock_analyze.call_count == 0

    def test_limit_validation_works(self, client):
        """5. Verify limit parameter validation (range 1-200, default 50)."""
        # Step a few times to build history
        for _ in range(3):
            client.post("/api/warehouse/step")

        # Valid limits
        res1 = client.get("/api/warehouse/history?limit=1")
        assert res1.status_code == 200
        assert len(res1.json()["observations"]) == 1

        res_max = client.get("/api/warehouse/history?limit=200")
        assert res_max.status_code == 200
        assert len(res_max.json()["observations"]) == 4

        # Invalid limits - out of range (ge=1, le=200)
        res_zero = client.get("/api/warehouse/history?limit=0")
        assert res_zero.status_code == 422

        res_over = client.get("/api/warehouse/history?limit=201")
        assert res_over.status_code == 422

        res_str = client.get("/api/warehouse/history?limit=notanumber")
        assert res_str.status_code == 422

    def test_run_next_observation_changes_actual_simulator_state(self, client):
        """6. Verify Run Next Observation advances the simulator state."""
        curr_before = client.get("/api/warehouse/current").json()
        assert curr_before["step"] == 0

        # Run next observation
        step_res = client.post("/api/warehouse/step")
        assert step_res.status_code == 200
        step_data = step_res.json()
        assert step_data["observation"]["step"] == 1

        # Check simulator state directly
        curr_after = client.get("/api/warehouse/current").json()
        assert curr_after["step"] == 1
        assert app_state.warehouse.step_count == 1

    def test_reset_restores_simulator_state(self, client):
        """7. Verify Reset restores the simulator state to baseline."""
        # Advance 3 steps
        for _ in range(3):
            client.post("/api/warehouse/step")

        assert app_state.warehouse.step_count == 3

        # Call reset endpoint
        reset_res = client.post("/api/warehouse/reset")
        assert reset_res.status_code == 200
        assert reset_res.json()["success"] is True

        # Verify baseline state restored
        curr = client.get("/api/warehouse/current").json()
        assert curr["step"] == 0
        assert curr["inventory"] == 42.0
        assert curr["free_capacity"] == 8.0

        history = client.get("/api/warehouse/history").json()
        assert len(history["observations"]) == 1
        assert history["observations"][0]["step"] == 0

    def test_operations_page_uses_real_backend_data(self, client):
        """8. Verify Operations page binds to real backend endpoints and all DOM IDs exist."""
        # Verify static delivery of operations.js
        js_resp = client.get("/js/operations.js")
        assert js_resp.status_code == 200
        js = js_resp.text

        # Verify script fetches real backend endpoints
        assert "/warehouse/current" in js
        assert "/warehouse/history" in js
        assert "/warehouse/step" in js
        assert "/warehouse/reset" in js

        # Verify all DOM IDs queried by operations.js exist in operations.html
        html_resp = client.get("/operations")
        assert html_resp.status_code == 200
        html = html_resp.text

        queried_ids = re.findall(r'getElementById\([\'"]([^\'"]+)[\'"]\)', js)
        assert len(queried_ids) >= 20

        missing_ids = [elem_id for elem_id in queried_ids if f'id="{elem_id}"' not in html]
        assert missing_ids == [], f"DOM IDs queried in operations.js missing in operations.html: {missing_ids}"

    def test_no_security_analysis_returned_by_history_endpoint(self, client):
        """9. Verify no security analysis or decision data is returned by the history endpoint."""
        response = client.get("/api/warehouse/history")
        assert response.status_code == 200
        data = response.json()

        # Top-level should not contain security fields
        forbidden_top_keys = [
            "security_analysis",
            "decision",
            "alerts",
            "ml",
            "semantic",
            "temporal",
            "structural",
            "risk_score",
            "integrity_score",
        ]
        for key in forbidden_top_keys:
            assert key not in data, f"Security key '{key}' unexpectedly found in history response"

        # Individual observation items should not contain security fields
        forbidden_item_keys = [
            "security_analysis",
            "anomaly_score",
            "risk_score",
            "classification",
            "is_anomaly",
            "semantic_score",
            "temporal_score",
            "structural_score",
        ]
        for obs in data["observations"]:
            for key in forbidden_item_keys:
                assert key not in obs, f"Security key '{key}' unexpectedly found in observation item"
