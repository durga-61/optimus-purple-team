"""Integration tests for FastAPI REST API endpoints."""

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.api.state import app_state


@pytest.fixture(scope="module")
def client():
    """Create FastAPI TestClient."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_state_before_test():
    """Ensure baseline state before each API test."""
    app_state.reset(seed=42)


class TestHealthEndpoints:
    """Tests for /api/health."""

    def test_get_health_success(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "organization-security-platform"
        assert data["simulator"] == "running"
        assert data["defender"] == "ready"
        assert "timestamp" in data


class TestWarehouseEndpoints:
    """Tests for /api/warehouse/*."""

    def test_get_warehouse_current(self, client):
        response = client.get("/api/warehouse/current")
        assert response.status_code == 200
        data = response.json()
        assert data["warehouse"] == "W01"
        assert data["capacity"] == 50.0
        assert data["inventory"] == 42.0
        assert data["free_capacity"] == 8.0
        assert data["occupancy"] == 84.0
        assert data["temperature"] == 4.2
        assert data["humidity"] == 71.0
        assert "timestamp" in data

    def test_post_warehouse_step_advances_and_analyzes(self, client):
        # Step the warehouse
        response = client.post("/api/warehouse/step")
        assert response.status_code == 200
        data = response.json()

        assert "observation" in data
        assert "security_analysis" in data
        obs = data["observation"]
        analysis = data["security_analysis"]

        assert obs["step"] == 1
        assert analysis["warehouse"] == "W01"
        assert analysis["decision"]["classification"] == "NORMAL"
        assert analysis["decision"]["integrity_score"] >= 95.0
        assert analysis["ml"]["status"] in ("NORMAL", "SUSPICIOUS")
        assert analysis["semantic"]["status"] == "NORMAL"

    def test_polling_endpoints_are_idempotent_and_do_not_advance_simulation(self, client):
        """Verify that repeated polling of GET endpoints does not advance state or generate duplicate events/alerts."""
        initial_wh = client.get("/api/warehouse/current").json()
        initial_status = client.get("/api/security/status").json()
        initial_alerts = client.get("/api/security/alerts").json()
        initial_events = client.get("/api/security/events").json()

        assert initial_wh["step"] == 0

        # Simulate 10 polling cycles
        for _ in range(10):
            wh = client.get("/api/warehouse/current").json()
            status = client.get("/api/security/status").json()
            latest = client.get("/api/security/latest").json()
            alerts = client.get("/api/security/alerts").json()
            events = client.get("/api/security/events").json()

            assert wh["step"] == 0
            assert wh["inventory"] == initial_wh["inventory"]
            assert wh["timestamp"] == initial_wh["timestamp"]
            assert status["status"] == initial_status["status"]
            assert len(alerts) == len(initial_alerts)
            assert len(events) == len(initial_events)

        # Now execute step once
        step_res = client.post("/api/warehouse/step").json()
        assert step_res["observation"]["step"] == 1

        # Poll 5 more times; step must stay at 1
        for _ in range(5):
            wh = client.get("/api/warehouse/current").json()
            assert wh["step"] == 1


class TestSecurityEndpoints:
    """Tests for /api/security/*."""

    def test_get_security_status(self, client):
        response = client.get("/api/security/status")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "NORMAL"
        assert data["integrity_score"] >= 95.0
        assert data["active_alerts"] == 0
        assert data["backend_health"] == "ONLINE"

    def test_get_security_latest(self, client):
        response = client.get("/api/security/latest")
        assert response.status_code == 200
        data = response.json()
        assert data["warehouse"] == "W01"
        assert "ml" in data
        assert "semantic" in data
        assert "temporal" in data
        assert "structural" in data
        assert "decision" in data
        assert len(data["semantic"]["constraints"]) == 3

    def test_get_security_alerts_empty_initially(self, client):
        response = client.get("/api/security/alerts")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 0

    def test_get_security_events(self, client):
        response = client.get("/api/security/events?limit=10")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        event_types = [e["event_type"] for e in data]
        assert "DATA_RECEIVED" in event_types

    def test_post_security_reset(self, client):
        # Advance simulation
        client.post("/api/warehouse/step")
        assert app_state.warehouse.step_count == 1

        # Reset
        response = client.post("/api/security/reset")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True

        # Verify state is back to 0
        assert app_state.warehouse.step_count == 0
        current = client.get("/api/warehouse/current").json()
        assert current["step"] == 0
        assert current["inventory"] == 42.0


class TestScenarioEndpoints:
    """Tests for /api/scenarios/*."""

    def test_list_scenarios(self, client):
        response = client.get("/api/scenarios")
        assert response.status_code == 200
        data = response.json()
        assert "scenarios" in data
        scenario_ids = [s["id"] for s in data["scenarios"]]
        assert "capacity_manipulation" in scenario_ids
        assert "inventory_manipulation" in scenario_ids
        assert "sensor_spoofing" in scenario_ids
        assert "replay" in scenario_ids
        assert "coordinated_manipulation" in scenario_ids
        assert "multi_source_manipulation" in scenario_ids

    def test_execute_capacity_manipulation_scenario(self, client):
        """Validates that triggering capacity attack produces verified C1 violation and alert."""
        response = client.post("/api/scenarios/capacity_manipulation")
        assert response.status_code == 200
        data = response.json()

        assert data["scenario"] == "capacity_manipulation"
        obs = data["observation"]
        analysis = data["security_analysis"]

        # Check observation values
        assert obs["free_capacity"] == 40.0
        assert obs["inventory"] + obs["free_capacity"] > obs["capacity"]

        # Check real DefenderService results
        assert analysis["semantic"]["status"] == "VIOLATION"
        assert "C1" in analysis["semantic"]["violated_constraints"]
        assert analysis["decision"]["classification"] in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK")
        assert analysis["decision"]["integrity_score"] < 75.0
        assert len(analysis["alerts"]) == 1

        # Check alerts endpoint reflects new alert
        alerts_resp = client.get("/api/security/alerts?active_only=true")
        assert alerts_resp.status_code == 200
        alerts = alerts_resp.json()
        assert len(alerts) == 1
        assert "ALT-" in alerts[0]["alert_id"]
        assert alerts[0]["classification"] == analysis["decision"]["classification"]

        # Check security status reflects alert
        status_resp = client.get("/api/security/status")
        assert status_resp.status_code == 200
        assert status_resp.json()["active_alerts"] == 1
        assert status_resp.json()["status"] == analysis["decision"]["classification"]

    def test_invalid_scenario_returns_404(self, client):
        response = client.post("/api/scenarios/non_existent_exploit")
        assert response.status_code == 404
        data = response.json()
        assert "not found" in data["detail"].lower()

    @pytest.mark.parametrize("scenario_name", [
        "capacity_manipulation",
        "inventory_manipulation",
        "sensor_spoofing",
        "replay_attack",
        "coordinated_weak",
        "multi_source",
    ])
    def test_execute_all_scenarios_and_aliases(self, client, scenario_name):
        """Validates that all six scenarios and their aliases execute successfully through the API."""
        response = client.post(f"/api/scenarios/{scenario_name}")
        assert response.status_code == 200
        data = response.json()
        assert "scenario" in data
        assert "observation" in data
        assert "security_analysis" in data
        obs = data["observation"]
        analysis = data["security_analysis"]
        assert obs["is_attack_injected"] is True
        assert analysis["decision"]["classification"] != "NORMAL"

    def test_concurrent_stepping_is_thread_safe(self, client):
        """Validates that concurrent step requests are safely serialized by AppState lock."""
        import concurrent.futures

        steps_to_run = 10
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(client.post, "/api/warehouse/step") for _ in range(steps_to_run)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        for res in results:
            assert res.status_code == 200

        wh = client.get("/api/warehouse/current").json()
        assert wh["step"] == steps_to_run

    def test_attack_then_recovery_sequence(self, client):
        """Validates recovery: attack raises risk/alerts, subsequent steps reduce risk via temporal decay."""
        # 1. Trigger capacity manipulation
        res = client.post("/api/scenarios/capacity_manipulation").json()
        attack_risk = res["security_analysis"]["decision"]["risk_score"]
        assert attack_risk >= 0.35

        # 2. Advance 6 normal steps
        for _ in range(6):
            client.post("/api/warehouse/step")

        latest = client.get("/api/security/latest").json()
        recovered_risk = latest["decision"]["risk_score"]
        # Temporal decay lowers risk score significantly
        assert recovered_risk < attack_risk
        assert latest["temporal"]["status"] in ("STABLE", "ELEVATED")

