"""Regression tests verifying target/action alignment across all supported attack types and targets."""

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.api.state import app_state
from app.config import settings
from app.simulator.scenarios import inject_sensor_spoofing, inject_capacity_manipulation


TEST_GATEWAY_TOKEN = "matrix-gateway-token-12345"


@pytest.fixture(scope="module")
def gateway_client():
    import os
    os.environ["ATTACK_GATEWAY_TOKEN"] = TEST_GATEWAY_TOKEN
    settings.ATTACK_GATEWAY_TOKEN = TEST_GATEWAY_TOKEN
    with TestClient(app, headers={"Authorization": f"Bearer {TEST_GATEWAY_TOKEN}"}) as client:
        yield client


@pytest.fixture(autouse=True)
def reset_state():
    app_state.reset(seed=42)


class TestTargetActionPrecision:
    """Proves that a requested attack target ONLY modifies that intended field."""

    def test_temperature_spoofing_does_not_modify_humidity(self, gateway_client):
        """Spoofing temperature must preserve the baseline humidity value untouched."""
        baseline_obs = app_state.warehouse.get_current_observation()
        baseline_humidity = baseline_obs.humidity

        payload = {
            "attack_type": "sensor_spoofing",
            "target": "temperature",
            "value": 29.5,
            "objective": "test temperature-only spoofing",
        }
        res = gateway_client.post("/api/attacker/attack", json=payload)
        assert res.status_code == 200

        current_obs = app_state.warehouse.get_current_observation()
        assert current_obs.temperature == 29.5
        # Humidity must NOT be silently substituted with 95.0 or altered
        assert abs(current_obs.humidity - baseline_humidity) < 0.5
        assert current_obs.humidity != 95.0

    def test_humidity_spoofing_does_not_modify_temperature(self, gateway_client):
        """Spoofing humidity must preserve the baseline temperature value untouched."""
        baseline_obs = app_state.warehouse.get_current_observation()
        baseline_temp = baseline_obs.temperature

        payload = {
            "attack_type": "sensor_spoofing",
            "target": "humidity",
            "value": 92.0,
            "objective": "test humidity-only spoofing",
        }
        res = gateway_client.post("/api/attacker/attack", json=payload)
        assert res.status_code == 200

        current_obs = app_state.warehouse.get_current_observation()
        assert current_obs.humidity == 92.0
        # Temperature must NOT be set to humidity value or altered
        assert abs(current_obs.temperature - baseline_temp) < 0.5
        assert current_obs.temperature != 92.0

    def test_environmental_sensors_target_spoofs_both(self, gateway_client):
        """Targeting environmental_sensors mutates both temperature and humidity."""
        payload = {
            "attack_type": "sensor_spoofing",
            "target": "environmental_sensors",
            "value": 26.0,
            "objective": "test dual environmental spoofing",
        }
        res = gateway_client.post("/api/attacker/attack", json=payload)
        assert res.status_code == 200

        current_obs = app_state.warehouse.get_current_observation()
        assert current_obs.temperature == 26.0
        assert current_obs.humidity == 95.0

    def test_free_capacity_manipulation_preserves_total_capacity(self, gateway_client):
        """Manipulating free_capacity must NOT alter total capacity."""
        baseline_obs = app_state.warehouse.get_current_observation()
        baseline_total = baseline_obs.capacity

        payload = {
            "attack_type": "capacity_manipulation",
            "target": "free_capacity",
            "value": 38.0,
            "objective": "test free capacity targeting",
        }
        res = gateway_client.post("/api/attacker/attack", json=payload)
        assert res.status_code == 200

        current_obs = app_state.warehouse.get_current_observation()
        assert current_obs.free_capacity == 38.0
        assert current_obs.capacity == baseline_total

    def test_total_capacity_manipulation_alters_capacity(self, gateway_client):
        """Manipulating capacity target modifies total capacity directly."""
        payload = {
            "attack_type": "capacity_manipulation",
            "target": "capacity",
            "value": 30.0,
            "objective": "test total capacity targeting",
        }
        res = gateway_client.post("/api/attacker/attack", json=payload)
        assert res.status_code == 200

        current_obs = app_state.warehouse.get_current_observation()
        assert current_obs.capacity == 30.0

    def test_inventory_manipulation_target(self, gateway_client):
        """Manipulating inventory target directly updates inventory and occupancy."""
        payload = {
            "attack_type": "inventory_manipulation",
            "target": "inventory",
            "value": 22.0,
            "objective": "test inventory targeting",
        }
        res = gateway_client.post("/api/attacker/attack", json=payload)
        assert res.status_code == 200

        current_obs = app_state.warehouse.get_current_observation()
        assert current_obs.inventory == 22.0
        assert current_obs.occupancy == round((22.0 / current_obs.capacity) * 100, 2)

    def test_replay_attack_all_allowed_targets(self, gateway_client):
        """Verify all whitelisted replay targets (inventory, telemetry_stream, observation, state)."""
        targets = ["inventory", "telemetry_stream", "observation", "state"]
        for target in targets:
            # Advance warehouse first so replay history is available
            app_state.warehouse.step()
            payload = {
                "attack_type": "replay_attack",
                "target": target,
                "value": None,
                "objective": f"test replay with target {target}",
            }
            res = gateway_client.post("/api/attacker/attack", json=payload)
            assert res.status_code == 200, f"Target '{target}' failed for replay_attack: {res.text}"

    def test_coordinated_weak_all_allowed_targets(self, gateway_client):
        """Verify coordinated weak attack targets (multi_metric, inventory_and_capacity)."""
        for target in ["multi_metric", "inventory_and_capacity"]:
            payload = {
                "attack_type": "coordinated_weak",
                "target": target,
                "value": -1.5,
                "objective": f"test coordinated weak with target {target}",
            }
            res = gateway_client.post("/api/attacker/attack", json=payload)
            assert res.status_code == 200

    def test_multi_source_all_allowed_targets(self, gateway_client):
        """Verify multi-source attack targets (facility, cross_subsystem, multi_source)."""
        for target in ["facility", "cross_subsystem", "multi_source"]:
            payload = {
                "attack_type": "multi_source",
                "target": target,
                "value": None,
                "objective": f"test multi-source with target {target}",
            }
            res = gateway_client.post("/api/attacker/attack", json=payload)
            assert res.status_code == 200
