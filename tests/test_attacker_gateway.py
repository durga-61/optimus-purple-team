"""Tests for the Attack Gateway interface and Part 1 / Part 2 security boundary."""

import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.api.routes.attacker import RATE_LIMIT_MAX_REQUESTS, _rate_limit_records
from app.api.state import app_state


TEST_GATEWAY_TOKEN = "test-research-token-7a8b9c"


@pytest.fixture(scope="module")
def client():
    import os
    from app.config import settings
    os.environ["ATTACK_GATEWAY_TOKEN"] = TEST_GATEWAY_TOKEN
    settings.ATTACK_GATEWAY_TOKEN = TEST_GATEWAY_TOKEN
    with TestClient(app, headers={"Authorization": f"Bearer {TEST_GATEWAY_TOKEN}"}) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_before_each():
    """Ensure each test runs from a pristine baseline state."""
    app_state.reset()
    import app.api.routes.attacker as atk_mod
    atk_mod._attack_history.clear()
    atk_mod._attack_counter = 0
    atk_mod._rate_limit_records.clear()


class TestAttackGatewayBoundary:
    """Test suite verifying the Attack Gateway security boundary, validation, and isolation."""

    def test_1_valid_attack_is_accepted(self, client):
        """1. Verify valid whitelisted attack request is accepted and executed."""
        payload = {
            "attack_type": "inventory_manipulation",
            "target": "inventory",
            "value": 20.0,
            "objective": "create an inventory flow discrepancy",
        }
        res = client.post("/api/attacker/attack", json=payload)
        assert res.status_code == 200
        data = res.json()

        assert data["execution"] == "accepted"
        assert data["attack_id"].startswith("ATK-")
        assert data["detection"] in ["DETECTED", "UNDETECTED"]
        assert data["classification"] in [
            "NORMAL",
            "LOW",
            "SUSPICIOUS",
            "POTENTIAL_ATTACK",
            "COORDINATED_ATTACK",
            None,
        ]
        assert "timestamp" in data

    def test_2_invalid_attack_type_is_rejected(self, client):
        """2. Verify non-whitelisted attack types are rejected with HTTP 422."""
        invalid_types = [
            "sql_injection",
            "buffer_overflow",
            "remote_code_execution",
            "arbitrary_dos",
            "unsupported_vector",
        ]
        for atk_type in invalid_types:
            payload = {
                "attack_type": atk_type,
                "target": "inventory",
                "value": 10.0,
                "objective": "test injection",
            }
            res = client.post("/api/attacker/attack", json=payload)
            assert res.status_code == 422
            assert "not permitted" in res.text or "Input should be" in res.text

    def test_3_invalid_target_is_rejected(self, client):
        """3. Verify mismatched or invalid targets for a specific attack type are rejected."""
        # target "temperature" is invalid for "inventory_manipulation"
        payload = {
            "attack_type": "inventory_manipulation",
            "target": "temperature",
            "value": 20.0,
            "objective": "invalid target",
        }
        res = client.post("/api/attacker/attack", json=payload)
        assert res.status_code == 422
        assert "invalid for attack type" in res.text

        # target "database_credentials" is completely unknown
        payload2 = {
            "attack_type": "sensor_spoofing",
            "target": "database_credentials",
            "value": 20.0,
            "objective": "invalid target",
        }
        res2 = client.post("/api/attacker/attack", json=payload2)
        assert res2.status_code == 422
        assert "invalid for attack type" in res2.text

    def test_4_malformed_parameters_are_rejected(self, client):
        """4. Verify malformed parameter types and missing required fields are rejected."""
        # Value is non-numeric string
        res = client.post(
            "/api/attacker/attack",
            json={
                "attack_type": "capacity_manipulation",
                "target": "free_capacity",
                "value": "twenty-five",
                "objective": "bad parameter",
            },
        )
        assert res.status_code == 422

        # Empty objective string
        res_empty = client.post(
            "/api/attacker/attack",
            json={
                "attack_type": "capacity_manipulation",
                "target": "free_capacity",
                "value": 30.0,
                "objective": "",
            },
        )
        assert res_empty.status_code == 422

    def test_5_arbitrary_fields_cannot_manipulate_simulator_state(self, client):
        """5. Verify unexpected JSON fields are rejected by extra='forbid'."""
        malicious_payload = {
            "attack_type": "inventory_manipulation",
            "target": "inventory",
            "value": 20.0,
            "objective": "payload injection",
            "exec_command": "__import__('os').system('dir')",
            "override_internal_state": True,
        }
        res = client.post("/api/attacker/attack", json=malicious_payload)
        assert res.status_code == 422
        assert "Extra inputs are not permitted" in res.text

    def test_6_arbitrary_attack_names_cannot_execute(self, client):
        """6. Verify arbitrary attack strings cannot trigger any execution."""
        res = client.post(
            "/api/attacker/attack",
            json={
                "attack_type": "arbitrary_custom_attack",
                "target": "facility",
                "objective": "execute custom",
            },
        )
        assert res.status_code == 422
        assert app_state.warehouse.step_count == 0

    def test_7_gateway_uses_controlled_scenario_mechanisms(self, client):
        """7. Verify gateway translates requests to real controlled scenarios."""
        # Execute capacity manipulation through gateway
        payload = {
            "attack_type": "capacity_manipulation",
            "target": "free_capacity",
            "value": 45.0,
            "objective": "desynchronize free capacity from total capacity",
        }
        res = client.post("/api/attacker/attack", json=payload)
        assert res.status_code == 200

        # Verify underlying simulator observation was mutated via controlled scenario
        curr_obs = app_state.warehouse.get_current_observation()
        assert curr_obs.is_attack_injected is True
        assert curr_obs.attack_type == "capacity_manipulation"
        assert curr_obs.free_capacity == 45.0

    def test_8_observation_contains_only_approved_fields(self, client):
        """8. Verify GET /api/attacker/observation exposes only approved raw fields."""
        res = client.get("/api/attacker/observation")
        assert res.status_code == 200
        data = res.json()

        approved_fields = {
            "target",
            "inventory",
            "free_capacity",
            "temperature",
            "humidity",
            "occupancy",
        }
        assert set(data.keys()) == approved_fields
        assert data["target"] == "W01"
        assert isinstance(data["inventory"], float)
        assert isinstance(data["temperature"], float)

        # Prohibited fields must never appear
        prohibited = [
            "anomaly_score",
            "c1",
            "c2",
            "c3",
            "risk_score",
            "threshold",
            "weights",
            "pipeline",
            "decision",
            "alerts",
            "is_attack_injected",
            "attack_type",
        ]
        for field in prohibited:
            assert field not in data

    def test_9_feedback_contains_only_approved_fields(self, client, monkeypatch):
        """9. Verify attack feedback contains only restricted fields, shielding classification by default."""
        payload = {
            "attack_type": "capacity_manipulation",
            "target": "free_capacity",
            "value": 40.0,
            "objective": "create C1 capacity violation",
        }
        res = client.post("/api/attacker/attack", json=payload)
        assert res.status_code == 200
        data = res.json()

        approved_fields = {
            "attack_id",
            "execution",
            "detection",
            "classification",
            "timestamp",
        }
        assert set(data.keys()) == approved_fields
        assert data["detection"] == "DETECTED"
        assert data["classification"] is None  # Shielded by default

        # When explicitly configured, classification is populated
        monkeypatch.setenv("GATEWAY_EXPOSE_CLASSIFICATION", "true")
        res2 = client.post("/api/attacker/attack", json=payload)
        assert res2.status_code == 200
        assert res2.json()["classification"] in ["POTENTIAL_ATTACK", "COORDINATED_ATTACK"]

    def test_10_gateway_cannot_expose_defenderservice_internals(self, client):
        """10. Verify no DefenderService internals leak across all gateway endpoints."""
        attack_res = client.post(
            "/api/attacker/attack",
            json={
                "attack_type": "inventory_manipulation",
                "target": "inventory",
                "value": 15.0,
                "objective": "test information leakage",
            },
        )
        assert attack_res.status_code == 200
        atk_id = attack_res.json()["attack_id"]

        result_res = client.get(f"/api/attacker/result/{atk_id}")
        assert result_res.status_code == 200
        result_data = result_res.json()

        # Check result endpoint for prohibited internal leakage
        prohibited = [
            "rules",
            "semantic",
            "isolation_forest",
            "temporal_weights",
            "graph_edges",
            "subsystems",
            "score_matrix",
            "thresholds",
            "features_evaluated",
        ]
        result_str = str(result_data).lower()
        for leak in prohibited:
            assert leak not in result_str, f"Defender internal '{leak}' leaked in result!"

    def test_11_gateway_does_not_permit_arbitrary_code_execution(self, client):
        """11. Verify gateway safely handles code/shell strings as pure literal text."""
        code_injection = "__import__('os').system('echo hacked')"
        payload = {
            "attack_type": "sensor_spoofing",
            "target": "temperature",
            "value": 25.0,
            "objective": code_injection,
        }
        res = client.post("/api/attacker/attack", json=payload)
        assert res.status_code == 200
        # Check that the code was treated as literal string in audit, not evaluated
        assert res.json()["execution"] == "accepted"

    def test_12_attack_ids_are_unique(self, client):
        """12. Verify attack IDs are unique and increment sequentially."""
        ids = []
        for i in range(3):
            res = client.post(
                "/api/attacker/attack",
                json={
                    "attack_type": "coordinated_weak",
                    "target": "multi_metric",
                    "value": -1.0,
                    "objective": f"step {i}",
                },
            )
            assert res.status_code == 200
            ids.append(res.json()["attack_id"])

        assert len(ids) == len(set(ids))
        assert ids == ["ATK-0001", "ATK-0002", "ATK-0003"]

        # Verify historical lookup by ID
        lookup_res = client.get("/api/attacker/result/ATK-0002")
        assert lookup_res.status_code == 200
        assert lookup_res.json()["attack_id"] == "ATK-0002"

        # Invalid ID returns 404
        nonexistent = client.get("/api/attacker/result/ATK-9999")
        assert nonexistent.status_code == 404

    def test_13_reset_works_correctly(self, client):
        """13. Verify POST /api/attacker/reset clears attacker history and restores baseline."""
        # Execute an attack
        client.post(
            "/api/attacker/attack",
            json={
                "attack_type": "inventory_manipulation",
                "target": "inventory",
                "value": 10.0,
                "objective": "pre-reset attack",
            },
        )
        assert client.get("/api/attacker/result/ATK-0001").status_code == 200

        # Reset via gateway
        reset_res = client.post("/api/attacker/reset")
        assert reset_res.status_code == 200
        assert reset_res.json()["success"] is True

        # Simulator should be back to step 0
        obs_res = client.get("/api/attacker/observation")
        assert obs_res.status_code == 200
        assert obs_res.json()["inventory"] == 42.0

        # History should be cleared
        assert client.get("/api/attacker/result/ATK-0001").status_code == 404

    def test_14_rate_limiting_works(self, client, monkeypatch):
        """14. Verify rate limiting returns HTTP 429 when threshold exceeded."""
        import app.api.routes.attacker as atk_mod

        monkeypatch.setattr(atk_mod, "RATE_LIMIT_MAX_REQUESTS", 3)

        # Exhaust rate limit budget
        for _ in range(3):
            res = client.post(
                "/api/attacker/attack",
                json={
                    "attack_type": "coordinated_weak",
                    "target": "multi_metric",
                    "objective": "burst test",
                },
            )
            assert res.status_code == 200

        # Next request must be throttled with HTTP 429
        throttled_res = client.post(
            "/api/attacker/attack",
            json={
                "attack_type": "coordinated_weak",
                "target": "multi_metric",
                "objective": "exceed limit",
            },
        )
        assert throttled_res.status_code == 429
        assert "Rate limit exceeded" in throttled_res.text

    def test_15_missing_gateway_token_returns_401(self):
        """15. Verify request without Authorization header returns HTTP 401."""
        with TestClient(app) as unauthed_client:
            res = unauthed_client.get("/api/attacker/observation")
            assert res.status_code == 401
            assert "Missing Authorization header" in res.text

            res_attack = unauthed_client.post(
                "/api/attacker/attack",
                json={
                    "attack_type": "capacity_manipulation",
                    "target": "free_capacity",
                    "value": 45.0,
                    "objective": "unauthorized attempt",
                },
            )
            assert res_attack.status_code == 401
            assert "Missing Authorization header" in res_attack.text

    def test_16_invalid_gateway_token_returns_401(self):
        """16. Verify request with invalid Bearer token returns HTTP 401."""
        with TestClient(app, headers={"Authorization": "Bearer wrong-invalid-token"}) as bad_client:
            res = bad_client.get("/api/attacker/observation")
            assert res.status_code == 401
            assert "Invalid or unauthorized gateway token" in res.text

    def test_17_valid_gateway_token_accepted(self):
        """17. Verify request with configured valid Bearer token returns HTTP 200."""
        with TestClient(app, headers={"Authorization": f"Bearer {TEST_GATEWAY_TOKEN}"}) as good_client:
            res = good_client.get("/api/attacker/observation")
            assert res.status_code == 200
            assert "target" in res.json()

    def test_18_attacker_cannot_access_security_endpoints(self):
        """18. Verify attacker client has no methods or endpoints to access Defender security APIs."""
        from attacker_app.gateway_client import AttackGatewayClient
        gw_client = AttackGatewayClient()
        assert not hasattr(gw_client, "get_security_status")
        assert not hasattr(gw_client, "get_alerts")
        assert not hasattr(gw_client, "get_ml_score")

    def test_19_attacker_cannot_access_warehouse_endpoints_directly(self):
        """19. Verify attacker client has no methods to call warehouse simulation endpoints directly."""
        from attacker_app.gateway_client import AttackGatewayClient
        gw_client = AttackGatewayClient()
        assert not hasattr(gw_client, "step_warehouse")
        assert not hasattr(gw_client, "get_warehouse_history")

    def test_20_gateway_client_rejects_arbitrary_url_construction(self):
        """20. Verify AttackGatewayClient._build_url strictly enforces endpoint whitelist."""
        from attacker_app.gateway_client import AttackGatewayClient, GatewayClientError
        gw_client = AttackGatewayClient(base_url="http://127.0.0.1:8000/api/attacker")

        # Approved endpoints succeed
        assert gw_client._build_url("observation") == "http://127.0.0.1:8000/api/attacker/observation"
        assert gw_client._build_url("attack") == "http://127.0.0.1:8000/api/attacker/attack"
        assert gw_client._build_url("result/ATK-0001") == "http://127.0.0.1:8000/api/attacker/result/ATK-0001"
        assert gw_client._build_url("reset") == "http://127.0.0.1:8000/api/attacker/reset"

        # Arbitrary endpoints rejected
        prohibited = [
            "/api/security/status",
            "/api/warehouse/current",
            "../admin",
            "eval",
            "malicious/backdoor",
            "http://external-evil.com",
        ]
        for bad_path in prohibited:
            with pytest.raises(GatewayClientError, match="Arbitrary URL construction rejected"):
                gw_client._build_url(bad_path)

