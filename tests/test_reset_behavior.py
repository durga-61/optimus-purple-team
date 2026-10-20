"""Tests for granular reset behavior, scope distinction, and accurate error reporting."""

import pytest
from fastapi.testclient import TestClient

from app.api.main import app as defender_app
from app.api.state import app_state
from app.config import settings
from attacker_app.gateway_client import AttackGatewayClient, GatewayClientError
from attacker_app.main import app as attacker_app
from attacker_app.schemas import AttackProposal, ProposalValidationResult
from attacker_app.state import attacker_state


TEST_GATEWAY_TOKEN = "reset-test-token-778899"


@pytest.fixture
def attacker_client():
    with TestClient(attacker_app) as client:
        yield client


@pytest.fixture
def defender_client():
    import os
    os.environ["ATTACK_GATEWAY_TOKEN"] = TEST_GATEWAY_TOKEN
    settings.ATTACK_GATEWAY_TOKEN = TEST_GATEWAY_TOKEN
    with TestClient(defender_app, headers={"Authorization": f"Bearer {TEST_GATEWAY_TOKEN}"}) as client:
        yield client


class TestGranularResetBehavior:
    """Verifies distinct reset scopes and non-misleading error reporting."""

    def test_clear_history_only_preserves_pending_proposal(self, attacker_client):
        """Clearing history clears history and experiments but preserves pending proposal."""
        # Stage pending proposal
        attacker_state.pending_proposal = AttackProposal(
            attack_type="capacity_manipulation",
            target="free_capacity",
            value=40.0,
            objective="test pending",
        )
        attacker_state.pending_proposal_id = "PROP-1001"
        attacker_state.pending_validation = ProposalValidationResult(valid=True, errors=[])

        # Execute endpoint to clear history
        res = attacker_client.post("/api/attacker/history/clear")
        assert res.status_code == 200
        data = res.json()
        assert data["history_cleared"] is True
        assert data["experiments_cleared"] is True

        # Pending proposal must remain intact
        assert attacker_state.pending_proposal is not None
        assert attacker_state.pending_proposal_id == "PROP-1001"

    def test_reset_attacker_only_preserves_defender_state(self, attacker_client):
        """Attacker-only reset clears pending proposals and local state without resetting defender."""
        # Advance defender simulation
        app_state.warehouse.step()
        app_state.warehouse.step()
        defender_step = app_state.warehouse.step_count
        assert defender_step >= 2

        # Reset attacker with scope=attacker_only
        res = attacker_client.post("/api/attacker/reset", json={"scope": "attacker_only"})
        assert res.status_code == 200
        data = res.json()
        assert data["attacker_reset"] is True
        assert data["scope"] == "attacker_only"

        # Defender state was NOT reset
        assert app_state.warehouse.step_count == defender_step

    def test_gateway_offline_reports_failure_not_misleading_success(self, attacker_client, monkeypatch):
        """When gateway is offline or returns an error, reset must NEVER report success=True."""
        def mock_offline_reset():
            raise GatewayClientError("Connection refused: Attack Gateway offline at http://127.0.0.1:8000")

        monkeypatch.setattr(attacker_state.gateway_client, "reset_gateway", mock_offline_reset)

        # Reset with scope=all when gateway is offline
        res = attacker_client.post("/api/attacker/reset", json={"scope": "all"})
        assert res.status_code == 502
        assert "Attack Gateway offline" in res.text

        # Direct call to state.reset returns accurate failure information
        res_dict = attacker_state.reset(scope="all")
        assert res_dict["success"] is False
        assert res_dict["gateway_success"] is False
        assert "Attack Gateway offline" in res_dict["gateway_error"]
        assert "Defender Gateway reset failed" in res_dict["message"]

    def test_gateway_offline_for_defender_only_reports_failure(self, attacker_client, monkeypatch):
        """defender_only reset fails when gateway is unreachable."""
        def mock_offline_reset():
            raise GatewayClientError("HTTP 503 Service Unavailable")

        monkeypatch.setattr(attacker_state.gateway_client, "reset_gateway", mock_offline_reset)

        res = attacker_client.post("/api/attacker/reset", json={"scope": "defender_only"})
        assert res.status_code == 502
        assert "503" in res.text

    def test_successful_complete_reset_flow(self, attacker_client, defender_client, monkeypatch):
        """Complete reset resets both Defender and Attacker when connected."""
        # Advance simulation
        defender_client.post("/api/warehouse/step")
        assert app_state.warehouse.step_count > 0

        # Wire attacker gateway client to in-process defender
        def mock_live_reset():
            r = defender_client.post("/api/attacker/reset")
            return r.json()

        def mock_live_obs():
            r = defender_client.get("/api/attacker/observation")
            from attacker_app.schemas import AttackerObservation
            return AttackerObservation(**r.json())

        monkeypatch.setattr(attacker_state.gateway_client, "reset_gateway", mock_live_reset)
        monkeypatch.setattr(attacker_state.gateway_client, "get_observation", mock_live_obs)

        res = attacker_client.post("/api/attacker/reset", json={"scope": "all"})
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["gateway_success"] is True
        assert data["attacker_reset"] is True

        # Defender warehouse reset back to step 0
        assert app_state.warehouse.step_count == 0
