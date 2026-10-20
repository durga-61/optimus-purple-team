"""Tests for security policies, authentication, authorization, and network exposure protection."""

import pytest
from fastapi.testclient import TestClient

from app.api.main import app as defender_app
from app.config import settings as defender_settings
from attacker_app.config import config as attacker_config
from attacker_app.main import app as attacker_app
from attacker_app.schemas import AttackProposal, ProposalValidationResult
from attacker_app.state import attacker_state


TEST_OPERATOR_TOKEN = "test-operator-secret-key-12345"
TEST_GATEWAY_TOKEN = "test-gateway-secret-token-67890"
TEST_ATTACKER_KEY = "test-attacker-api-key-abcde"


@pytest.fixture
def defender_client():
    with TestClient(defender_app) as client:
        yield client


@pytest.fixture
def attacker_client():
    with TestClient(attacker_app) as client:
        yield client


class TestDefenderSecurityProtection:
    """Tests protecting Defender state-changing endpoints from unauthorized access."""

    def test_strict_mode_rejects_unauthenticated_state_changes(self, defender_client, monkeypatch):
        """When LOCAL_DEMO_MODE is disabled, state-changing endpoints MUST reject unauthenticated calls."""
        monkeypatch.setattr(defender_settings, "LOCAL_DEMO_MODE", False)
        monkeypatch.setattr(defender_settings, "OPERATOR_TOKEN", TEST_OPERATOR_TOKEN)

        endpoints = [
            ("POST", "/api/warehouse/step"),
            ("POST", "/api/warehouse/reset"),
            ("POST", "/api/security/reset"),
            ("POST", "/api/scenarios/capacity_manipulation"),
        ]
        for method, path in endpoints:
            res = defender_client.post(path)
            assert res.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {res.status_code}"
            assert "Unauthorized" in res.text or "detail" in res.json()

    def test_invalid_token_is_rejected(self, defender_client, monkeypatch):
        """Invalid Bearer token or X-Operator-Token MUST return HTTP 401."""
        monkeypatch.setattr(defender_settings, "LOCAL_DEMO_MODE", False)
        monkeypatch.setattr(defender_settings, "OPERATOR_TOKEN", TEST_OPERATOR_TOKEN)

        headers = {"Authorization": "Bearer invalid-token-value"}
        res = defender_client.post("/api/warehouse/step", headers=headers)
        assert res.status_code == 401

        custom_header = {"X-Operator-Token": "invalid-token-value"}
        res2 = defender_client.post("/api/warehouse/step", headers=custom_header)
        assert res2.status_code == 401

    def test_valid_token_allows_state_changes(self, defender_client, monkeypatch):
        """Valid Bearer token or X-Operator-Token allows authorized state changes."""
        monkeypatch.setattr(defender_settings, "LOCAL_DEMO_MODE", False)
        monkeypatch.setattr(defender_settings, "OPERATOR_TOKEN", TEST_OPERATOR_TOKEN)

        # Bearer header
        headers = {"Authorization": f"Bearer {TEST_OPERATOR_TOKEN}"}
        res = defender_client.post("/api/warehouse/step", headers=headers)
        assert res.status_code == 200

        # X-Operator-Token header
        res2 = defender_client.post("/api/warehouse/step", headers={"X-Operator-Token": TEST_OPERATOR_TOKEN})
        assert res2.status_code == 200

    def test_non_loopback_rejected_even_in_local_demo_mode(self, defender_client, monkeypatch):
        """Demo mode must NOT silently expose unauthenticated state changes over non-loopback network."""
        monkeypatch.setattr(defender_settings, "LOCAL_DEMO_MODE", True)
        monkeypatch.setattr(defender_settings, "OPERATOR_TOKEN", TEST_OPERATOR_TOKEN)

        # External IP simulated via forwarded headers
        headers = {"X-Forwarded-For": "192.168.1.150"}
        res = defender_client.post("/api/warehouse/step", headers=headers)
        assert res.status_code == 401
        assert "restricted to loopback interface" in res.text

    def test_loopback_local_demo_permitted_when_configured(self, defender_client, monkeypatch):
        """Local loopback access is permitted when opt-in LOCAL_DEMO_MODE is True."""
        monkeypatch.setattr(defender_settings, "LOCAL_DEMO_MODE", True)
        res = defender_client.post("/api/warehouse/step")
        assert res.status_code == 200


class TestAttackerSecurityProtection:
    """Tests protecting Attacker application and human-in-the-loop controls."""

    def test_strict_mode_rejects_unauthenticated_attacker_requests(self, attacker_client, monkeypatch):
        """When LOCAL_DEMO_MODE is disabled, Attacker API requires authentication."""
        monkeypatch.setattr(attacker_config, "LOCAL_DEMO_MODE", False)
        monkeypatch.setattr(attacker_config, "ATTACKER_API_KEY", TEST_ATTACKER_KEY)

        endpoints = [
            ("GET", "/api/attacker/status"),
            ("GET", "/api/attacker/observation"),
            ("GET", "/api/attacker/history"),
            ("GET", "/api/attacker/experiments"),
            ("POST", "/api/attacker/propose"),
            ("POST", "/api/attacker/execute"),
            ("POST", "/api/attacker/discard"),
            ("POST", "/api/attacker/reset"),
        ]
        for method, path in endpoints:
            if method == "GET":
                res = attacker_client.get(path)
            else:
                res = attacker_client.post(path)
            assert res.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {res.status_code}"

    def test_valid_attacker_api_key_accepted(self, attacker_client, monkeypatch):
        """Valid Bearer token or X-API-Key allows attacker operations."""
        monkeypatch.setattr(attacker_config, "LOCAL_DEMO_MODE", False)
        monkeypatch.setattr(attacker_config, "ATTACKER_API_KEY", TEST_ATTACKER_KEY)

        # Mock observation so status check doesn't fail on gateway
        monkeypatch.setattr(attacker_state, "fetch_observation", lambda: None)

        headers = {"Authorization": f"Bearer {TEST_ATTACKER_KEY}"}
        res = attacker_client.get("/api/attacker/status", headers=headers)
        assert res.status_code == 200

        headers_api_key = {"X-API-Key": TEST_ATTACKER_KEY}
        res2 = attacker_client.get("/api/attacker/status", headers=headers_api_key)
        assert res2.status_code == 200

    def test_human_approval_bypass_prevention(self, attacker_client):
        """Direct call to /api/attacker/execute with approved=False or no pending proposal is rejected."""
        # 1. No pending proposal
        attacker_state.pending_proposal = None
        res_no_prop = attacker_client.post("/api/attacker/execute")
        assert res_no_prop.status_code == 400
        assert "No pending attack proposal" in res_no_prop.text

        # 2. Stage a pending proposal
        prop = AttackProposal(
            attack_type="capacity_manipulation",
            target="free_capacity",
            value=45.0,
            objective="test objective",
        )
        attacker_state.pending_proposal = prop
        attacker_state.pending_proposal_id = "PROP-0999"
        attacker_state.pending_validation = ProposalValidationResult(valid=True, errors=[])

        # 3. Call execute with approved=False -> MUST be rejected
        res_disapproved = attacker_client.post(
            "/api/attacker/execute",
            json={"proposal_id": "PROP-0999", "approved": False},
        )
        assert res_disapproved.status_code == 400
        assert "human approval" in res_disapproved.text

        # 4. Call execute with wrong proposal_id -> MUST be rejected
        res_mismatch = attacker_client.post(
            "/api/attacker/execute",
            json={"proposal_id": "PROP-WRONG-0001", "approved": True},
        )
        assert res_mismatch.status_code == 400
        assert "Proposal ID mismatch" in res_mismatch.text


class TestGatewayAuthenticationAndCORS:
    """Tests verifying Attack Gateway authentication and trusted CORS origins."""

    def test_gateway_endpoints_require_configured_token(self, defender_client, monkeypatch):
        """Gateway endpoints must fail clearly if token is missing or unauthorized."""
        monkeypatch.setenv("ATTACK_GATEWAY_TOKEN", TEST_GATEWAY_TOKEN)
        monkeypatch.setattr(defender_settings, "ATTACK_GATEWAY_TOKEN", TEST_GATEWAY_TOKEN)

        # No auth header
        res_no_auth = defender_client.get("/api/attacker/observation")
        assert res_no_auth.status_code == 401

        # Wrong token
        res_bad_auth = defender_client.get(
            "/api/attacker/observation",
            headers={"Authorization": "Bearer wrong-secret-token"},
        )
        assert res_bad_auth.status_code == 401

        # Valid token
        res_valid = defender_client.get(
            "/api/attacker/observation",
            headers={"Authorization": f"Bearer {TEST_GATEWAY_TOKEN}"},
        )
        assert res_valid.status_code == 200

    def test_cors_policy_rejects_untrusted_origins(self, attacker_client):
        """Attacker app CORS policy must not allow arbitrary untrusted origins with credentials."""
        res = attacker_client.options(
            "/api/attacker/status",
            headers={
                "Origin": "https://malicious-external-site.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        # Should NOT return allow-origin for arbitrary external sites
        allow_origin = res.headers.get("access-control-allow-origin")
        assert allow_origin != "https://malicious-external-site.com"
        assert allow_origin != "*"
