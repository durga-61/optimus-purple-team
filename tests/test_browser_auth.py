"""Tests for browser-facing API contract, same-origin session cookies, and authentication."""

import pytest
from fastapi.testclient import TestClient

from app.api.main import app as defender_app
from app.config import settings as defender_settings
from attacker_app.config import config as attacker_config
from attacker_app.main import app as attacker_app
from attacker_app.state import attacker_state


TEST_OP_TOKEN = "op-browser-auth-secret-123"
TEST_ATT_KEY = "att-browser-auth-key-456"


@pytest.fixture
def def_client():
    with TestClient(defender_app) as client:
        yield client


@pytest.fixture
def att_client():
    with TestClient(attacker_app) as client:
        yield client


class TestDefenderBrowserAuth:
    """Verifies same-origin session cookie authentication for Defender Operator endpoints."""

    def test_session_status_in_loopback_demo_mode(self, def_client, monkeypatch):
        """Loopback client in demo mode reports authenticated via demo_loopback."""
        monkeypatch.setattr(defender_settings, "LOCAL_DEMO_MODE", True)
        res = def_client.get("/api/auth/session")
        assert res.status_code == 200
        data = res.json()
        assert data["authenticated"] is True
        assert data["mode"] == "demo_loopback"
        assert data["local_demo_mode"] is True

    def test_session_status_unauthenticated_in_strict_mode(self, def_client, monkeypatch):
        """When LOCAL_DEMO_MODE is False, unauthenticated client reports unauthenticated."""
        monkeypatch.setattr(defender_settings, "LOCAL_DEMO_MODE", False)
        monkeypatch.setattr(defender_settings, "OPERATOR_TOKEN", TEST_OP_TOKEN)
        res = def_client.get("/api/auth/session")
        assert res.status_code == 200
        data = res.json()
        assert data["authenticated"] is False
        assert data["mode"] == "unauthenticated"

    def test_login_with_invalid_token_rejected(self, def_client, monkeypatch):
        """Invalid token rejected with 401."""
        monkeypatch.setattr(defender_settings, "OPERATOR_TOKEN", TEST_OP_TOKEN)
        res = def_client.post("/api/auth/login", json={"token": "wrong-token"})
        assert res.status_code == 401
        assert "Invalid operator token" in res.text

    def test_login_with_valid_token_sets_httponly_cookie(self, def_client, monkeypatch):
        """Valid login sets optimus_operator_session cookie and authorizes session."""
        monkeypatch.setattr(defender_settings, "LOCAL_DEMO_MODE", False)
        monkeypatch.setattr(defender_settings, "OPERATOR_TOKEN", TEST_OP_TOKEN)

        login_res = def_client.post("/api/auth/login", json={"token": TEST_OP_TOKEN})
        assert login_res.status_code == 200
        assert "optimus_operator_session" in login_res.cookies
        cookie_val = login_res.cookies["optimus_operator_session"]
        assert cookie_val == TEST_OP_TOKEN

        # Set cookie directly on TestClient instance
        def_client.cookies.set("optimus_operator_session", cookie_val)

        # Subsequent state changes succeed using the session cookie in strict mode
        step_res = def_client.post("/api/warehouse/step")
        assert step_res.status_code == 200

        # Session status reports authenticated via cookie_session
        session_res = def_client.get("/api/auth/session")
        assert session_res.status_code == 200
        assert session_res.json()["authenticated"] is True
        assert session_res.json()["mode"] == "cookie_session"

    def test_logout_terminates_session(self, def_client, monkeypatch):
        """Logout clears the operator session cookie."""
        monkeypatch.setattr(defender_settings, "LOCAL_DEMO_MODE", False)
        monkeypatch.setattr(defender_settings, "OPERATOR_TOKEN", TEST_OP_TOKEN)

        # Login first
        login_res = def_client.post("/api/auth/login", json={"token": TEST_OP_TOKEN})
        assert login_res.status_code == 200

        # Logout
        logout_res = def_client.post("/api/auth/logout")
        assert logout_res.status_code == 200
        assert logout_res.json()["authenticated"] is False


class TestAttackerBrowserAuth:
    """Verifies same-origin session cookie authentication for Attacker Console endpoints."""

    def test_attacker_session_status_in_loopback_demo_mode(self, att_client, monkeypatch):
        """Loopback client in demo mode reports authenticated via demo_loopback."""
        monkeypatch.setattr(attacker_config, "LOCAL_DEMO_MODE", True)
        res = att_client.get("/api/attacker/auth/session")
        assert res.status_code == 200
        data = res.json()
        assert data["authenticated"] is True
        assert data["mode"] == "demo_loopback"

    def test_attacker_session_unauthenticated_in_strict_mode(self, att_client, monkeypatch):
        """When LOCAL_DEMO_MODE is False, unauthenticated client reports unauthenticated."""
        monkeypatch.setattr(attacker_config, "LOCAL_DEMO_MODE", False)
        monkeypatch.setattr(attacker_config, "ATTACKER_API_KEY", TEST_ATT_KEY)
        res = att_client.get("/api/attacker/auth/session")
        assert res.status_code == 200
        data = res.json()
        assert data["authenticated"] is False
        assert data["mode"] == "unauthenticated"

    def test_attacker_login_with_invalid_key_rejected(self, att_client, monkeypatch):
        """Invalid key rejected with 401."""
        monkeypatch.setattr(attacker_config, "ATTACKER_API_KEY", TEST_ATT_KEY)
        res = att_client.post("/api/attacker/auth/login", json={"token": "wrong-key"})
        assert res.status_code == 401
        assert "Invalid attacker API key" in res.text

    def test_attacker_login_with_valid_key_sets_cookie(self, att_client, monkeypatch):
        """Valid key sets optimus_attacker_session cookie and authorizes access in strict mode."""
        monkeypatch.setattr(attacker_config, "LOCAL_DEMO_MODE", False)
        monkeypatch.setattr(attacker_config, "ATTACKER_API_KEY", TEST_ATT_KEY)
        monkeypatch.setattr(attacker_state, "fetch_observation", lambda: None)

        login_res = att_client.post("/api/attacker/auth/login", json={"token": TEST_ATT_KEY})
        assert login_res.status_code == 200
        assert "optimus_attacker_session" in login_res.cookies
        cookie_val = login_res.cookies["optimus_attacker_session"]

        # Set cookie directly on TestClient instance
        att_client.cookies.set("optimus_attacker_session", cookie_val)

        # Calling status endpoint succeeds using the session cookie in strict mode
        status_res = att_client.get("/api/attacker/status")
        assert status_res.status_code == 200

        # Session status reports authenticated via cookie_session
        session_res = att_client.get("/api/attacker/auth/session")
        assert session_res.status_code == 200
        assert session_res.json()["authenticated"] is True
        assert session_res.json()["mode"] == "cookie_session"

    def test_attacker_logout_clears_session(self, att_client):
        """Logout clears the attacker session cookie."""
        logout_res = att_client.post("/api/attacker/auth/logout")
        assert logout_res.status_code == 200
        assert logout_res.json()["authenticated"] is False
