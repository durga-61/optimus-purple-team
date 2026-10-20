"""Regression test suite for SHA-256 cryptographic audit chain and tamper detection.

Tests:
1. Empty audit chains (trivially valid, anchored to GENESIS_HASH).
2. Clean sequential event generation and hash linkage across simulation steps.
3. Tampering detection: modification of event message, metadata, step, timestamp, severity, or hash.
4. Deletion detection: removal of genesis, intermediate, or subsequent events.
5. Reordering detection: permutation or reversal of chained events.
6. Insertion detection: injection of unauthorized foreign events.
7. Service reset behavior: clean re-anchoring of the audit chain to genesis root.
8. API Endpoint GET /api/security/audit-chain/verify: HTTP 200 verification, failure reporting, auth enforcement.
"""

import copy
import pytest
from fastapi.testclient import TestClient

from app.api.main import app
from app.api.state import app_state
from app.config import settings
from app.defender.audit import (
    GENESIS_HASH,
    AuditChainVerificationResponse,
    compute_event_hash,
    verify_audit_chain,
)
from app.defender.models import SecurityEvent
from app.defender.service import DefenderService
from app.simulator.warehouse import ColdStorageWarehouse


@pytest.fixture
def service():
    """Return a fresh DefenderService instance with initialized audit chain."""
    srv = DefenderService()
    srv.reset()
    return srv


@pytest.fixture
def client():
    """Return a FastAPI TestClient configured for Defender API."""
    with TestClient(app) as test_client:
        yield test_client


# ==============================================================================
# Unit Tests: Core Audit Chain Verification Function
# ==============================================================================

class TestAuditChainCoreVerification:
    """Verifies the core mathematical and cryptographic properties of the audit chain."""

    def test_empty_chain_is_valid(self):
        """An empty audit chain is trivially valid and reports 0 events."""
        res = verify_audit_chain([])
        assert res.valid is True
        assert res.total_events == 0
        assert res.genesis_hash == GENESIS_HASH
        assert res.latest_event_hash is None
        assert res.error is None
        assert res.failed_event_index is None
        assert "empty" in res.details.get("message", "").lower()

    def test_valid_single_event_chain(self):
        """A single event whose prev_hash matches GENESIS_HASH is cryptographically valid."""
        timestamp = "2026-10-20T12:00:00Z"
        step = 1
        event_type = "DATA_RECEIVED"
        severity = "INFO"
        source = "DefenderService"
        message = "Initial observation"
        metadata = {"warehouse": "W01"}

        event_hash = compute_event_hash(
            timestamp=timestamp,
            step=step,
            event_type=event_type,
            severity=severity,
            source=source,
            message=message,
            metadata=metadata,
            prev_hash=GENESIS_HASH,
        )

        event = SecurityEvent(
            timestamp=timestamp,
            step=step,
            event_type=event_type,
            severity=severity,
            source=source,
            message=message,
            metadata=metadata,
            prev_hash=GENESIS_HASH,
            event_hash=event_hash,
        )

        res = verify_audit_chain([event])
        assert res.valid is True
        assert res.total_events == 1
        assert res.genesis_hash == GENESIS_HASH
        assert res.latest_event_hash == event_hash
        assert res.error is None
        assert event.verify_hash() is True

    def test_valid_multi_event_chain(self, service):
        """Multiple events sequentially logged by DefenderService form an unbroken valid chain."""
        wh = ColdStorageWarehouse(seed=42)
        for _ in range(5):
            service.analyze(wh.step())

        assert len(service.events) >= 15  # Each step generates ~6-7 events
        res = service.verify_audit_chain()

        assert res.valid is True
        assert res.total_events == len(service.events)
        assert res.genesis_hash == GENESIS_HASH
        assert res.latest_event_hash == service.events[-1].event_hash
        assert res.error is None
        assert res.failed_event_index is None

        # Verify every individual event link
        events = service.events
        assert events[0].prev_hash == GENESIS_HASH
        for i in range(1, len(events)):
            assert events[i].prev_hash == events[i - 1].event_hash
            assert events[i].verify_hash() is True


# ==============================================================================
# Tampering and Adversarial Manipulation Tests
# ==============================================================================

class TestAuditChainTamperDetection:
    """Verifies detection of adversarial modifications, deletions, and permutations."""

    def test_tampering_event_message_detected(self, service):
        """Modifying the text message of an event causes a HASH_MISMATCH."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.step())
        service.analyze(wh.step())

        # Tamper with the 3rd event
        tamper_idx = 2
        original_msg = service.events[tamper_idx].message
        service.events[tamper_idx].message = "ATTACKER ALTERED MESSAGE CONTENT"

        res = service.verify_audit_chain()
        assert res.valid is False
        assert res.error == "HASH_MISMATCH"
        assert res.failed_event_index == tamper_idx
        assert "altered or tampered" in res.details["reason"].lower()

        # Restore message
        service.events[tamper_idx].message = original_msg
        assert service.verify_audit_chain().valid is True

    def test_tampering_event_metadata_detected(self, service):
        """Modifying nested metadata dictionary values causes a HASH_MISMATCH."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.step())

        tamper_idx = 1
        service.events[tamper_idx].metadata["forged_attribute"] = "malicious_payload"

        res = service.verify_audit_chain()
        assert res.valid is False
        assert res.error == "HASH_MISMATCH"
        assert res.failed_event_index == tamper_idx

    def test_tampering_event_step_or_timestamp_detected(self, service):
        """Modifying the step number or timestamp causes a HASH_MISMATCH."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.step())

        tamper_idx = 0
        service.events[tamper_idx].step = 99999

        res = service.verify_audit_chain()
        assert res.valid is False
        assert res.error == "HASH_MISMATCH"
        assert res.failed_event_index == tamper_idx

    def test_tampering_event_severity_detected(self, service):
        """Modifying severity (e.g. downgrading ALERT to INFO) causes a HASH_MISMATCH."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.step())

        tamper_idx = 0
        service.events[tamper_idx].severity = "CRITICAL"

        res = service.verify_audit_chain()
        assert res.valid is False
        assert res.error == "HASH_MISMATCH"
        assert res.failed_event_index == tamper_idx

    def test_tampering_event_hash_directly_detected(self, service):
        """Corrupting the event_hash digest itself causes a HASH_MISMATCH."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.step())

        tamper_idx = 0
        service.events[tamper_idx].event_hash = "f" * 64

        res = service.verify_audit_chain()
        assert res.valid is False
        assert res.error == "HASH_MISMATCH"
        assert res.failed_event_index == tamper_idx


class TestAuditChainSequenceBreachDetection:
    """Verifies detection of deleted, inserted, or reordered audit events."""

    def test_deletion_of_first_event_detected(self, service):
        """Deleting the genesis event breaks the chain at index 0 with CHAIN_BROKEN."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.step())

        # Remove the first event
        service.events.pop(0)

        res = service.verify_audit_chain()
        assert res.valid is False
        assert res.error == "CHAIN_BROKEN"
        assert res.failed_event_index == 0
        assert res.details["expected_prev_hash"] == GENESIS_HASH

    def test_deletion_of_intermediate_event_detected(self, service):
        """Deleting an event in the middle breaks the chain with CHAIN_BROKEN at the deletion point."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.step())
        service.analyze(wh.step())

        total_before = len(service.events)
        delete_idx = 4
        # Remove event at index 4
        deleted_event = service.events.pop(delete_idx)

        res = service.verify_audit_chain()
        assert res.valid is False
        assert res.error == "CHAIN_BROKEN"
        assert res.failed_event_index == delete_idx
        assert res.total_events == total_before - 1

    def test_reordering_adjacent_events_detected(self, service):
        """Swapping two adjacent events causes a CHAIN_BROKEN error."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.step())

        assert len(service.events) >= 4
        # Swap events at index 1 and 2
        service.events[1], service.events[2] = service.events[2], service.events[1]

        res = service.verify_audit_chain()
        assert res.valid is False
        assert res.error == "CHAIN_BROKEN"
        assert res.failed_event_index == 1

    def test_reversing_chain_detected(self, service):
        """Reversing the entire event sequence causes a CHAIN_BROKEN error."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.step())

        service.events.reverse()
        res = service.verify_audit_chain()
        assert res.valid is False
        assert res.error == "CHAIN_BROKEN"

    def test_insertion_of_foreign_event_detected(self, service):
        """Inserting an unauthorized foreign event into the sequence breaks the chain."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.step())

        foreign_event = SecurityEvent(
            timestamp="2026-10-20T12:05:00Z",
            step=1,
            event_type="UNAUTHORIZED_INJECTION",
            severity="CRITICAL",
            source="Attacker",
            message="Injected event",
            metadata={},
            prev_hash="a" * 64,
            event_hash="b" * 64,
        )

        # Insert into middle
        insert_idx = 2
        service.events.insert(insert_idx, foreign_event)

        res = service.verify_audit_chain()
        assert res.valid is False
        assert res.error == "CHAIN_BROKEN"
        assert res.failed_event_index == insert_idx


# ==============================================================================
# Service Lifecycle and Reset Tests
# ==============================================================================

class TestAuditChainServiceIntegration:
    """Verifies service reset and continuous hash-chain propagation."""

    def test_service_reset_reanchors_chain_to_genesis(self, service):
        """Resetting DefenderService clears events and re-anchors to GENESIS_HASH."""
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.step())
        assert len(service.events) > 0
        assert service.latest_event_hash != GENESIS_HASH

        service.reset()
        assert len(service.events) == 0
        assert service.latest_event_hash == GENESIS_HASH

        # Verification on reset state is valid
        res_reset = service.verify_audit_chain()
        assert res_reset.valid is True
        assert res_reset.total_events == 0

        # Subsequent observation correctly starts from GENESIS_HASH again
        service.analyze(wh.step())
        assert len(service.events) > 0
        assert service.events[0].prev_hash == GENESIS_HASH
        assert service.verify_audit_chain().valid is True

    def test_continuous_linkage_across_multiple_steps(self, service):
        """Every single event over 10 consecutive steps is strictly linked."""
        wh = ColdStorageWarehouse(seed=42)
        for _ in range(10):
            service.analyze(wh.step())

        res = service.verify_audit_chain()
        assert res.valid is True
        assert res.total_events == len(service.events)

        # Verify hash continuity
        for i in range(len(service.events) - 1):
            assert service.events[i + 1].prev_hash == service.events[i].event_hash


# ==============================================================================
# API Endpoint Integration Tests: GET /api/security/audit-chain/verify
# ==============================================================================

class TestAuditChainApiEndpoint:
    """Verifies the HTTP endpoint exposing audit chain verification."""

    def test_api_verify_empty_or_fresh_chain(self, client):
        """Fresh or clean application state returns HTTP 200 with valid=True."""
        response = client.get("/api/security/audit-chain/verify")
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["genesis_hash"] == GENESIS_HASH
        assert "disclaimer" in data
        assert "in-memory" in data["disclaimer"].lower()

    def test_api_verify_after_simulation_steps(self, client):
        """After running warehouse steps, the endpoint confirms an unbroken chain."""
        # Reset first
        client.post("/api/warehouse/reset")
        # Step twice
        client.post("/api/warehouse/step")
        client.post("/api/warehouse/step")

        response = client.get("/api/security/audit-chain/verify")
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["total_events"] > 0
        assert data["latest_event_hash"] is not None
        assert data["error"] is None

    def test_api_verify_detects_tampering_in_live_state(self, client):
        """Tampering with an event in live state causes the API endpoint to report valid=False."""
        client.post("/api/warehouse/reset")
        client.post("/api/warehouse/step")

        # Access live app_state events directly to simulate in-memory memory corruption
        assert len(app_state.defender.events) > 0
        original_msg = app_state.defender.events[0].message
        app_state.defender.events[0].message = "CORRUPTED IN-MEMORY DATA"

        response = client.get("/api/security/audit-chain/verify")
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert data["error"] == "HASH_MISMATCH"
        assert data["failed_event_index"] == 0

        # Restore
        app_state.defender.events[0].message = original_msg
        assert client.get("/api/security/audit-chain/verify").json()["valid"] is True

    def test_api_verify_requires_operator_access_non_loopback(self, client, monkeypatch):
        """Non-loopback callers without credentials are rejected with HTTP 401."""
        settings.LOCAL_DEMO_MODE = False
        settings.OPERATOR_TOKEN = "secret-operator-token-xyz"

        # Call with spoofed remote IP and no credentials
        response = client.get(
            "/api/security/audit-chain/verify",
            headers={"X-Forwarded-For": "198.51.100.25"},
        )
        assert response.status_code == 401

        # Call with valid Bearer token succeeds
        valid_res = client.get(
            "/api/security/audit-chain/verify",
            headers={
                "X-Forwarded-For": "198.51.100.25",
                "Authorization": "Bearer secret-operator-token-xyz",
            },
        )
        assert valid_res.status_code == 200
        assert valid_res.json()["valid"] is True

        # Restore defaults
        settings.LOCAL_DEMO_MODE = True
        settings.OPERATOR_TOKEN = None
