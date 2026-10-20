"""End-to-End Adversarial Evaluation Workflow Test Suite.

Verifies the complete, controlled 11-step evaluation pipeline across
the 3 separate perspectives:
1. Operations Monitor: Raw simulated data & data changes
2. AI Attacker Console: Restricted observation, proposal generation, human approval, experiment records
3. Defender Portal: Detection rules, ML anomaly scores, semantic verification, alerts, and decisions

Hard isolation between Part 1 and Part 2 is strictly preserved.
"""

import ast
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

# Part 1 imports (only in test fixture to verify Part 1 state)
from app.api.main import app as part1_app
from app.api.state import app_state as part1_state

# Part 2 imports
from attacker_app.main import app as part2_app
from attacker_app.schemas import AttackerObservation, AttackProposal
from attacker_app.state import attacker_state as part2_state


TEST_GATEWAY_TOKEN = "test-research-token-7a8b9c"


@pytest.fixture
def part1_client():
    """TestClient for Part 1 Organization Defender System."""
    import os
    from app.config import settings
    os.environ["ATTACK_GATEWAY_TOKEN"] = TEST_GATEWAY_TOKEN
    settings.ATTACK_GATEWAY_TOKEN = TEST_GATEWAY_TOKEN
    with TestClient(part1_app, headers={"Authorization": f"Bearer {TEST_GATEWAY_TOKEN}"}) as client:
        yield client


@pytest.fixture
def part2_client():
    """TestClient for Part 2 AI Attacker Application."""
    with TestClient(part2_app) as client:
        yield client


@pytest.fixture(autouse=True)
def reset_both_applications(part1_client, monkeypatch):
    """Reset both Part 1 and Part 2 state before every test."""
    part1_state.reset()
    part2_state.gateway_client.token = TEST_GATEWAY_TOKEN

    # Wire gateway_client to in-process part1_client for self-contained test execution
    def mock_get_observation():
        res = part1_client.get("/api/attacker/observation")
        from attacker_app.schemas import AttackerObservation
        return AttackerObservation(**res.json())

    def mock_execute_attack(proposal):
        payload = proposal.model_dump(exclude_none=True)
        res = part1_client.post("/api/attacker/attack", json=payload)
        from attacker_app.schemas import AttackFeedback
        return AttackFeedback(**res.json())

    def mock_reset_gateway():
        res = part1_client.post("/api/attacker/reset")
        return res.json()

    monkeypatch.setattr(part2_state.gateway_client, "get_observation", mock_get_observation)
    monkeypatch.setattr(part2_state.gateway_client, "execute_attack", mock_execute_attack)
    monkeypatch.setattr(part2_state.gateway_client, "reset_gateway", mock_reset_gateway)

    part2_state.reset()
    import app.api.routes.attacker as atk_mod
    atk_mod._attack_counter = 0
    atk_mod._attack_history.clear()
    atk_mod._rate_limit_records.clear()


class TestAdversarialEvaluationWorkflowE2E:
    """Complete 11-point end-to-end evaluation workflow test suite."""

    def test_1_simulator_generates_data(self, part1_client):
        """1. Simulator generates clean baseline organizational telemetry."""
        # Initial baseline observation
        obs_res = part1_client.get("/api/warehouse/current")
        assert obs_res.status_code == 200
        data = obs_res.json()
        assert data["warehouse"] == "W01"
        assert data["step"] == 0
        assert data["inventory"] == 42.0
        assert data["free_capacity"] == 8.0
        assert data["capacity"] == 50.0

        # Advance simulator
        step_res = part1_client.post("/api/warehouse/step")
        assert step_res.status_code == 200
        step_data = step_res.json()
        assert step_data["observation"]["step"] == 1

        # Check history endpoint
        hist_res = part1_client.get("/api/warehouse/history?limit=10")
        assert hist_res.status_code == 200
        hist_data = hist_res.json()
        assert len(hist_data["observations"]) >= 1
        assert hist_data["observations"][-1]["step"] == 1

    def test_2_attacker_obtains_restricted_observation(self, part1_client, part2_client):
        """2. Attacker obtains strictly restricted operational telemetry via gateway."""
        # Advance simulation in Part 1
        part1_client.post("/api/warehouse/step")

        # Query observation from Part 2 gateway endpoint
        gw_obs_res = part1_client.get("/api/attacker/observation")
        assert gw_obs_res.status_code == 200
        gw_data = gw_obs_res.json()

        # Attacker state pulls observation
        part2_obs_res = part2_client.get("/api/attacker/observation")
        assert part2_obs_res.status_code == 200
        part2_data = part2_obs_res.json()

        # Approved metrics only
        approved_keys = {"target", "inventory", "free_capacity", "temperature", "humidity", "occupancy"}
        assert set(part2_data.keys()) == approved_keys
        assert part2_data["target"] == "W01"

        # Forbidden internal metrics must not be present
        forbidden_keys = ["anomaly_score", "risk_score", "c1", "c2", "c3", "threshold", "weights"]
        for key in forbidden_keys:
            assert key not in part2_data

    def test_3_attacker_creates_proposal(self, part2_client):
        """3. Attacker creates valid candidate attack proposal using active planner."""
        propose_res = part2_client.post(
            "/api/attacker/propose",
            json={"planner": "deterministic", "objective_hint": "Evaluate capacity desync vulnerability"},
        )
        assert propose_res.status_code == 200
        data = propose_res.json()

        assert data["proposal_id"].startswith("PROP-")
        assert data["planner_label"] == "DETERMINISTIC FALLBACK"
        assert data["validation"]["valid"] is True
        assert data["proposal"]["attack_type"] == "capacity_manipulation"
        assert data["proposal"]["target"] == "free_capacity"
        assert data["proposal"]["value"] is not None
        assert "strategy_rationale" in data
        assert "observed_telemetry" in data

    def test_4_human_approval_is_required(self, part1_client, part2_client):
        """4. Candidate proposal requires explicit human approval and cannot execute automatically."""
        # Baseline simulation step
        initial_step = part1_state.warehouse.step_count

        # Attacker generates proposal
        part2_client.post(
            "/api/attacker/propose",
            json={"planner": "deterministic", "objective_hint": "Pending approval test"},
        )

        # Confirm proposal is held in pending state in Part 2
        status_res = part2_client.get("/api/attacker/status")
        status_data = status_res.json()
        assert status_data["has_pending_proposal"] is True
        assert status_data["pending_proposal"] is not None

        # Confirm simulation step in Part 1 has NOT changed (attack was not executed automatically)
        assert part1_state.warehouse.step_count == initial_step
        assert len(part2_state.history) == 0
        assert len(part2_state.experiments) == 0

    def test_5_gateway_validates_proposal(self, part1_client):
        """5. Part 1 Attack Gateway strictly enforces validation on incoming requests."""
        # 1. Invalid attack type
        res_invalid_type = part1_client.post(
            "/api/attacker/attack",
            json={"attack_type": "arbitrary_backdoor", "target": "server", "objective": "hack"},
        )
        assert res_invalid_type.status_code == 422

        # 2. Mismatched target
        res_mismatched = part1_client.post(
            "/api/attacker/attack",
            json={"attack_type": "capacity_manipulation", "target": "temperature", "value": 45.0, "objective": "bad"},
        )
        assert res_mismatched.status_code == 422

        # 3. Extra forbidden fields
        res_extra = part1_client.post(
            "/api/attacker/attack",
            json={
                "attack_type": "capacity_manipulation",
                "target": "free_capacity",
                "value": 45.0,
                "objective": "bad",
                "malicious_extra": True,
            },
        )
        assert res_extra.status_code == 422

    def test_6_controlled_attack_executes(self, part1_client):
        """6. Gateway executes attack via controlled simulator scenario."""
        valid_payload = {
            "attack_type": "capacity_manipulation",
            "target": "free_capacity",
            "value": 45.0,
            "objective": "Execute controlled capacity desynchronization",
        }
        res = part1_client.post("/api/attacker/attack", json=valid_payload)
        assert res.status_code == 200

        # Verify underlying simulator observation was mutated
        current_obs = part1_state.warehouse.get_current_observation()
        assert current_obs.is_attack_injected is True
        assert current_obs.attack_type == "capacity_manipulation"
        assert current_obs.free_capacity == 45.0

    def test_7_defender_evaluates_result(self, part1_client):
        """7. Defender evaluates mutated data through semantic and decision engines."""
        # Execute attack via gateway
        part1_client.post(
            "/api/attacker/attack",
            json={
                "attack_type": "capacity_manipulation",
                "target": "free_capacity",
                "value": 45.0,
                "objective": "Trigger C1 violation",
            },
        )

        latest_analysis = part1_state.defender.get_latest_analysis()
        assert latest_analysis is not None
        assert latest_analysis.decision.classification in ["POTENTIAL_ATTACK", "COORDINATED_ATTACK"]
        assert "C1" in latest_analysis.semantic.violated_constraints
        assert latest_analysis.semantic.status == "VIOLATION"
        assert latest_analysis.decision.risk_score >= 0.3

        # Check alerts
        alerts = part1_state.defender.get_alerts(active_only=True)
        assert len(alerts) > 0
        assert any("C1" in a.reason or "Capacity" in a.reason for a in alerts)

    def test_8_restricted_feedback_returns_to_attacker(self, part1_client):
        """8. Restricted feedback returned to attacker shields all Defender internals."""
        res = part1_client.post(
            "/api/attacker/attack",
            json={
                "attack_type": "sensor_spoofing",
                "target": "temperature",
                "value": 28.0,
                "objective": "Spoof temperature sensor",
            },
        )
        assert res.status_code == 200
        data = res.json()

        approved_feedback_keys = {"attack_id", "execution", "detection", "classification", "timestamp"}
        assert set(data.keys()) == approved_feedback_keys
        assert data["execution"] == "accepted"
        assert data["detection"] == "DETECTED"

        # Leakage check
        raw_text = str(data).lower()
        forbidden_internal_terms = ["isolation_forest", "weights", "semantic", "threshold", "c1", "c2", "c3"]
        for term in forbidden_internal_terms:
            assert term not in raw_text

    def test_9_defender_page_reflects_resulting_state(self, part1_client):
        """9. Defender page endpoints reflect updated security decision and alerts."""
        part1_client.post(
            "/api/attacker/attack",
            json={
                "attack_type": "capacity_manipulation",
                "target": "free_capacity",
                "value": 45.0,
                "objective": "E2E Defender status update",
            },
        )

        # 1. Security Status
        status_res = part1_client.get("/api/security/status")
        assert status_res.status_code == 200
        status_data = status_res.json()
        assert status_data["status"] in ["POTENTIAL_ATTACK", "COORDINATED_ATTACK"]
        assert status_data["risk_score"] > 0
        assert status_data["active_alerts"] > 0

        # 2. Security Alerts
        alerts_res = part1_client.get("/api/security/alerts")
        assert alerts_res.status_code == 200
        assert len(alerts_res.json()) > 0

        # 3. Security Events stream
        events_res = part1_client.get("/api/security/events")
        assert events_res.status_code == 200
        assert len(events_res.json()) > 0

    def test_10_operations_page_reflects_underlying_data(self, part1_client):
        """10. Operations page endpoints reflect manipulated operational telemetry."""
        # Execute attack via gateway
        part1_client.post(
            "/api/attacker/attack",
            json={
                "attack_type": "capacity_manipulation",
                "target": "free_capacity",
                "value": 45.0,
                "objective": "E2E Operations reflection",
            },
        )

        # Operations current observation
        curr_res = part1_client.get("/api/warehouse/current")
        assert curr_res.status_code == 200
        curr_data = curr_res.json()
        assert curr_data["free_capacity"] == 45.0

        # Operations history contains the manipulated observation
        hist_res = part1_client.get("/api/warehouse/history?limit=10")
        assert hist_res.status_code == 200
        hist_data = hist_res.json()
        latest_record = hist_data["observations"][-1]
        assert latest_record["free_capacity"] == 45.0

        # Zero security fields in operations data
        assert "risk_score" not in curr_data
        assert "classification" not in curr_data
        assert "alerts" not in curr_data

    def test_11_no_direct_part2_to_defenderservice_access(self):
        """11. Verify complete AST isolation: Part 2 contains zero imports of Part 1."""
        attacker_app_dir = Path(__file__).resolve().parent.parent / "attacker_app"
        py_files = list(attacker_app_dir.rglob("*.py"))
        assert len(py_files) >= 5

        for py_path in py_files:
            tree = ast.parse(py_path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert not alias.name.startswith(("app.", "app")), (
                            f"Illegal import '{alias.name}' in {py_path.name}"
                        )
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    assert not mod.startswith(("app.", "app")), (
                        f"Illegal import-from '{mod}' in {py_path.name}"
                    )

    def test_12_experiment_record_creation_and_history(self, part1_client, part2_client, monkeypatch):
        """12. Full human-approved flow generates immutable ExperimentRecord with latency tracking."""
        # Stage proposal
        propose_res = part2_client.post(
            "/api/attacker/propose",
            json={"planner": "deterministic", "objective_hint": "Experiment record verification"},
        )
        assert propose_res.status_code == 200

        # Mock gateway client execute_attack using Part 1 client
        def direct_client_execute(proposal):
            payload = proposal.model_dump(exclude_none=True)
            res = part1_client.post("/api/attacker/attack", json=payload)
            from attacker_app.schemas import AttackFeedback
            return AttackFeedback(**res.json())

        monkeypatch.setattr(part2_state.gateway_client, "execute_attack", direct_client_execute)

        # Human executes proposal
        exec_res = part2_client.post("/api/attacker/execute")
        assert exec_res.status_code == 200
        feedback = exec_res.json()

        assert feedback["attack_id"].startswith("ATK-")
        assert feedback["detection"] == "DETECTED"

        # Check Part 2 Experiment Records endpoint
        exp_res = part2_client.get("/api/attacker/experiments")
        assert exp_res.status_code == 200
        experiments = exp_res.json()
        assert len(experiments) == 1

        record = experiments[0]
        assert record["experiment_id"] == "EXP-0001"
        assert record["attack_id"].startswith("ATK-")
        assert record["attack_type"] == "capacity_manipulation"
        assert record["target"] == "free_capacity"
        assert record["execution_status"] == "accepted"
        assert record["detection_status"] == "DETECTED"
        assert record["classification"] in ["POTENTIAL_ATTACK", "COORDINATED_ATTACK", None]
        assert record["detection_delay_ms"] is not None
        assert record["detection_delay_ms"] >= 0.0

        # Verify zero internal defender metrics leaked into experiment record
        record_str = str(record).lower()
        for forbidden in ["weights", "isolation_forest", "c1", "c2", "threshold"]:
            assert forbidden not in record_str
