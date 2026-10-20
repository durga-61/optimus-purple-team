"""Test suite for Part 2 AI Attacker Application.

Proves:
1. Part 2 starts independently.
2. Part 2 contains no imports from Part 1.
3. Valid proposals are accepted locally.
4. Invalid proposals are rejected locally.
5. Raw LLM output cannot directly execute.
6. Deterministic fallback works.
7. Attacker only calls the gateway.
8. Attacker cannot call DefenderService.
9. Attacker cannot access simulator objects.
10. Restricted observation is preserved.
11. Restricted feedback is preserved.
"""

import ast
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from attacker_app.config import config
from attacker_app.gateway_client import AttackGatewayClient, GatewayClientError
from attacker_app.main import app
from attacker_app.planner import DeterministicPlanner, LLMPlanner
from attacker_app.schemas import (
    AttackFeedback,
    AttackProposal,
    AttackerObservation,
    ProposalValidationResult,
)
from attacker_app.state import attacker_state
from attacker_app.validator import validate_proposal


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def reset_attacker_state():
    """Reset attacker state between test runs."""
    attacker_state.current_observation = AttackerObservation(
        target="W01",
        inventory=42.0,
        free_capacity=58.0,
        temperature=4.1,
        humidity=65.2,
        occupancy=42.0,
    )
    attacker_state.pending_proposal = None
    attacker_state.pending_proposal_id = None
    attacker_state.pending_planner_label = None
    attacker_state.pending_validation = None
    attacker_state.history.clear()
    attacker_state._proposal_counter = 0


class TestPart2AttackerApplication:
    """Comprehensive test verification for Part 2 isolated architecture."""

    def test_1_part_2_starts_independently(self, client):
        """1. Verify Part 2 starts and serves responses independently."""
        # Test UI serves HTML
        res_ui = client.get("/")
        assert res_ui.status_code == 200
        assert "text/html" in res_ui.headers["content-type"]
        assert "Adversarial Evaluation" in res_ui.text

        # Test Status API
        res_status = client.get("/api/attacker/status")
        assert res_status.status_code == 200
        data = res_status.json()
        assert data["status"] == "online"
        assert "has_pending_proposal" in data

    def test_2_part_2_contains_no_imports_from_part_1(self):
        """2. Verify Part 2 code contains ZERO imports from Part 1 ('app.*')."""
        attacker_app_dir = Path(__file__).resolve().parent.parent / "attacker_app"
        assert attacker_app_dir.exists(), "attacker_app directory missing"

        python_files = list(attacker_app_dir.rglob("*.py"))
        assert len(python_files) >= 5, "Expected at least 5 python files in attacker_app"

        forbidden_prefixes = ("app.", "app")

        for py_path in python_files:
            content = py_path.read_text(encoding="utf-8")
            tree = ast.parse(content, filename=str(py_path))

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        assert not alias.name.startswith(forbidden_prefixes), (
                            f"Illegal import '{alias.name}' detected in {py_path.name}"
                        )
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    assert not mod.startswith(forbidden_prefixes), (
                        f"Illegal import-from '{mod}' detected in {py_path.name}"
                    )

    def test_3_valid_proposals_are_accepted_locally(self):
        """3. Verify local proposal validator accepts all 6 whitelisted attack scenarios."""
        valid_cases = [
            ("capacity_manipulation", "free_capacity", 45.0, "desync capacity"),
            ("inventory_manipulation", "inventory", 20.0, "violate conservation"),
            ("sensor_spoofing", "temperature", 25.0, "spoof warm temperature"),
            ("sensor_spoofing", "humidity", 85.0, "spoof high humidity"),
            ("replay_attack", "inventory", 42.0, "replay stale observation"),
            ("coordinated_weak", "multi_metric", -1.0, "sub-threshold drift"),
            ("multi_source", "facility", 1.0, "multi-source ledger discrepancy"),
        ]

        for atk_type, target, val, obj in valid_cases:
            candidate = {
                "attack_type": atk_type,
                "target": target,
                "value": val,
                "objective": obj,
            }
            is_valid, validation_res, parsed = validate_proposal(candidate)
            assert is_valid is True, f"Failed for valid case: {candidate}, errors: {validation_res.errors}"
            assert len(validation_res.errors) == 0
            assert parsed is not None
            assert parsed.attack_type == atk_type

    def test_4_invalid_proposals_are_rejected_locally(self):
        """4. Verify invalid proposals are rejected with descriptive validation errors."""
        invalid_cases = [
            # Unknown attack type
            ({"attack_type": "ddos_flood", "target": "network", "objective": "flood"}, "Schema violation"),
            # Mismatched target
            ({"attack_type": "capacity_manipulation", "target": "temperature", "value": 45.0, "objective": "test"}, "Invalid target"),
            # Negative capacity
            ({"attack_type": "capacity_manipulation", "target": "free_capacity", "value": -10.0, "objective": "test"}, "negative"),
            # Out of bounds sensor temperature
            ({"attack_type": "sensor_spoofing", "target": "temperature", "value": 150.0, "objective": "test"}, "physical envelope"),
            # Extra unexpected fields
            ({"attack_type": "inventory_manipulation", "target": "inventory", "value": 10.0, "objective": "test", "extra_field": 123}, "Schema violation"),
        ]

        for candidate, expected_err_substring in invalid_cases:
            is_valid, validation_res, parsed = validate_proposal(candidate)
            assert is_valid is False, f"Expected invalid for: {candidate}"
            assert parsed is None
            assert any(expected_err_substring.lower() in err.lower() for err in validation_res.errors), (
                f"Expected '{expected_err_substring}' in errors: {validation_res.errors}"
            )

    def test_5_raw_llm_output_cannot_directly_execute(self):
        """5. Verify raw LLM output or injection strings cannot bypass validation or execute code."""
        malicious_strings = [
            "__import__('os').system('dir')",
            "exec('import sys; sys.exit()')",
            "<script>alert('xss')</script>",
            "DROP TABLE users;",
            "SELECT * FROM defender_rules;",
        ]

        for raw_text in malicious_strings:
            # 1. Test passing raw text as candidate dictionary
            is_valid, validation_res, parsed = validate_proposal({"raw": raw_text})
            assert is_valid is False
            assert parsed is None

            # 2. Test passing malicious string as objective field
            # It should remain pure inert text and must still follow schema rules
            is_valid_prop, _, parsed_prop = validate_proposal({
                "attack_type": "sensor_spoofing",
                "target": "temperature",
                "value": 15.0,
                "objective": raw_text,
            })
            assert is_valid_prop is True
            # The malicious payload must be preserved strictly as an inert literal string
            assert parsed_prop.objective == raw_text
            # It was never executed
            assert parsed_prop.value == 15.0

    def test_6_deterministic_fallback_works(self):
        """6. Verify deterministic fallback generates valid proposals without LLM access."""
        planner = DeterministicPlanner()
        assert planner.label == "DETERMINISTIC FALLBACK"

        sample_obs = AttackerObservation(
            target="W01",
            inventory=40.0,
            free_capacity=60.0,
            temperature=4.0,
            humidity=65.0,
            occupancy=40.0,
        )

        proposal, label, rationale, val_res = planner.propose(sample_obs, history=[])
        assert label == "DETERMINISTIC FALLBACK"
        assert isinstance(proposal, AttackProposal)

        # Validate proposal locally
        is_valid, validation_res, _ = validate_proposal(proposal)
        assert is_valid is True
        assert proposal.attack_type == "capacity_manipulation"
        assert proposal.target == "free_capacity"

        # LLMPlanner fallback without key
        llm_planner = LLMPlanner(provider=None)
        assert "DETERMINISTIC FALLBACK" in llm_planner.label
        fb_proposal, fb_label, fb_rat, fb_val = llm_planner.propose(sample_obs, history=[])
        assert "DETERMINISTIC FALLBACK" in fb_label
        assert isinstance(fb_proposal, AttackProposal)

    def test_7_attacker_only_calls_the_gateway(self):
        """7. Verify gateway client restricts URLs strictly to configured gateway endpoints."""
        gw_client = AttackGatewayClient(base_url="http://127.0.0.1:8000/api/attacker")

        assert gw_client._build_url("observation") == "http://127.0.0.1:8000/api/attacker/observation"
        assert gw_client._build_url("/attack") == "http://127.0.0.1:8000/api/attacker/attack"
        assert gw_client._build_url("result/ATK-0001") == "http://127.0.0.1:8000/api/attacker/result/ATK-0001"
        assert gw_client._build_url("reset") == "http://127.0.0.1:8000/api/attacker/reset"

        # Client has no methods to invoke arbitrary endpoints outside gateway base
        assert not hasattr(gw_client, "execute_shell")
        assert not hasattr(gw_client, "call_arbitrary_url")

    def test_8_attacker_cannot_call_defenderservice(self):
        """8. Verify DefenderService is not imported or accessible anywhere in Part 2."""
        import attacker_app
        import attacker_app.main
        import attacker_app.state
        import attacker_app.planner
        import attacker_app.gateway_client

        modules = [attacker_app, attacker_app.main, attacker_app.state, attacker_app.planner, attacker_app.gateway_client]
        for m in modules:
            assert not hasattr(m, "DefenderService")
            assert not hasattr(m, "defender")

    def test_9_attacker_cannot_access_simulator_objects(self):
        """9. Verify ColdStorageWarehouse simulator is not accessible in Part 2 state."""
        assert not hasattr(attacker_state, "warehouse")
        assert not hasattr(attacker_state, "simulator")
        assert not hasattr(attacker_state, "ColdStorageWarehouse")

        # Current observation must be pure Pydantic schema, not a simulator object
        obs = attacker_state.current_observation
        assert isinstance(obs, AttackerObservation)
        assert not hasattr(obs, "step")
        assert not hasattr(obs, "inject_attack")

    def test_10_restricted_observation_is_preserved(self):
        """10. Verify AttackerObservation exposes only approved operational metrics."""
        approved_fields = {
            "target",
            "inventory",
            "free_capacity",
            "temperature",
            "humidity",
            "occupancy",
        }
        actual_fields = set(AttackerObservation.model_fields.keys())
        assert actual_fields == approved_fields

        # Prohibited fields must not exist
        prohibited = [
            "anomaly_score",
            "risk_score",
            "c1",
            "c2",
            "c3",
            "weights",
            "threshold",
            "decision",
            "is_attack_injected",
            "attack_type",
        ]
        for p in prohibited:
            assert p not in actual_fields

    def test_11_restricted_feedback_is_preserved(self):
        """11. Verify AttackFeedback exposes only approved high-level outcome fields."""
        approved_fields = {
            "attack_id",
            "execution",
            "detection",
            "classification",
            "timestamp",
        }
        actual_fields = set(AttackFeedback.model_fields.keys())
        assert actual_fields == approved_fields

        # Prohibited fields must not exist
        prohibited = [
            "rules_triggered",
            "weights",
            "score_matrix",
            "temporal_score",
            "structural_score",
            "subsystem_edges",
            "isolation_forest_raw",
        ]
        for p in prohibited:
            assert p not in actual_fields

    def test_12_propose_and_human_in_the_loop_execution_flow(self, client, monkeypatch):
        """12. Verify full proposal generation, local validation, and human approval flow."""
        # 1. Propose an attack
        propose_res = client.post(
            "/api/attacker/propose",
            json={"planner": "deterministic", "objective_hint": "test evasive capacity attack"},
        )
        assert propose_res.status_code == 200
        prop_data = propose_res.json()

        assert prop_data["proposal"]["attack_type"] == "capacity_manipulation"
        assert prop_data["validation"]["valid"] is True
        assert prop_data["planner_label"] == "DETERMINISTIC FALLBACK"

        # Proposal is pending, NOT yet executed
        assert attacker_state.pending_proposal is not None
        assert len(attacker_state.history) == 0

        # Mock gateway client's execute_attack to test human approval transmission
        def mock_execute(proposal):
            return AttackFeedback(
                attack_id="ATK-0001",
                execution="accepted",
                detection="DETECTED",
                classification="POTENTIAL_ATTACK",
                timestamp="2026-09-14T20:50:00Z",
            )

        monkeypatch.setattr(attacker_state.gateway_client, "execute_attack", mock_execute)

        # 2. Human clicks Execute
        exec_res = client.post("/api/attacker/execute")
        assert exec_res.status_code == 200
        feedback = exec_res.json()
        assert feedback["attack_id"] == "ATK-0001"
        assert feedback["detection"] == "DETECTED"
        assert feedback["classification"] == "POTENTIAL_ATTACK"

        # Pending proposal should now be cleared
        assert attacker_state.pending_proposal is None
        # History recorded
        assert len(attacker_state.history) == 1
        assert attacker_state.history[0].executed is True
        assert attacker_state.history[0].result.attack_id == "ATK-0001"

        # 3. Discard workflow when proposal is generated but rejected by human
        client.post("/api/attacker/propose", json={"planner": "deterministic"})
        assert attacker_state.pending_proposal is not None
        discard_res = client.post("/api/attacker/discard")
        assert discard_res.status_code == 200
        assert attacker_state.pending_proposal is None
