"""Integration tests for DefenderService and end-to-end security analysis pipeline."""

import pytest
from app.defender.service import DefenderService
from app.simulator.models import WarehouseObservation
from app.simulator.scenarios import (
    inject_capacity_manipulation,
    inject_inventory_manipulation,
    inject_sensor_spoofing,
    inject_replay_attack,
    inject_coordinated_manipulation,
    inject_multi_source_manipulation,
)
from app.simulator.warehouse import ColdStorageWarehouse


class TestDefenderServicePipeline:
    """Test suite for complete DefenderService orchestration."""

    @pytest.fixture
    def service(self):
        return DefenderService()

    def test_normal_observation_flow(self, service):
        wh = ColdStorageWarehouse(seed=42)
        normal_obs = wh.get_current_observation()

        result = service.analyze(normal_obs)

        # Verify pipeline stage outputs
        assert result.warehouse == "W01"
        assert result.step == 0
        assert result.ml.status in ("NORMAL", "SUSPICIOUS")
        assert result.semantic.status == "NORMAL"
        assert len(result.semantic.violated_constraints) == 0
        assert result.temporal.status == "STABLE"
        assert result.structural.status == "ISOLATED"
        assert result.decision.classification == "NORMAL"
        assert result.decision.integrity_score >= 90.0
        assert len(result.alerts) == 0

        # Status endpoint matches
        status = service.get_status()
        assert status["status"] == "NORMAL"
        assert status["active_alerts"] == 0

    def test_end_to_end_attack_flow_normal_to_attacked(self, service):
        """Validates Section 12 test requirement: Normal -> Attacked -> Detection."""
        wh = ColdStorageWarehouse(seed=42)

        # 1. Feed normal baseline
        base_obs = wh.get_current_observation()
        normal_result = service.analyze(base_obs)
        assert normal_result.decision.classification == "NORMAL"
        assert len(service.get_alerts(active_only=True)) == 0

        # 2. Advance one normal step
        step1_obs = wh.step(inbound=2.0, outbound=1.0)
        step1_result = service.analyze(step1_obs)
        assert step1_result.decision.classification == "NORMAL"

        # 3. Inject Capacity Manipulation Attack (44.3 + 40 > 50)
        attack_obs = inject_capacity_manipulation(step1_obs, reported_free_capacity=40.0)
        attack_result = service.analyze(attack_obs)

        # 4. Verify detection in pipeline
        assert attack_result.semantic.status == "VIOLATION"
        assert "C1" in attack_result.semantic.violated_constraints
        assert attack_result.decision.classification in ("POTENTIAL_ATTACK", "COORDINATED_ATTACK")
        assert attack_result.decision.integrity_score < 75.0
        assert len(attack_result.alerts) == 1
        assert "40.0" in attack_result.decision.explanation

        # 5. Verify alert persistence
        active_alerts = service.get_alerts(active_only=True)
        assert len(active_alerts) == 1
        assert active_alerts[0].target == "Warehouse W01"

    def test_deterministic_inventory_manipulation_scenario(self, service):
        wh = ColdStorageWarehouse(seed=42)
        base = service.analyze(wh.get_current_observation())

        # Abrupt unrecorded inventory drop: 42t -> 20t
        step1 = wh.step()
        attacked = inject_inventory_manipulation(step1, manipulated_inventory=20.0)
        result = service.analyze(attacked)

        assert result.semantic.status == "VIOLATION"
        assert "C2" in result.semantic.violated_constraints
        assert result.decision.classification == "POTENTIAL_ATTACK"
        assert len(result.alerts) >= 1

    def test_deterministic_sensor_spoofing_scenario(self, service):
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.get_current_observation())

        # Extreme temperature spoofing
        step1 = wh.step()
        attacked = inject_sensor_spoofing(step1, spoofed_temperature=28.0, spoofed_humidity=98.0)
        result = service.analyze(attacked)

        # Should flag C3 warning and ML anomaly
        assert any(c.constraint == "C3" and c.status == "WARNING" for c in result.semantic.constraints)
        assert result.ml.status in ("ANOMALY", "SUSPICIOUS") or result.ml.anomaly_score >= 0.40
        assert result.decision.classification in ("SUSPICIOUS", "LOW", "POTENTIAL_ATTACK")

    def test_deterministic_replay_attack_behavior(self, service):
        """Evaluates replay attack behavior honestly per Section 13."""
        wh = ColdStorageWarehouse(seed=42)
        obs0 = wh.get_current_observation()
        service.analyze(obs0)

        # Advance warehouse 3 steps so inventory moves
        obs1 = wh.step(inbound=2.0, outbound=0.0)
        service.analyze(obs1)
        obs2 = wh.step(inbound=2.0, outbound=0.0)
        service.analyze(obs2)

        # Replay obs0 (inventory was 42.0, now it is 46.0) under current step
        replayed = inject_replay_attack(current_obs=obs2, previous_obs=obs0)
        result = service.analyze(replayed)

        # When an old observation is replayed into an evolving system, C2 flow breaks
        # because the sudden unrecorded jump from 46.0 to 42.0 violates flow conservation!
        assert "C2" in result.semantic.violated_constraints
        assert result.semantic.status == "VIOLATION"
        assert result.decision.classification == "POTENTIAL_ATTACK"

    def test_multi_source_manipulation_activates_multi_source_correlation(self, service):
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.get_current_observation())

        step1 = wh.step()
        multi_attack = inject_multi_source_manipulation(step1)
        result = service.analyze(multi_attack)

        # Both ledger (flow) and sensor (temperature) affected
        assert "inventory_ledger" in result.structural.affected_nodes
        assert "environmental_iot" in result.structural.affected_nodes
        assert result.structural.status == "MULTI_SOURCE"

    def test_event_stream_logging(self, service):
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.get_current_observation())

        events = service.get_events(limit=20)
        event_types = [e.event_type for e in events]
        assert "DATA_RECEIVED" in event_types
        assert "ML_ANALYSIS_COMPLETED" in event_types
        assert "TEMPORAL_ANALYSIS" in event_types
        assert "STRUCTURAL_ANALYSIS" in event_types
        assert "JOINT_DECISION" in event_types

    def test_service_reset(self, service):
        wh = ColdStorageWarehouse(seed=42)
        service.analyze(wh.get_current_observation())
        service.reset()

        assert len(service.observation_history) == 0
        assert len(service.events) == 0
        assert len(service.alerts) == 0
        assert service.last_observation is None
        assert service.latest_analysis is None
