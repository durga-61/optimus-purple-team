"""Tests for SemanticEngine and individual C1, C2, C3 constraint checks."""

import pytest
from app.defender.semantic import SemanticEngine
from app.simulator.models import WarehouseObservation
from app.simulator.scenarios import (
    inject_capacity_manipulation,
    inject_inventory_manipulation,
    inject_sensor_spoofing,
)


class TestSemanticEngine:
    """Test suite for semantic integrity verification."""

    @pytest.fixture
    def engine(self):
        return SemanticEngine(c1_tolerance=0.5, c2_tolerance=0.5)

    def test_c1_capacity_pass(self, engine):
        obs = WarehouseObservation(
            warehouse="W01",
            capacity=50.0,
            inventory=42.0,
            free_capacity=8.0,
        )
        c1 = engine.check_c1_capacity(obs)
        assert c1.status == "PASSED"
        assert c1.difference == 0.0
        assert "consistent" in c1.message.lower()

    def test_c1_capacity_violation_master_example(self, engine):
        # Master Prompt Section 4 and Phase 3 example:
        # Inventory = 44.3, Free capacity = 40, Total = 50 -> 44.3 + 40 = 84.3 > 50
        obs = WarehouseObservation(
            warehouse="W01",
            capacity=50.0,
            inventory=44.3,
            free_capacity=40.0,
        )
        c1 = engine.check_c1_capacity(obs)
        assert c1.status == "VIOLATED"
        assert c1.difference == 34.3
        assert "44.3" in c1.message
        assert "40.0" in c1.message
        assert ">" in c1.message

    def test_c2_inventory_flow_pass(self, engine):
        prev_obs = WarehouseObservation(
            warehouse="W01",
            capacity=50.0,
            inventory=40.0,
            free_capacity=10.0,
        )
        # Inbound 2.0, Outbound 1.0 -> expected current inventory = 41.0
        curr_obs = WarehouseObservation(
            warehouse="W01",
            capacity=50.0,
            inventory=41.0,
            free_capacity=9.0,
            inbound=2.0,
            outbound=1.0,
        )
        c2 = engine.check_c2_inventory_flow(curr_obs, prev_obs)
        assert c2.status == "PASSED"
        assert c2.difference == 0.0

    def test_c2_inventory_flow_violation(self, engine):
        prev_obs = WarehouseObservation(
            warehouse="W01",
            capacity=50.0,
            inventory=40.0,
            free_capacity=10.0,
        )
        # Expected inventory = 40.0 + 1.0 - 0.0 = 41.0, but current reports 25.0!
        curr_obs = WarehouseObservation(
            warehouse="W01",
            capacity=50.0,
            inventory=25.0,
            free_capacity=25.0,
            inbound=1.0,
            outbound=0.0,
        )
        c2 = engine.check_c2_inventory_flow(curr_obs, prev_obs)
        assert c2.status == "VIOLATED"
        assert c2.difference == 16.0
        assert "C2 Flow violation" in c2.message

    def test_c3_historical_operating_envelope_pass(self, engine):
        obs = WarehouseObservation(
            warehouse="W01",
            temperature=4.2,
            humidity=71.0,
        )
        c3 = engine.check_c3_historical(obs)
        assert c3.status == "PASSED"
        assert c3.difference == 0.0

    def test_c3_historical_deviation(self, engine):
        # Temperature 18.5 °C violates cold-storage envelope (1.0 - 7.0 °C)
        obs = WarehouseObservation(
            warehouse="W01",
            temperature=18.5,
            humidity=71.0,
        )
        c3 = engine.check_c3_historical(obs)
        assert c3.status == "WARNING"
        assert "outside safe operating range" in c3.message

    def test_full_semantic_analyze_on_attacked_observation(self, engine):
        base_obs = WarehouseObservation(
            warehouse="W01",
            capacity=50.0,
            inventory=42.0,
            free_capacity=8.0,
            temperature=4.2,
            humidity=71.0,
        )
        attacked_obs = inject_capacity_manipulation(base_obs, reported_free_capacity=40.0)

        result = engine.analyze(current_obs=attacked_obs, previous_obs=base_obs)
        assert result.status == "VIOLATION"
        assert "C1" in result.violated_constraints
        assert result.semantic_score >= 0.50
        assert "C1 Capacity violation" in result.explanation
