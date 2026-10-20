"""Comprehensive tests for ColdStorageWarehouse simulator and data models."""

import pytest
from pydantic import ValidationError

from app.config import settings
from app.simulator.models import WarehouseObservation
from app.simulator.warehouse import ColdStorageWarehouse
from app.simulator.scenarios import (
    inject_capacity_manipulation,
    inject_inventory_manipulation,
    inject_sensor_spoofing,
    inject_replay_attack,
    inject_coordinated_manipulation,
    inject_multi_source_manipulation,
)


class TestWarehouseInitialization:
    """Tests verifying warehouse initialization and baseline state."""

    def test_warehouse_initializes_with_defaults(self):
        warehouse = ColdStorageWarehouse(seed=42)
        obs = warehouse.get_current_observation()

        assert obs.warehouse == "W01"
        assert obs.capacity == 50.0
        assert obs.inventory == 42.0
        assert obs.free_capacity == 8.0
        assert obs.occupancy == 84.0
        assert obs.temperature == 4.2
        assert obs.humidity == 71.0
        assert obs.step == 0
        assert obs.is_attack_injected is False
        assert obs.attack_type is None

    def test_capacity_and_free_capacity_invariant(self):
        warehouse = ColdStorageWarehouse(total_capacity=100.0, initial_inventory=60.0, seed=42)
        obs = warehouse.get_current_observation()

        assert obs.capacity == 100.0
        assert obs.inventory == 60.0
        assert obs.free_capacity == 40.0
        assert round(obs.inventory + obs.free_capacity, 2) == obs.capacity
        assert obs.occupancy == 60.0


class TestWarehouseDynamics:
    """Tests verifying simulation state transitions and physical bounds."""

    def test_inbound_and_outbound_affect_inventory(self):
        warehouse = ColdStorageWarehouse(total_capacity=50.0, initial_inventory=40.0, seed=42)

        # Step 1: Inbound 3.0, Outbound 1.0 -> Net +2.0 -> Inventory = 42.0
        obs1 = warehouse.step(inbound=3.0, outbound=1.0)
        assert obs1.inventory == 42.0
        assert obs1.free_capacity == 8.0
        assert obs1.inbound == 3.0
        assert obs1.outbound == 1.0
        assert obs1.step == 1

        # Step 2: Inbound 0.0, Outbound 5.0 -> Net -5.0 -> Inventory = 37.0
        obs2 = warehouse.step(inbound=0.0, outbound=5.0)
        assert obs2.inventory == 37.0
        assert obs2.free_capacity == 13.0
        assert obs2.inbound == 0.0
        assert obs2.outbound == 5.0
        assert obs2.step == 2

    def test_telemetry_remains_within_normal_ranges(self):
        warehouse = ColdStorageWarehouse(seed=42)

        for _ in range(50):
            obs = warehouse.step()
            # Verify cold storage temperature limits (1.0 to 7.0 °C)
            assert settings.TEMP_MIN_BOUND <= obs.temperature <= settings.TEMP_MAX_BOUND
            # Verify relative humidity limits (60% to 85%)
            assert settings.HUMIDITY_MIN_BOUND <= obs.humidity <= settings.HUMIDITY_MAX_BOUND
            # Verify normal occupancy and free capacity consistency
            assert 0.0 <= obs.occupancy <= 100.0
            assert round(obs.inventory + obs.free_capacity, 2) == obs.capacity

    def test_history_tracking_and_limit(self):
        warehouse = ColdStorageWarehouse(history_size=15, seed=42)

        for _ in range(25):
            warehouse.step()

        # Total history buffer should not exceed history_size (15)
        assert len(warehouse.history) == 15
        recent_10 = warehouse.get_history(limit=10)
        assert len(recent_10) == 10
        assert recent_10[-1].step == 25
        assert recent_10[0].step == 16


class TestDeterministicExecution:
    """Tests verifying reproducible deterministic simulation behavior."""

    def test_identical_seeds_produce_identical_trajectories(self):
        wh1 = ColdStorageWarehouse(seed=999)
        wh2 = ColdStorageWarehouse(seed=999)

        for _ in range(20):
            obs1 = wh1.step()
            obs2 = wh2.step()

            assert obs1.step == obs2.step
            assert obs1.inventory == obs2.inventory
            assert obs1.free_capacity == obs2.free_capacity
            assert obs1.temperature == obs2.temperature
            assert obs1.humidity == obs2.humidity
            assert obs1.inbound == obs2.inbound
            assert obs1.outbound == obs2.outbound

    def test_different_seeds_produce_different_trajectories(self):
        wh1 = ColdStorageWarehouse(seed=111)
        wh2 = ColdStorageWarehouse(seed=222)

        differences = 0
        for _ in range(15):
            obs1 = wh1.step()
            obs2 = wh2.step()
            if obs1.temperature != obs2.temperature or obs1.inventory != obs2.inventory:
                differences += 1

        assert differences > 0

    def test_reset_restores_deterministic_baseline(self):
        wh = ColdStorageWarehouse(seed=777)
        for _ in range(10):
            wh.step()

        wh.reset(seed=777)
        obs_reset = wh.get_current_observation()
        assert obs_reset.step == 0
        assert obs_reset.inventory == 42.0
        assert obs_reset.free_capacity == 8.0


class TestInvalidStateRejection:
    """Tests verifying validation rules and rejection of invalid states."""

    def test_rejects_non_positive_capacity(self):
        with pytest.raises(ValueError, match="Total capacity must be greater than zero"):
            ColdStorageWarehouse(total_capacity=0.0)

        with pytest.raises(ValueError, match="Total capacity must be greater than zero"):
            ColdStorageWarehouse(total_capacity=-50.0)

    def test_rejects_inventory_exceeding_capacity(self):
        with pytest.raises(ValueError, match="Initial inventory must be between 0 and total capacity"):
            ColdStorageWarehouse(total_capacity=50.0, initial_inventory=55.0)

    def test_rejects_negative_initial_inventory(self):
        with pytest.raises(ValueError, match="Initial inventory must be between 0 and total capacity"):
            ColdStorageWarehouse(total_capacity=50.0, initial_inventory=-5.0)

    def test_pydantic_model_rejects_negative_values(self):
        with pytest.raises(ValidationError):
            WarehouseObservation(capacity=-10.0)

        with pytest.raises(ValidationError):
            WarehouseObservation(inventory=-5.0)


class TestDeterministicAttackScenarios:
    """Tests verifying deterministic attack injection scenario generators."""

    def test_capacity_manipulation_creates_semantic_discrepancy(self):
        wh = ColdStorageWarehouse(seed=42)
        base = wh.get_current_observation()
        assert base.inventory == 42.0
        assert base.free_capacity == 8.0
        assert base.capacity == 50.0

        attacked = inject_capacity_manipulation(base, reported_free_capacity=40.0)
        assert attacked.is_attack_injected is True
        assert attacked.attack_type == "capacity_manipulation"
        assert attacked.inventory == 42.0
        assert attacked.free_capacity == 40.0
        assert attacked.capacity == 50.0
        # Check C1 inconsistency: 42 + 40 = 82 > 50
        assert attacked.inventory + attacked.free_capacity > attacked.capacity

    def test_inventory_manipulation_attack(self):
        wh = ColdStorageWarehouse(seed=42)
        base = wh.get_current_observation()
        attacked = inject_inventory_manipulation(base, manipulated_inventory=25.0)

        assert attacked.is_attack_injected is True
        assert attacked.attack_type == "inventory_manipulation"
        assert attacked.inventory == 25.0

    def test_sensor_spoofing_attack(self):
        wh = ColdStorageWarehouse(seed=42)
        base = wh.get_current_observation()
        attacked = inject_sensor_spoofing(base, spoofed_temperature=22.5, spoofed_humidity=98.0)

        assert attacked.is_attack_injected is True
        assert attacked.attack_type == "sensor_spoofing"
        assert attacked.temperature == 22.5
        assert attacked.humidity == 98.0

    def test_replay_attack(self):
        wh = ColdStorageWarehouse(seed=42)
        obs_past = wh.get_current_observation()
        obs_future = wh.step(inbound=2.0, outbound=0.0)

        attacked = inject_replay_attack(current_obs=obs_future, previous_obs=obs_past)
        assert attacked.is_attack_injected is True
        assert attacked.attack_type == "replay"
        assert attacked.inventory == obs_past.inventory
        assert attacked.free_capacity == obs_past.free_capacity

    def test_coordinated_manipulation_attack(self):
        wh = ColdStorageWarehouse(seed=42)
        base = wh.get_current_observation()
        attacked = inject_coordinated_manipulation(base, inventory_delta=-2.0, reported_free_capacity_delta=1.0)

        assert attacked.is_attack_injected is True
        assert attacked.attack_type == "coordinated_manipulation"
        assert attacked.inventory == 40.0
        assert attacked.free_capacity == 9.0

    def test_multi_source_manipulation_attack(self):
        wh = ColdStorageWarehouse(seed=42)
        base = wh.get_current_observation()
        attacked = inject_multi_source_manipulation(base)

        assert attacked.is_attack_injected is True
        assert attacked.attack_type == "multi_source_manipulation"
        assert attacked.inventory == 37.0
        assert attacked.temperature == round(base.temperature + 6.0, 2)
