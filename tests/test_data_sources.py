"""Comprehensive test suite for the pluggable data sources layer.

Validates HohenheimDataSource, metadata, schema parsing, 9-sensor representation,
missing data handling, deterministic playback, seek, reset, and factory switching.
"""

import os
from pathlib import Path
import pytest

from app.data_sources.base import BaseDataSource
from app.data_sources.hohenheim import HohenheimDataSource, DATASET_METADATA, SENSOR_IDS
from app.data_sources.repository import SimulatorDataSourceAdapter, create_data_source
from app.simulator.models import WarehouseObservation


class TestHohenheimDataSource:
    """Test suite for the real-recorded University of Hohenheim dataset adapter."""

    @pytest.fixture(scope="class")
    @classmethod
    def data_source(cls):
        ds = HohenheimDataSource()
        yield ds
        ds._conn.close()

    def test_metadata_and_provenance(self, data_source):
        """Verify authoritative dataset metadata, citation, and license."""
        meta = data_source.get_metadata()
        assert meta["doi"] == "10.5281/zenodo.15130001"
        assert meta["license"] == "Creative Commons Attribution 4.0 International (CC-BY-4.0)"
        assert meta["is_real_dataset"] is True
        assert meta["num_sensors"] == 9
        assert meta["sampling_rate_seconds"] == 5.0
        assert meta["has_inventory_ledger"] is False
        assert meta["has_shipment_ledger"] is False
        assert meta["total_records"] == 156835

    def test_all_nine_sensors_present(self, data_source):
        """Verify all 9 DHT22 sensors are exposed and identified."""
        sensors = data_source.get_available_sensors()
        assert len(sensors) == 9
        assert sensors == SENSOR_IDS
        assert "SENSOR01" in sensors
        assert "SENSOR09" in sensors

    def test_initial_observation_structure(self, data_source):
        """Verify initial observation structure, units, and lack of fabricated ledger fields."""
        obs = data_source.get_current_observation()
        assert isinstance(obs, WarehouseObservation)
        assert obs.step == 0
        assert obs.source == "hohenheim"
        assert obs.is_recorded_playback is True
        assert obs.timestamp == "2024-09-02T09:35:25Z"

        # Ledger fields must strictly be None
        assert obs.capacity is None
        assert obs.inventory is None
        assert obs.free_capacity is None
        assert obs.inbound is None
        assert obs.outbound is None
        assert obs.occupancy is None

        # Environmental fields must be valid floats
        assert isinstance(obs.temperature, float)
        assert isinstance(obs.humidity, float)
        assert 0.0 <= obs.humidity <= 100.0

        # Multi-sensor dictionary
        assert obs.sensors is not None
        assert len(obs.sensors) == 9
        for s_id in SENSOR_IDS:
            assert s_id in obs.sensors
            assert "temperature" in obs.sensors[s_id]
            assert "humidity" in obs.sensors[s_id]

    def test_sequential_step_advancement(self, data_source):
        """Verify step() advances the playback cursor deterministically chronologically."""
        data_source.reset()
        obs0 = data_source.get_current_observation()
        assert obs0.step == 0

        obs1 = data_source.step()
        assert obs1.step == 1
        assert obs1.timestamp == "2024-09-02T09:35:30Z"

        obs2 = data_source.step()
        assert obs2.step == 2
        assert obs2.timestamp == "2024-09-02T09:35:35Z"

    def test_seek_playback_and_boundary_checks(self, data_source):
        """Verify seeking to arbitrary valid step index and rejection of out-of-bounds indices."""
        target_step = 720
        obs = data_source.seek(target_step)
        assert obs.step == target_step
        assert data_source.get_current_observation().step == target_step

        # Negative step out of bounds
        with pytest.raises(ValueError):
            data_source.seek(-1)

        # Exceeding total records
        with pytest.raises(ValueError):
            data_source.seek(9999999)

    def test_reset_behavior(self, data_source):
        """Verify reset restores cursor to step 0 and clears history."""
        data_source.seek(150)
        assert data_source.get_current_observation().step == 150

        reset_obs = data_source.reset()
        assert reset_obs.step == 0
        assert data_source.get_current_observation().step == 0
        assert len(data_source.get_history()) == 1

    def test_data_quality_and_missing_value_handling(self, data_source):
        """Verify accurate reporting of active sensors vs dropouts (NaNs) without silent zero imputation."""
        # Step 5000 has partial NaNs on mobile sensors
        obs = data_source.seek(5000)
        q = obs.data_quality
        assert q is not None
        assert q["total_sensors"] == 9
        assert q["has_missing_data"] is True
        assert "SENSOR05" in q["missing_sensors"]
        assert "SENSOR01" in q["active_sensors"]
        assert obs.sensors["SENSOR05"]["temperature"] is None

        # Inter-sensor delta should be calculated over active non-null sensors
        assert isinstance(q["inter_sensor_temp_delta"], float)
        assert q["inter_sensor_temp_delta"] >= 0.0

    def test_physical_event_mapping(self, data_source):
        """Verify physical door actions from experiment_actions.csv are matched to timestamps."""
        # Find a step during door opening (e.g. 2024-09-02 10:45:00)
        # Step offset: 09:35:25 to 10:45:00 is (69 min * 60 + 35 sec) / 5 = 835 steps
        obs = data_source.seek(835)
        assert obs.active_action == "Door opened"

    def test_factory_switching(self):
        """Verify factory creates both Hohenheim and Simulator data sources correctly."""
        real_ds = create_data_source("hohenheim")
        assert isinstance(real_ds, HohenheimDataSource)
        assert real_ds.get_metadata()["is_real_dataset"] is True

        sim_ds = create_data_source("simulator")
        assert isinstance(sim_ds, SimulatorDataSourceAdapter)
        assert sim_ds.get_metadata()["is_real_dataset"] is False
        sim_obs = sim_ds.get_current_observation()
        assert sim_obs.inventory is not None
        assert sim_obs.capacity is not None
