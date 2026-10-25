"""Data Source Repository and Factory.

Provides centralized management and switching between real recorded datasets
(Hohenheim 9-sensor time series) and the cold-storage warehouse simulator.
"""

import logging
from typing import Optional
from app.config import settings
from app.data_sources.base import BaseDataSource
from app.data_sources.hohenheim import HohenheimDataSource
from app.simulator.warehouse import ColdStorageWarehouse

logger = logging.getLogger("data_sources.repository")


class SimulatorDataSourceAdapter(BaseDataSource):
    """Adapter wrapping the existing ColdStorageWarehouse simulator into the BaseDataSource interface."""

    def __init__(self, seed: Optional[int] = 42):
        self.warehouse = ColdStorageWarehouse(seed=seed)

    def get_metadata(self):
        return {
            "title": "Cold-Storage Warehouse Synthetic Simulator",
            "is_real_dataset": False,
            "warehouse_id": self.warehouse.warehouse_id,
            "has_inventory_ledger": True,
            "has_shipment_ledger": True,
        }

    def get_available_sensors(self):
        return ["ambient_temp", "ambient_humidity", "occupancy_sensor"]

    def get_current_observation(self):
        return self.warehouse.get_current_observation()

    def step(self, *args, **kwargs):
        return self.warehouse.step(*args, **kwargs)

    def seek(self, step: int):
        # Simulator cannot seek arbitrarily; step up to target or reset
        self.warehouse.reset()
        obs = self.warehouse.get_current_observation()
        for _ in range(step):
            obs = self.warehouse.step()
        return obs

    def reset(self, seed: Optional[int] = None):
        self.warehouse.reset(seed=seed)
        return self.warehouse.get_current_observation()

    def get_history(self, limit: int = 50):
        return self.warehouse.get_history(limit=limit)

    def get_window(self, start_step: int, window_size: int = 20):
        history = self.warehouse.get_history(limit=max(50, window_size))
        return history[-window_size:] if history else [self.warehouse.get_current_observation()]

    @property
    def warehouse_id(self):
        return self.warehouse.warehouse_id

    @property
    def step_count(self):
        return self.warehouse.step_count

    def current_observation(self):
        return self.warehouse.get_current_observation()

    def inject_observation(self, obs):
        return self.warehouse.inject_observation(obs)

    def __getattr__(self, name):
        return getattr(self.warehouse, name)

    def get_playback_status(self):
        obs = self.warehouse.get_current_observation()
        return {
            "source": "simulator",
            "is_recorded_playback": False,
            "current_step": obs.step,
            "total_records": -1,
            "progress_percent": None,
            "timestamp": obs.timestamp,
            "active_action": None,
        }


def create_data_source(mode: Optional[str] = None) -> BaseDataSource:
    """Factory creating the configured data source instance."""
    mode = (mode or settings.DATA_SOURCE_MODE).lower().strip()
    if mode == "simulator":
        logger.info("Instantiating SimulatorDataSourceAdapter.")
        return SimulatorDataSourceAdapter(seed=settings.DEFAULT_RANDOM_SEED)
    else:
        logger.info("Instantiating real-recorded HohenheimDataSource.")
        return HohenheimDataSource()
