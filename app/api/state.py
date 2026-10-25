"""Central thread-safe application state manager.

Coordinates the active data source (University of Hohenheim 9-sensor time series
or cold-storage warehouse simulator) and the DefenderService multi-layer pipeline.
"""

import logging
import threading
from typing import Optional, Tuple
from app.config import settings
from app.data_sources.base import BaseDataSource
from app.data_sources.repository import create_data_source
from app.defender.models import SecurityAnalysisResult
from app.defender.service import DefenderService
from app.simulator.models import WarehouseObservation

logger = logging.getLogger("api.state")


class AppState:
    """Manages runtime instances of Data Source and DefenderService with thread safety."""

    def __init__(self, mode: Optional[str] = None, seed: Optional[int] = 42):
        self._lock = threading.RLock()
        self.data_source: BaseDataSource = create_data_source(mode=mode)
        self.defender: DefenderService = DefenderService()

        # Seed baseline state into DefenderService
        self.defender.analyze(self.data_source.get_current_observation())
        logger.info(
            f"Initialized shared AppState with data source '{self.data_source.get_metadata().get('title')}'."
        )

    @property
    def warehouse(self) -> BaseDataSource:
        """Backward-compatible alias providing access to the active observation source."""
        return self.data_source

    def step(self) -> Tuple[WarehouseObservation, SecurityAnalysisResult]:
        """Atomically advance playback/simulation by one step and run DefenderService analysis."""
        with self._lock:
            obs = self.data_source.step()
            analysis = self.defender.analyze(obs)
            return obs, analysis

    def seek(self, step: int) -> Tuple[WarehouseObservation, SecurityAnalysisResult]:
        """Atomically seek dataset playback to a specific step index and evaluate."""
        with self._lock:
            obs = self.data_source.seek(step)
            analysis = self.defender.analyze(obs)
            return obs, analysis

    def reset(self, seed: Optional[int] = 42) -> None:
        """Atomically reset data source playback and defender state to baseline."""
        with self._lock:
            self.data_source.reset(seed=seed)
            self.defender.reset()
            self.defender.analyze(self.data_source.get_current_observation())
            logger.info("Reset shared AppState and re-seeded baseline.")

    def set_data_source_mode(self, mode: str) -> None:
        """Switch data source between 'hohenheim' and 'simulator' at runtime."""
        with self._lock:
            self.data_source = create_data_source(mode=mode)
            self.defender.reset()
            self.defender.analyze(self.data_source.get_current_observation())
            logger.info(f"Switched data source mode to '{mode}'.")


# Global application state instance
app_state = AppState()
