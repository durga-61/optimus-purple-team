import logging
import threading
from typing import Optional, Tuple
from app.defender.models import SecurityAnalysisResult
from app.defender.service import DefenderService
from app.simulator.models import WarehouseObservation
from app.simulator.warehouse import ColdStorageWarehouse

logger = logging.getLogger("api.state")


class AppState:
    """Manages runtime instances of ColdStorageWarehouse and DefenderService with thread safety."""

    def __init__(self, seed: Optional[int] = 42):
        self._lock = threading.RLock()
        self.warehouse = ColdStorageWarehouse(seed=seed)
        self.defender = DefenderService()
        # Analyze baseline observation so DefenderService has initial state
        self.defender.analyze(self.warehouse.get_current_observation())
        logger.info("Initialized shared AppState (Warehouse & DefenderService).")

    def step(self) -> Tuple[WarehouseObservation, SecurityAnalysisResult]:
        """Atomically advance the warehouse simulation and run DefenderService analysis."""
        with self._lock:
            obs = self.warehouse.step()
            analysis = self.defender.analyze(obs)
            return obs, analysis

    def reset(self, seed: Optional[int] = 42) -> None:
        """Atomically reset warehouse and defender state to baseline."""
        with self._lock:
            self.warehouse.reset(seed=seed)
            self.defender.reset()
            self.defender.analyze(self.warehouse.get_current_observation())
            logger.info("Reset shared AppState.")


# Global application state instance
app_state = AppState()
