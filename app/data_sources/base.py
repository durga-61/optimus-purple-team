"""Base abstract class and schemas for pluggable data sources."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from app.simulator.models import WarehouseObservation


class BaseDataSource(ABC):
    """Abstract base class for all telemetry and operational data providers."""

    @abstractmethod
    def get_metadata(self) -> Dict[str, Any]:
        """Return metadata regarding the underlying dataset or generator."""
        pass

    @abstractmethod
    def get_available_sensors(self) -> List[str]:
        """Return list of distinct sensor identifiers provided by this source."""
        pass

    @abstractmethod
    def get_current_observation(self) -> WarehouseObservation:
        """Return the observation at the current playback or generation cursor."""
        pass

    @abstractmethod
    def step(self) -> WarehouseObservation:
        """Advance playback or simulation by one discrete observation step."""
        pass

    @abstractmethod
    def seek(self, step: int) -> WarehouseObservation:
        """Seek playback to a specific discrete step index."""
        pass

    @abstractmethod
    def reset(self, seed: Optional[int] = None) -> WarehouseObservation:
        """Reset the data source to its initial beginning state."""
        pass

    @abstractmethod
    def get_history(self, limit: int = 50) -> List[WarehouseObservation]:
        """Retrieve recent historical observations in chronological order."""
        pass

    @abstractmethod
    def get_playback_status(self) -> Dict[str, Any]:
        """Return playback cursor position, total records, and source mode."""
        pass

    def get_window(self, start_step: int, window_size: int = 20) -> List[WarehouseObservation]:
        """Retrieve a window of consecutive observations starting from start_step."""
        return []

    def close(self) -> None:
        """Release underlying resources, file handles, or database connections."""
        pass
