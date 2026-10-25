"""Data models for organization cold-storage warehouse and environmental telemetry.

Defines Pydantic models for IoT telemetry, multi-sensor environmental recordings,
operational records, and data source observations.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator


class WarehouseObservation(BaseModel):
    """Represents a single point-in-time observation of the cold-storage environment.
    
    Supports both simulated warehouse records (with inventory/capacity ledgers)
    and real recorded environmental datasets (such as University of Hohenheim 9-sensor time series).
    """

    warehouse: str = Field(default="W01", description="Identifier of the monitored facility")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of the observation",
    )
    step: int = Field(default=0, ge=0, description="Sequential observation sequence number")

    # Core operational capacity & inventory metrics (Optional - None in pure environmental datasets)
    capacity: Optional[float] = Field(default=50.0, description="Total storage capacity in metric tons")
    inventory: Optional[float] = Field(default=42.0, description="Current recorded inventory in metric tons")
    free_capacity: Optional[float] = Field(default=8.0, description="Reported available capacity in metric tons")

    # Primary environmental IoT sensor telemetry
    temperature: float = Field(default=4.2, description="Internal cold-storage temperature in °C")
    humidity: float = Field(default=71.0, ge=0, le=100, description="Relative humidity percentage")
    occupancy: Optional[float] = Field(default=84.0, description="Storage occupancy percentage")

    # Inbound / Outbound shipment ledger (Optional - None in pure environmental datasets)
    inbound: Optional[float] = Field(default=0.0, description="Inbound shipment tonnage since last step")
    outbound: Optional[float] = Field(default=0.0, description="Outbound shipment tonnage since last step")

    # Attack simulation metadata (tracked for verification)
    is_attack_injected: bool = Field(default=False, description="True if an attack modifier was applied")
    attack_type: Optional[str] = Field(default=None, description="Name of the injected attack scenario, if any")

    # Real recorded dataset & multi-sensor metadata
    source: str = Field(default="simulator", description="Data source identifier (hohenheim or simulator)")
    is_recorded_playback: bool = Field(default=False, description="True if playback of historical recorded dataset")
    dataset_name: Optional[str] = Field(default=None, description="Name of the recorded dataset, if applicable")
    sensors: Optional[Dict[str, Dict[str, Optional[float]]]] = Field(
        default=None, description="Per-sensor environmental readings for all available DHT22 sensors"
    )
    active_action: Optional[str] = Field(default=None, description="Documented physical experiment action (e.g. Door opened)")
    data_quality: Optional[Dict[str, Any]] = Field(default=None, description="Data completeness and sensor health metrics")

    @field_validator("capacity")
    @classmethod
    def validate_capacity_positive(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            if v <= 0:
                raise ValueError("Capacity must be strictly positive")
            return round(v, 2)
        return None

    @field_validator("inventory", "free_capacity", "inbound", "outbound")
    @classmethod
    def round_tonnage(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            if v < 0:
                raise ValueError("Tonnage values cannot be negative")
            return round(v, 2)
        return None

    @field_validator("temperature", "humidity")
    @classmethod
    def round_telemetry(cls, v: float) -> float:
        return round(v, 2)

    @field_validator("occupancy")
    @classmethod
    def round_occupancy(cls, v: Optional[float]) -> Optional[float]:
        if v is not None:
            return round(v, 2)
        return None

    def to_api_dict(self) -> Dict[str, Any]:
        """Convert to dict matching API schema."""
        return {
            "warehouse": self.warehouse,
            "capacity": self.capacity,
            "inventory": self.inventory,
            "free_capacity": self.free_capacity,
            "temperature": self.temperature,
            "humidity": self.humidity,
            "occupancy": self.occupancy,
            "inbound": self.inbound,
            "outbound": self.outbound,
            "timestamp": self.timestamp,
            "source": self.source,
            "is_recorded_playback": self.is_recorded_playback,
            "dataset_name": self.dataset_name,
            "sensors": self.sensors,
            "active_action": self.active_action,
        }
