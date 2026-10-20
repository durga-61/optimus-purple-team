"""Data models for organization cold-storage warehouse simulator.

Defines Pydantic models for IoT telemetry, operational records, and state snapshots.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, field_validator


class WarehouseObservation(BaseModel):
    """Represents a single point-in-time observation of the warehouse environment.
    
    Includes IoT sensor readings, inventory levels, capacity metrics, and shipment flow.
    """

    warehouse: str = Field(default="W01", description="Identifier of the monitored facility")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp of the observation",
    )
    step: int = Field(default=0, ge=0, description="Sequential observation sequence number")

    # Core operational capacity & inventory metrics (in metric tons)
    capacity: float = Field(default=50.0, gt=0, description="Total storage capacity in metric tons")
    inventory: float = Field(default=42.0, ge=0, description="Current recorded inventory in metric tons")
    free_capacity: float = Field(default=8.0, ge=0, description="Reported available capacity in metric tons")

    # Environmental IoT sensor telemetry
    temperature: float = Field(default=4.2, description="Internal cold-storage temperature in °C")
    humidity: float = Field(default=71.0, ge=0, le=100, description="Relative humidity percentage")
    occupancy: float = Field(default=84.0, ge=0, le=100, description="Storage occupancy percentage")

    # Inbound / Outbound shipment ledger (in metric tons)
    inbound: float = Field(default=0.0, ge=0, description="Inbound shipment tonnage since last step")
    outbound: float = Field(default=0.0, ge=0, description="Outbound shipment tonnage since last step")

    # Attack simulation metadata (tracked by simulator for validation)
    is_attack_injected: bool = Field(default=False, description="True if an attack modifier was applied")
    attack_type: Optional[str] = Field(default=None, description="Name of the injected attack scenario, if any")

    @field_validator("capacity")
    @classmethod
    def validate_capacity_positive(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("Capacity must be strictly positive")
        return round(v, 2)

    @field_validator("inventory", "free_capacity", "inbound", "outbound")
    @classmethod
    def round_tonnage(cls, v: float) -> float:
        if v < 0:
            raise ValueError("Tonnage values cannot be negative")
        return round(v, 2)

    @field_validator("temperature", "humidity", "occupancy")
    @classmethod
    def round_telemetry(cls, v: float) -> float:
        return round(v, 2)

    def to_api_dict(self) -> Dict[str, Any]:
        """Convert to dict matching API_SPECIFICATION.md /api/live-data schema."""
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
        }
