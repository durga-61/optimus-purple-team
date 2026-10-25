"""Deterministic attack injection scenarios for warehouse simulation testing.

These scenarios generate controlled anomalies and data integrity attacks on top of
normal warehouse observations to validate the defender pipeline (ML, Semantic,
Temporal, Structural, and Joint Decision).
"""

from typing import Optional
from app.simulator.models import WarehouseObservation


def inject_capacity_manipulation(
    obs: WarehouseObservation,
    reported_free_capacity: Optional[float] = 40.0,
    total_capacity: Optional[float] = None,
) -> WarehouseObservation:
    """Injects a capacity inconsistency attack (violates C1 Capacity Consistency)."""
    data = obs.model_dump()
    if data.get("inventory") is None:
        data["inventory"] = 42.0
    if data.get("capacity") is None:
        data["capacity"] = 50.0
    if data.get("free_capacity") is None:
        data["free_capacity"] = 8.0
    if total_capacity is not None:
        data["capacity"] = float(total_capacity)
    elif reported_free_capacity is not None:
        data["free_capacity"] = float(reported_free_capacity)
    data["is_attack_injected"] = True
    data["attack_type"] = "capacity_manipulation"
    return WarehouseObservation(**data)


def inject_inventory_manipulation(
    obs: WarehouseObservation,
    manipulated_inventory: float = 25.0,
) -> WarehouseObservation:
    """Injects an inventory manipulation attack (violates C2 Flow Consistency).
    
    Alters the inventory value abruptly without corresponding inbound/outbound records.
    """
    data = obs.model_dump()
    if data.get("capacity") is None:
        data["capacity"] = 50.0
    if data.get("free_capacity") is None:
        data["free_capacity"] = 8.0
    data["inventory"] = float(manipulated_inventory)
    data["occupancy"] = round((float(manipulated_inventory) / data["capacity"]) * 100, 2)
    data["is_attack_injected"] = True
    data["attack_type"] = "inventory_manipulation"
    return WarehouseObservation(**data)


def inject_sensor_spoofing(
    obs: WarehouseObservation,
    spoofed_temperature: Optional[float] = 19.5,
    spoofed_humidity: Optional[float] = None,
) -> WarehouseObservation:
    """Injects sensor spoofing attack (violates C3 Historical envelope & ML anomaly).
    
    Alters temperature and/or humidity to values outside safe cold-storage ranges.
    Preserves untouched sensor telemetry if not targeted.
    """
    data = obs.model_dump()
    if spoofed_temperature is not None:
        data["temperature"] = float(spoofed_temperature)
    if spoofed_humidity is not None:
        data["humidity"] = float(spoofed_humidity)
    data["is_attack_injected"] = True
    data["attack_type"] = "sensor_spoofing"
    return WarehouseObservation(**data)


def inject_replay_attack(
    current_obs: WarehouseObservation,
    previous_obs: WarehouseObservation,
) -> WarehouseObservation:
    """Injects a replay attack.
    
    Submits an earlier observation's inventory and sensor values under the current timestamp.
    """
    data = current_obs.model_dump()
    data["inventory"] = previous_obs.inventory
    data["free_capacity"] = previous_obs.free_capacity
    data["temperature"] = previous_obs.temperature
    data["humidity"] = previous_obs.humidity
    data["occupancy"] = previous_obs.occupancy
    data["inbound"] = previous_obs.inbound
    data["outbound"] = previous_obs.outbound
    data["is_attack_injected"] = True
    data["attack_type"] = "replay"
    return WarehouseObservation(**data)


def inject_coordinated_manipulation(
    obs: WarehouseObservation,
    inventory_delta: float = -2.0,
    reported_free_capacity_delta: float = 1.0,
) -> WarehouseObservation:
    """Injects coordinated weak manipulation.
    
    Subtle shifts across inventory and free capacity designed to evade single-variable checks.
    """
    data = obs.model_dump()
    if data.get("inventory") is None:
        data["inventory"] = 42.0
    if data.get("capacity") is None:
        data["capacity"] = 50.0
    if data.get("free_capacity") is None:
        data["free_capacity"] = 8.0
    data["inventory"] = max(0.0, round(data["inventory"] + inventory_delta, 2))
    data["free_capacity"] = max(0.0, round(data["free_capacity"] + reported_free_capacity_delta, 2))
    data["is_attack_injected"] = True
    data["attack_type"] = "coordinated_manipulation"
    return WarehouseObservation(**data)


def inject_multi_source_manipulation(
    obs: WarehouseObservation,
) -> WarehouseObservation:
    """Injects multi-source manipulation affecting sensors and operational records simultaneously."""
    data = obs.model_dump()
    if data.get("inventory") is None:
        data["inventory"] = 42.0
    if data.get("capacity") is None:
        data["capacity"] = 50.0
    if data.get("free_capacity") is None:
        data["free_capacity"] = 8.0
    data["inventory"] = max(0.0, round(data["inventory"] - 5.0, 2))
    data["temperature"] = round(data["temperature"] + 6.0, 2)  # Heating up cold storage
    data["inbound"] = 0.0
    data["outbound"] = 0.0
    data["is_attack_injected"] = True
    data["attack_type"] = "multi_source_manipulation"
    return WarehouseObservation(**data)
