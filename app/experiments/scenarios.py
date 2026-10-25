"""Controlled attack scenarios for authentic cold-storage sensor time-series data.

Operates strictly on copies of real recorded observations. The original raw dataset
is NEVER modified. Ground truth labels and attack metadata are strictly isolated from
the Defender pipeline.
"""

from copy import deepcopy
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from app.config import settings
from app.experiments.models import AttackConfiguration, ModifiedField
from app.simulator.models import WarehouseObservation

# Supported attack scenarios metadata
SCENARIOS_CATALOG: Dict[str, Dict[str, Any]] = {
    "temperature_manipulation": {
        "id": "temperature_manipulation",
        "name": "Temperature Reading Manipulation",
        "description": "Applies a discrete numerical offset to a selected sensor channel's temperature reading, testing single-point out-of-envelope detection.",
        "target_layers": ["Semantic (C3)", "ML Outlier Detector", "Decision Fusion"],
        "default_parameters": {"target_sensor": "SENSOR01", "magnitude": 12.0},
        "parameter_schema": {
            "target_sensor": {"type": "select", "options": [f"SENSOR0{i}" for i in range(1, 10)], "default": "SENSOR01"},
            "magnitude": {"type": "number", "unit": "°C", "default": 12.0, "min": -20.0, "max": 30.0},
        },
    },
    "humidity_manipulation": {
        "id": "humidity_manipulation",
        "name": "Relative Humidity Manipulation",
        "description": "Alters relative humidity in a selected sensor channel, testing environmental moisture bounds and multi-sensor drift.",
        "target_layers": ["Semantic (C3)", "ML Outlier Detector"],
        "default_parameters": {"target_sensor": "SENSOR01", "magnitude": 25.0},
        "parameter_schema": {
            "target_sensor": {"type": "select", "options": [f"SENSOR0{i}" for i in range(1, 10)], "default": "SENSOR01"},
            "magnitude": {"type": "number", "unit": "%", "default": 25.0, "min": -50.0, "max": 50.0},
        },
    },
    "sensor_drift": {
        "id": "sensor_drift",
        "name": "Progressive Sensor Bias / Drift",
        "description": "Applies a gradual cumulative offset over consecutive observation intervals, designed to evaluate temporal recurrence and subtle evasion.",
        "target_layers": ["Temporal Engine", "ML Outlier Detector", "Semantic (C3)"],
        "default_parameters": {"target_sensor": "SENSOR02", "drift_rate": 0.8, "drift_steps": 5},
        "parameter_schema": {
            "target_sensor": {"type": "select", "options": [f"SENSOR0{i}" for i in range(1, 10)], "default": "SENSOR02"},
            "drift_rate": {"type": "number", "unit": "°C/step", "default": 0.8, "min": 0.1, "max": 3.0},
            "drift_steps": {"type": "number", "unit": "steps", "default": 5, "min": 1, "max": 20},
        },
    },
    "replay_substitution": {
        "id": "replay_substitution",
        "name": "Telemetry Replay / Stale Data",
        "description": "Substitutes recorded telemetry from an earlier timestamp under the current timestamp, evaluating temporal continuity and state freezing.",
        "target_layers": ["Temporal Engine", "Semantic (C3/C4)", "ML Outlier Detector"],
        "default_parameters": {"target_sensor": "SENSOR01", "replay_step": None},
        "parameter_schema": {
            "target_sensor": {"type": "select", "options": [f"SENSOR0{i}" for i in range(1, 10)], "default": "SENSOR01"},
            "replay_step": {"type": "number", "unit": "step", "default": 0, "min": 0, "max": 156834},
        },
    },
    "cross_sensor_inconsistency": {
        "id": "cross_sensor_inconsistency",
        "name": "Cross-Sensor Spatial Inconsistency",
        "description": "Injects an localized thermal gradient into one sensor relative to the remaining spatial array, triggering C4 spatial delta alerts.",
        "target_layers": ["Semantic (C4 Spatial)", "ML Multi-Sensor Outlier", "Structural Engine"],
        "default_parameters": {"target_sensor": "SENSOR04", "magnitude": 8.0},
        "parameter_schema": {
            "target_sensor": {"type": "select", "options": [f"SENSOR0{i}" for i in range(1, 10)], "default": "SENSOR04"},
            "magnitude": {"type": "number", "unit": "°C", "default": 8.0, "min": 4.0, "max": 20.0},
        },
    },
    "sensor_dropout": {
        "id": "sensor_dropout",
        "name": "Targeted Sensor Dropout / Telemetry Suppression",
        "description": "Selectively suppresses telemetry from specified sensor channels, testing missing-data robustness and dropout differentiation.",
        "target_layers": ["ML Multi-Sensor Outlier", "Data Quality Guard", "Semantic (C4)"],
        "default_parameters": {"target_sensor": "SENSOR01"},
        "parameter_schema": {
            "target_sensor": {"type": "select", "options": [f"SENSOR0{i}" for i in range(1, 10)], "default": "SENSOR01"},
        },
    },
}


def _recompute_environmental_quality(obs_dict: Dict[str, Any], target_sensor: str) -> None:
    """Recompute spatial metrics and active sensor counts after a sensor modification."""
    sensors = obs_dict.get("sensors") or {}
    active_sensors = []
    missing_sensors = []
    temps = []
    hums = []

    for s_id in [f"SENSOR0{i}" for i in range(1, 10)]:
        s_data = sensors.get(s_id) or {}
        t = s_data.get("temperature")
        h = s_data.get("humidity")
        if t is not None and h is not None:
            active_sensors.append(s_id)
            temps.append(float(t))
            hums.append(float(h))
        else:
            missing_sensors.append(s_id)

    # Primary cold-storage temperature & humidity representation
    if sensors.get("SENSOR01") and sensors["SENSOR01"].get("temperature") is not None:
        obs_dict["temperature"] = sensors["SENSOR01"]["temperature"]
        obs_dict["humidity"] = sensors["SENSOR01"]["humidity"]
    elif temps:
        obs_dict["temperature"] = round(float(np.mean(temps)), 2)
        obs_dict["humidity"] = round(float(np.mean(hums)), 2)
    else:
        obs_dict["temperature"] = settings.TARGET_TEMPERATURE
        obs_dict["humidity"] = settings.TARGET_HUMIDITY

    temp_delta = round(float(max(temps) - min(temps)), 2) if len(temps) > 1 else 0.0
    hum_delta = round(float(max(hums) - min(hums)), 2) if len(hums) > 1 else 0.0

    obs_dict["data_quality"] = {
        "total_sensors": 9,
        "active_sensor_count": len(active_sensors),
        "missing_sensor_count": len(missing_sensors),
        "active_sensors": active_sensors,
        "missing_sensors": missing_sensors,
        "has_missing_data": len(missing_sensors) > 0,
        "inter_sensor_temp_delta": temp_delta,
        "inter_sensor_hum_delta": hum_delta,
        "spatial_temp_std": round(float(np.std(temps)), 2) if len(temps) > 1 else 0.0,
    }


def apply_temperature_manipulation(
    obs: WarehouseObservation,
    target_sensor: str = "SENSOR01",
    magnitude: float = 12.0,
) -> Tuple[WarehouseObservation, List[ModifiedField]]:
    """Inject discrete temperature manipulation into a target sensor channel."""
    data = obs.model_dump()
    sensors = data.setdefault("sensors", {})
    s_data = sensors.setdefault(target_sensor, {"temperature": 11.2, "humidity": 75.0})

    orig_temp = s_data.get("temperature")
    if orig_temp is None:
        orig_temp = 11.2

    new_temp = round(float(orig_temp + magnitude), 2)
    s_data["temperature"] = new_temp
    _recompute_environmental_quality(data, target_sensor)

    # Ground-truth isolation: NEVER leak attack flag into Defender input
    data["is_attack_injected"] = False
    data["attack_type"] = None

    mod_field = ModifiedField(
        sensor=target_sensor,
        field="temperature",
        original_value=orig_temp,
        modified_value=new_temp,
        delta=round(magnitude, 2),
        description=f"Shifted {target_sensor} temperature from {orig_temp:.1f}°C to {new_temp:.1f}°C (offset: {magnitude:+.1f}°C)",
    )
    return WarehouseObservation(**data), [mod_field]


def apply_humidity_manipulation(
    obs: WarehouseObservation,
    target_sensor: str = "SENSOR01",
    magnitude: float = 25.0,
) -> Tuple[WarehouseObservation, List[ModifiedField]]:
    """Inject relative humidity manipulation into a target sensor channel."""
    data = obs.model_dump()
    sensors = data.setdefault("sensors", {})
    s_data = sensors.setdefault(target_sensor, {"temperature": 11.2, "humidity": 75.0})

    orig_hum = s_data.get("humidity")
    if orig_hum is None:
        orig_hum = 75.0

    new_hum = round(float(min(100.0, max(0.0, orig_hum + magnitude))), 2)
    s_data["humidity"] = new_hum
    _recompute_environmental_quality(data, target_sensor)

    data["is_attack_injected"] = False
    data["attack_type"] = None

    mod_field = ModifiedField(
        sensor=target_sensor,
        field="humidity",
        original_value=orig_hum,
        modified_value=new_hum,
        delta=round(new_hum - orig_hum, 2),
        description=f"Shifted {target_sensor} humidity from {orig_hum:.1f}% to {new_hum:.1f}% (offset: {magnitude:+.1f}%)",
    )
    return WarehouseObservation(**data), [mod_field]


def apply_sensor_drift(
    obs: WarehouseObservation,
    target_sensor: str = "SENSOR02",
    drift_rate: float = 0.8,
    drift_steps: int = 5,
) -> Tuple[WarehouseObservation, List[ModifiedField]]:
    """Inject cumulative gradual sensor drift over discrete steps."""
    data = obs.model_dump()
    sensors = data.setdefault("sensors", {})
    s_data = sensors.setdefault(target_sensor, {"temperature": 11.2, "humidity": 75.0})

    orig_temp = s_data.get("temperature")
    if orig_temp is None:
        orig_temp = 11.2

    cumulative_offset = round(float(drift_rate * drift_steps), 2)
    new_temp = round(float(orig_temp + cumulative_offset), 2)
    s_data["temperature"] = new_temp
    _recompute_environmental_quality(data, target_sensor)

    data["is_attack_injected"] = False
    data["attack_type"] = None

    mod_field = ModifiedField(
        sensor=target_sensor,
        field="temperature",
        original_value=orig_temp,
        modified_value=new_temp,
        delta=cumulative_offset,
        description=f"Applied progressive bias to {target_sensor}: {drift_steps} steps at {drift_rate:+.1f}°C/step = {cumulative_offset:+.1f}°C total drift",
    )
    return WarehouseObservation(**data), [mod_field]


def apply_replay_substitution(
    obs: WarehouseObservation,
    target_sensor: str = "SENSOR01",
    past_obs: Optional[WarehouseObservation] = None,
) -> Tuple[WarehouseObservation, List[ModifiedField]]:
    """Substitute an earlier historical observation's sensor reading under the current timestamp."""
    data = obs.model_dump()
    sensors = data.setdefault("sensors", {})
    s_data = sensors.setdefault(target_sensor, {"temperature": 11.2, "humidity": 75.0})

    orig_temp = s_data.get("temperature")
    orig_hum = s_data.get("humidity")

    if past_obs and past_obs.sensors and target_sensor in past_obs.sensors:
        past_target = past_obs.sensors[target_sensor]
        replayed_temp = past_target.get("temperature")
        replayed_hum = past_target.get("humidity")
    else:
        # Synthetic replay baseline if no prior history provided
        replayed_temp = 4.2
        replayed_hum = 71.0

    s_data["temperature"] = replayed_temp
    s_data["humidity"] = replayed_hum
    _recompute_environmental_quality(data, target_sensor)

    data["is_attack_injected"] = False
    data["attack_type"] = None

    past_step = past_obs.step if past_obs else "historical"
    fields = [
        ModifiedField(
            sensor=target_sensor,
            field="temperature",
            original_value=orig_temp,
            modified_value=replayed_temp,
            delta=round(replayed_temp - (orig_temp or 0.0), 2) if (replayed_temp is not None and orig_temp is not None) else None,
            description=f"Replayed {target_sensor} temperature from Step {past_step} ({replayed_temp}°C) into current Step {obs.step}",
        ),
        ModifiedField(
            sensor=target_sensor,
            field="humidity",
            original_value=orig_hum,
            modified_value=replayed_hum,
            delta=round(replayed_hum - (orig_hum or 0.0), 2) if (replayed_hum is not None and orig_hum is not None) else None,
            description=f"Replayed {target_sensor} humidity from Step {past_step} ({replayed_hum}%) into current Step {obs.step}",
        ),
    ]
    return WarehouseObservation(**data), fields


def apply_cross_sensor_inconsistency(
    obs: WarehouseObservation,
    target_sensor: str = "SENSOR04",
    magnitude: float = 8.0,
) -> Tuple[WarehouseObservation, List[ModifiedField]]:
    """Inject a spatial gradient inconsistency between a target sensor and the remaining array."""
    data = obs.model_dump()
    sensors = data.setdefault("sensors", {})
    s_data = sensors.setdefault(target_sensor, {"temperature": 11.2, "humidity": 75.0})

    orig_temp = s_data.get("temperature")
    if orig_temp is None:
        orig_temp = 11.2

    new_temp = round(float(orig_temp + magnitude), 2)
    s_data["temperature"] = new_temp
    _recompute_environmental_quality(data, target_sensor)

    data["is_attack_injected"] = False
    data["attack_type"] = None

    mod_field = ModifiedField(
        sensor=target_sensor,
        field="temperature",
        original_value=orig_temp,
        modified_value=new_temp,
        delta=round(magnitude, 2),
        description=f"Induced cross-sensor spatial gradient violation on {target_sensor} (+{magnitude:.1f}°C vs ambient room cluster)",
    )
    return WarehouseObservation(**data), [mod_field]


def apply_sensor_dropout(
    obs: WarehouseObservation,
    target_sensor: str = "SENSOR01",
) -> Tuple[WarehouseObservation, List[ModifiedField]]:
    """Intentionally suppress telemetry from specified sensor channels (forced dropout)."""
    data = obs.model_dump()
    sensors = data.setdefault("sensors", {})
    s_data = sensors.setdefault(target_sensor, {"temperature": 11.2, "humidity": 75.0})

    orig_temp = s_data.get("temperature")
    orig_hum = s_data.get("humidity")

    # Suppress channel
    s_data["temperature"] = None
    s_data["humidity"] = None
    _recompute_environmental_quality(data, target_sensor)

    data["is_attack_injected"] = False
    data["attack_type"] = None

    mod_field = ModifiedField(
        sensor=target_sensor,
        field="telemetry",
        original_value=orig_temp,
        modified_value=None,
        delta=None,
        description=f"Suppressed all telemetry from {target_sensor} (injected dropout)",
    )
    return WarehouseObservation(**data), [mod_field]


def apply_attack(
    obs: WarehouseObservation,
    config: AttackConfiguration,
    past_obs: Optional[WarehouseObservation] = None,
) -> Tuple[WarehouseObservation, List[ModifiedField]]:
    """Master dispatch router applying the configured attack scenario."""
    sc = config.scenario.lower().strip()
    sensor = config.target_sensor.strip().upper() if config.target_sensor else "SENSOR01"

    if sc == "temperature_manipulation":
        mag = config.magnitude if config.magnitude is not None else 12.0
        return apply_temperature_manipulation(obs, target_sensor=sensor, magnitude=mag)

    elif sc == "humidity_manipulation":
        mag = config.magnitude if config.magnitude is not None else 25.0
        return apply_humidity_manipulation(obs, target_sensor=sensor, magnitude=mag)

    elif sc == "sensor_drift":
        rate = config.drift_rate if config.drift_rate is not None else 0.8
        steps = config.drift_steps if config.drift_steps is not None else 5
        return apply_sensor_drift(obs, target_sensor=sensor, drift_rate=rate, drift_steps=steps)

    elif sc == "replay_substitution":
        return apply_replay_substitution(obs, target_sensor=sensor, past_obs=past_obs)

    elif sc == "cross_sensor_inconsistency":
        mag = config.magnitude if config.magnitude is not None else 8.0
        return apply_cross_sensor_inconsistency(obs, target_sensor=sensor, magnitude=mag)

    elif sc == "sensor_dropout":
        return apply_sensor_dropout(obs, target_sensor=sensor)

    else:
        raise ValueError(
            f"Unknown attack scenario '{config.scenario}'. Available: {list(SCENARIOS_CATALOG.keys())}"
        )
