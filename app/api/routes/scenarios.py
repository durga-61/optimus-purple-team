"""Deterministic attack scenarios API endpoints."""

from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException

from app.api.auth import verify_operator_access

from app.api.schemas import (
    ScenarioExecutionResponse,
    ScenarioInfo,
    ScenariosListResponse,
)
from app.api.state import app_state
from app.simulator.scenarios import (
    inject_capacity_manipulation,
    inject_inventory_manipulation,
    inject_sensor_spoofing,
    inject_replay_attack,
    inject_coordinated_manipulation,
    inject_multi_source_manipulation,
)

router = APIRouter(prefix="/scenarios", tags=["Scenarios"])

SCENARIOS_CATALOG: Dict[str, Dict[str, str]] = {
    "capacity_manipulation": {
        "name": "Capacity Inconsistency Attack",
        "description": "Manipulates reported free capacity while keeping inventory constant (Inventory 42t + Free 40t > Total 50t).",
        "target_constraint": "C1 (Capacity Consistency)",
    },
    "inventory_manipulation": {
        "name": "Inventory Ledger Manipulation",
        "description": "Abruptly shifts reported inventory without corresponding inbound or outbound shipment ledger records.",
        "target_constraint": "C2 (Inventory Flow Consistency)",
    },
    "sensor_spoofing": {
        "name": "IoT Environmental Sensor Spoofing",
        "description": "Spoofs temperature and humidity readings far outside safe cold-storage historical operating bounds.",
        "target_constraint": "C3 (Historical Operating Envelope) & ML Anomaly",
    },
    "replay": {
        "name": "Telemetry Replay Attack",
        "description": "Replays an earlier valid historical observation into the evolving warehouse state, causing flow discrepancies.",
        "target_constraint": "C2 (Inventory Flow) & State Continuity",
    },
    "coordinated_manipulation": {
        "name": "Coordinated Weak Manipulation",
        "description": "Subtle, correlated micro-manipulations across inventory and capacity designed to evade single-point thresholds.",
        "target_constraint": "C1, C2 & Temporal Recurrence",
    },
    "multi_source_manipulation": {
        "name": "Multi-Source Cross-Subsystem Attack",
        "description": "Simultaneously corrupts inventory ledgers and heating cold storage to trigger multi-source correlation.",
        "target_constraint": "C1, C2, C3 & Structural Subsystem Graph",
    },
}


SCENARIO_ALIASES: Dict[str, str] = {
    "replay_attack": "replay",
    "coordinated_weak": "coordinated_manipulation",
    "multi_source": "multi_source_manipulation",
}


@router.get("", response_model=ScenariosListResponse)
def list_available_scenarios() -> ScenariosListResponse:
    """List all available deterministic attack simulation scenarios."""
    scenarios_list = [
        ScenarioInfo(
            id=key,
            name=meta["name"],
            description=meta["description"],
            target_constraint=meta["target_constraint"],
        )
        for key, meta in SCENARIOS_CATALOG.items()
    ]
    return ScenariosListResponse(scenarios=scenarios_list)


@router.post("/{scenario_name}", response_model=ScenarioExecutionResponse, dependencies=[Depends(verify_operator_access)])
def execute_deterministic_scenario(scenario_name: str) -> ScenarioExecutionResponse:
    """Execute a controlled deterministic attack scenario through the live DefenderService pipeline."""
    scenario_input = scenario_name.lower().strip()
    scenario_key = SCENARIO_ALIASES.get(scenario_input, scenario_input)

    if scenario_key not in SCENARIOS_CATALOG:
        valid_keys = ", ".join(list(SCENARIOS_CATALOG.keys()) + list(SCENARIO_ALIASES.keys()))
        raise HTTPException(
            status_code=404,
            detail=f"Scenario '{scenario_name}' not found. Available scenarios: {valid_keys}",
        )

    with app_state._lock:
        # 1. Step the warehouse to obtain an up-to-date baseline observation
        base_obs = app_state.warehouse.step()

        # 2. Apply deterministic mutation
        if scenario_key == "capacity_manipulation":
            attacked_obs = inject_capacity_manipulation(base_obs, reported_free_capacity=40.0)
        elif scenario_key == "inventory_manipulation":
            attacked_obs = inject_inventory_manipulation(base_obs, manipulated_inventory=20.0)
        elif scenario_key == "sensor_spoofing":
            attacked_obs = inject_sensor_spoofing(base_obs, spoofed_temperature=28.0, spoofed_humidity=95.0)
        elif scenario_key == "replay":
            # Replay attack requires that DefenderService has analyzed an evolved state so replaying history[0] creates a flow violation
            if app_state.warehouse.step_count <= 1:
                evolved_obs = app_state.warehouse.step(inbound=3.0, outbound=0.0)
                app_state.defender.analyze(evolved_obs)
            base_obs = app_state.warehouse.step()
            past_obs = app_state.warehouse.history[0]
            attacked_obs = inject_replay_attack(current_obs=base_obs, previous_obs=past_obs)
        elif scenario_key == "coordinated_manipulation":
            attacked_obs = inject_coordinated_manipulation(base_obs, inventory_delta=-2.0, reported_free_capacity_delta=1.0)
        elif scenario_key == "multi_source_manipulation":
            attacked_obs = inject_multi_source_manipulation(base_obs)
        else:
            raise HTTPException(status_code=400, detail=f"Unimplemented scenario handler for {scenario_key}")

        # 3. Synchronize warehouse state with injected observation
        app_state.warehouse.inject_observation(attacked_obs)

        # 4. Route through the actual DefenderService pipeline
        analysis = app_state.defender.analyze(attacked_obs)

        return ScenarioExecutionResponse(
            scenario=scenario_key,
            observation=attacked_obs,
            security_analysis=analysis,
        )
