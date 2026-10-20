from fastapi import APIRouter, Depends, Query
from app.api.auth import verify_operator_access
from app.api.schemas import (
    ResetResponse,
    WarehouseHistoryResponse,
    WarehouseObservationHistoryItem,
    WarehouseStepResponse,
)
from app.api.state import app_state
from app.simulator.models import WarehouseObservation

router = APIRouter(prefix="/warehouse", tags=["Warehouse"])


@router.get("/current", response_model=WarehouseObservation)
def get_current_warehouse_state() -> WarehouseObservation:
    """Retrieve the current real-time cold-storage warehouse telemetry and operational state."""
    return app_state.warehouse.get_current_observation()


@router.get("/history", response_model=WarehouseHistoryResponse)
def get_warehouse_history(
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of recent observations to return")
) -> WarehouseHistoryResponse:
    """Retrieve historical observations recorded by the warehouse simulator.

    Idempotent read-only endpoint:
    - Reads existing simulator history
    - Never advances the simulation
    - Never modifies state
    - Never triggers DefenderService
    """
    raw_history = app_state.warehouse.get_history(limit=limit)
    items = [
        WarehouseObservationHistoryItem(
            step=obs.step,
            timestamp=obs.timestamp,
            temperature=obs.temperature,
            humidity=obs.humidity,
            inventory=obs.inventory,
            free_capacity=obs.free_capacity,
            total_capacity=obs.capacity,
            occupancy=obs.occupancy,
            inbound=obs.inbound,
            outbound=obs.outbound,
        )
        for obs in raw_history
    ]
    return WarehouseHistoryResponse(
        warehouse=app_state.warehouse.warehouse_id,
        observations=items,
    )


@router.post("/step", response_model=WarehouseStepResponse, dependencies=[Depends(verify_operator_access)])
def step_warehouse_simulation() -> WarehouseStepResponse:
    """Advance the warehouse simulation by one discrete step and evaluate through DefenderService.
    
    The newly generated observation is processed immediately by the full security pipeline,
    updating the security state, events, and active alerts atomically.
    """
    observation, security_analysis = app_state.step()

    return WarehouseStepResponse(
        observation=observation,
        security_analysis=security_analysis,
    )


@router.post("/reset", response_model=ResetResponse, dependencies=[Depends(verify_operator_access)])
def reset_warehouse_simulation() -> ResetResponse:
    """Reset the warehouse simulator and operational history to baseline state."""
    app_state.reset()
    return ResetResponse(
        success=True,
        message="Warehouse simulation successfully reset to initial baseline state.",
    )
