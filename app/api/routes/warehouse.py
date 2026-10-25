"""Warehouse and Cold-Storage Data Source API Endpoints."""

import time
from typing import Any, Dict
from fastapi import APIRouter, Depends, Query, status, HTTPException
from app.api.auth import verify_operator_access
from app.api.schemas import (
    PlaybackStatusResponse,
    ResetResponse,
    SeekPlaybackRequest,
    TransmitObservationRequest,
    TransmitObservationResponse,
    WarehouseHistoryResponse,
    WarehouseObservationHistoryItem,
    WarehouseStepResponse,
)
from app.api.state import app_state
from app.simulator.models import WarehouseObservation

router = APIRouter(prefix="/warehouse", tags=["Warehouse & Data Source"])


@router.get("/window")
def get_warehouse_window(
    step: int = Query(default=0, ge=0, description="Start step index for observation window"),
    size: int = Query(default=20, ge=1, le=100, description="Number of consecutive observations to return"),
) -> Dict[str, Any]:
    """Retrieve consecutive observations starting from step for time-series visualization."""
    observations = app_state.data_source.get_window(start_step=step, window_size=size)
    return {
        "start_step": step,
        "window_size": len(observations),
        "observations": [
            {
                "step": obs.step,
                "timestamp": obs.timestamp,
                "temperature": obs.temperature,
                "humidity": obs.humidity,
                "sensors": obs.sensors,
                "active_action": obs.active_action,
                "data_quality": obs.data_quality,
            }
            for obs in observations
        ],
    }


@router.get("/current", response_model=WarehouseObservation)
def get_current_warehouse_state() -> WarehouseObservation:
    """Retrieve current cold-storage telemetry, multi-sensor readings, and operational state."""
    return app_state.data_source.get_current_observation()


@router.get("/history", response_model=WarehouseHistoryResponse)
def get_warehouse_history(
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of recent observations to return")
) -> WarehouseHistoryResponse:
    """Retrieve historical observations recorded by the data source or simulator."""
    raw_history = app_state.data_source.get_history(limit=limit)
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
            sensors=obs.sensors,
            active_action=obs.active_action,
        )
        for obs in raw_history
    ]
    wh_id = getattr(app_state.data_source, "warehouse_id", "W01-Hohenheim")
    return WarehouseHistoryResponse(
        warehouse=wh_id,
        observations=items,
    )


@router.get("/playback", response_model=PlaybackStatusResponse)
def get_playback_status() -> PlaybackStatusResponse:
    """Retrieve playback progress, active action, and dataset cursor information."""
    status_dict = app_state.data_source.get_playback_status()
    return PlaybackStatusResponse(**status_dict)


@router.get("/metadata")
def get_data_source_metadata() -> Dict[str, Any]:
    """Retrieve authoritative metadata regarding the active data source and dataset."""
    return app_state.data_source.get_metadata()


@router.post("/step", response_model=WarehouseStepResponse, dependencies=[Depends(verify_operator_access)])
def step_warehouse_simulation() -> WarehouseStepResponse:
    """Advance the dataset playback or simulation by one step and evaluate through DefenderService."""
    observation, security_analysis = app_state.step()
    return WarehouseStepResponse(
        observation=observation,
        security_analysis=security_analysis,
    )


@router.post("/seek", response_model=WarehouseStepResponse, dependencies=[Depends(verify_operator_access)])
def seek_playback_position(body: SeekPlaybackRequest) -> WarehouseStepResponse:
    """Seek recorded dataset playback to a discrete step index and evaluate."""
    try:
        observation, security_analysis = app_state.seek(body.step)
        return WarehouseStepResponse(
            observation=observation,
            security_analysis=security_analysis,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to seek playback: {exc}",
        )


@router.post("/reset", response_model=ResetResponse, dependencies=[Depends(verify_operator_access)])
def reset_warehouse_simulation() -> ResetResponse:
    """Reset the data source and operational history to baseline state."""
    app_state.reset()
    return ResetResponse(
        success=True,
        message="Data source playback and DefenderService successfully reset to initial baseline state.",
    )


@router.post("/mode/{mode}", dependencies=[Depends(verify_operator_access)])
def set_data_source_mode(mode: str) -> Dict[str, Any]:
    """Switch runtime data source between 'hohenheim' (real dataset) and 'simulator'."""
    clean_mode = mode.lower().strip()
    if clean_mode not in ("hohenheim", "simulator"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mode must be either 'hohenheim' or 'simulator'.",
        )
    app_state.set_data_source_mode(clean_mode)
    return {
        "success": True,
        "mode": clean_mode,
        "metadata": app_state.data_source.get_metadata(),
    }


@router.post(
    "/transmit",
    response_model=TransmitObservationResponse,
    dependencies=[Depends(verify_operator_access)],
)
def transmit_observation(body: TransmitObservationRequest) -> TransmitObservationResponse:
    """Transmit a sensor observation from Sensor Transmitter to the Defender analysis pipeline.

    Returns delivery receipt with stable observation ID, timestamp, and Defender analysis verdict.
    """
    t0 = time.perf_counter()
    try:
        if body.observation:
            obs = WarehouseObservation(**body.observation)
        elif body.step is not None:
            obs = app_state.data_source.seek(body.step)
        else:
            obs = app_state.data_source.get_current_observation()

        # Run analysis through Defender pipeline
        analysis = app_state.defender.analyze(obs)
        latency_ms = (time.perf_counter() - t0) * 1000.0

        sensors_dict = obs.sensors or {}
        dq = obs.data_quality or {}
        active_cnt = dq.get("active_sensor_count")
        if active_cnt is None:
            active_cnt = sum(1 for s in sensors_dict.values() if s.get("temperature") is not None)

        obs_id = f"OBS-{obs.step:06d}"
        return TransmitObservationResponse(
            status="DELIVERED",
            observation_id=obs_id,
            step=obs.step,
            timestamp=obs.timestamp,
            source=obs.source or "hohenheim",
            sensors_transmitted=len(sensors_dict),
            active_sensors=active_cnt,
            defender_classification=analysis.decision.classification,
            risk_score=analysis.decision.risk_score,
            integrity_score=analysis.decision.integrity_score,
            latency_ms=round(latency_ms, 2),
            security_analysis=analysis,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Transmission to Defender pipeline failed: {exc}",
        )
