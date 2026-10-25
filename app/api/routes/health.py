"""Health check API endpoints."""

import logging

from fastapi import APIRouter
from app.api.schemas import HealthResponse
from app.api.state import app_state

logger = logging.getLogger("api.health")

router = APIRouter(tags=["Health"])


def _active_data_source() -> str:
    """Return the identifier of the data source currently serving observations."""
    try:
        return app_state.data_source.get_playback_status().get("source", "unknown")
    except Exception:  # pragma: no cover - defensive: health must never raise
        logger.warning("Could not resolve active data source for health check", exc_info=True)
        return "unknown"


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Check application health and readiness of the data source and defender engine."""
    data_source_status = "running" if app_state.data_source is not None else "unavailable"
    defender_status = "ready" if app_state.defender is not None else "unavailable"
    is_healthy = data_source_status == "running" and defender_status == "ready"

    return HealthResponse(
        status="healthy" if is_healthy else "degraded",
        service="organization-security-platform",
        data_source=_active_data_source(),
        simulator=data_source_status,
        defender=defender_status,
    )
