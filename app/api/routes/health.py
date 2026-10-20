"""Health check API endpoints."""

from fastapi import APIRouter
from app.api.schemas import HealthResponse
from app.api.state import app_state

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Check application health and readiness of simulator and defender engines."""
    simulator_status = "running" if app_state.warehouse is not None else "unavailable"
    defender_status = "ready" if app_state.defender is not None else "unavailable"
    is_healthy = simulator_status == "running" and defender_status == "ready"

    return HealthResponse(
        status="healthy" if is_healthy else "degraded",
        service="organization-security-platform",
        simulator=simulator_status,
        defender=defender_status,
    )
