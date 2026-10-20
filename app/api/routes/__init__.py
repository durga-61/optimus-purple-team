"""API route modules package."""

from app.api.routes.health import router as health_router
from app.api.routes.warehouse import router as warehouse_router
from app.api.routes.security import router as security_router
from app.api.routes.scenarios import router as scenarios_router

__all__ = ["health_router", "warehouse_router", "security_router", "scenarios_router"]
