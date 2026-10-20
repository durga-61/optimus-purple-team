"""FastAPI application initialization and middleware configuration."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes.attacker import router as attacker_router
from app.api.routes.auth import router as auth_router
from app.api.routes.health import router as health_router
from app.api.routes.scenarios import router as scenarios_router
from app.api.routes.security import router as security_router
from app.api.routes.warehouse import router as warehouse_router
from app.api.state import app_state
from app.config import settings

logger = logging.getLogger("api.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler managing application startup and shutdown."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    # Verify app_state baseline
    if app_state.warehouse is None or app_state.defender is None:
        app_state.reset()
    yield
    logger.info("Shutting down Organization Information Security Platform.")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="REST API for Organization Security Monitoring & Attack Simulation",
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # CORS configuration for trusted local frontend origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # Global Exception Handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled server error at {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "detail": "An unexpected error occurred during request processing.",
            },
        )

    # Register API Route Routers under /api
    app.include_router(health_router, prefix="/api")
    app.include_router(auth_router, prefix="/api")
    app.include_router(warehouse_router, prefix="/api")
    app.include_router(security_router, prefix="/api")
    app.include_router(scenarios_router, prefix="/api")
    app.include_router(attacker_router, prefix="/api")

    # Explicit routes for Live Operations & Sensor Monitor
    frontend_dir = Path(__file__).resolve().parent.parent / "frontend"

    @app.get("/operations")
    @app.get("/operations/")
    def get_operations_page():
        operations_html = frontend_dir / "operations.html"
        if operations_html.exists():
            return FileResponse(str(operations_html))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Operations page not found")

    # Mount Organization Security Portal frontend
    if frontend_dir.exists():
        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

    return app


app = create_app()
