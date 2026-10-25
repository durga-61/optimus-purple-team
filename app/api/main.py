"""FastAPI application initialization and middleware configuration."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes.attacker import router as attacker_router
from app.api.routes.auth import router as auth_router
from app.api.routes.experiments import router as experiments_router
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

    # Disable browser caching on static HTML, JS, and CSS to prevent stale dashboard rendering
    @app.middleware("http")
    async def add_no_cache_headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if (
            path.startswith("/css")
            or path.startswith("/js")
            or path in ("/", "/index.html", "/operations", "/operations.html")
        ):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

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
    app.include_router(experiments_router, prefix="/api")

    # Three-Portal Routing & Operations Redirection
    frontend_dir = Path(__file__).resolve().parent.parent / "frontend"

    # Portal 1: Defender Portal
    @app.get("/")
    def get_defender_page():
        index_html = frontend_dir / "index.html"
        if index_html.exists():
            return FileResponse(str(index_html))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Defender Portal not found")

    # Portal 2: Sensor Transmitter Portal
    @app.get("/transmitter")
    @app.get("/transmitter/")
    def get_transmitter_page():
        transmitter_html = frontend_dir / "transmitter.html"
        if transmitter_html.exists():
            return FileResponse(str(transmitter_html))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sensor Transmitter Portal not found")

    # Portal 3: Attack Simulator Portal
    @app.get("/simulator")
    @app.get("/simulator/")
    def get_simulator_page():
        simulator_html = frontend_dir / "simulator.html"
        if simulator_html.exists():
            return FileResponse(str(simulator_html))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attack Simulator Portal not found")

    # Demo Sandbox Portal
    @app.get("/demo")
    @app.get("/demo/")
    def get_demo_page():
        demo_html = frontend_dir / "demo.html"
        if demo_html.exists():
            return FileResponse(str(demo_html))
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Demo Sandbox page not found")

    # Favicon routes (SVG vector icon)
    @app.get("/favicon.ico")
    @app.get("/favicon.svg")
    def get_favicon():
        favicon_svg = frontend_dir / "favicon.svg"
        if favicon_svg.exists():
            return FileResponse(str(favicon_svg), media_type="image/svg+xml")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Favicon not found")

    # Legacy /operations route permanently redirects to /transmitter
    @app.get("/operations")
    @app.get("/operations/")
    def redirect_operations_to_transmitter():
        return RedirectResponse(url="/transmitter", status_code=status.HTTP_307_TEMPORARY_REDIRECT)

    # Mount static assets directory
    if frontend_dir.exists():
        app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")

    return app


app = create_app()
