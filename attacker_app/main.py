"""FastAPI Web Server for Part 2 AI Attacker Application.

Runs independently on port 8001. Interacts with Part 1 exclusively via HTTP.
Serves the Attacker Console UI and provides API endpoints for proposal generation,
human-in-the-loop approval, and execution.
"""

import hmac
import logging
import os
from pathlib import Path
from typing import Optional
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from attacker_app.config import config
from attacker_app.gateway_client import GatewayClientError
from attacker_app.schemas import (
    AttackFeedback,
    AttackProposal,
    AttackerHistoryItem,
    AttackerObservation,
    AttackerResetRequest,
    ExecuteAttackRequest,
    ProposalGenerationRequest,
    ProposalValidationResult,
    TokenLoginRequest,
)
from attacker_app.state import attacker_state

logger = logging.getLogger("attacker.api")

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def is_loopback(request: Request) -> bool:
    """Determine whether request originates strictly from loopback interface."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
        return client_ip in LOOPBACK_HOSTS

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip() in LOOPBACK_HOSTS

    if request.client and request.client.host:
        return request.client.host in LOOPBACK_HOSTS

    return True  # In-process test client defaults to loopback


def get_valid_attacker_keys() -> list[str]:
    """Retrieve all configured attacker API keys."""
    keys = []
    if config.ATTACKER_API_KEY:
        keys.append(config.ATTACKER_API_KEY)
    env_key = os.getenv("ATTACKER_API_KEY")
    if env_key and env_key not in keys:
        keys.append(env_key)
    return keys


def verify_attacker_access(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> str:
    """Validate authentication for Attacker API endpoints.

    If local demo mode is active and the request originates strictly from loopback,
    unauthenticated access is granted for local development convenience.
    Otherwise, a valid Bearer token, X-API-Key, or session cookie matching ATTACKER_API_KEY
    is strictly required.
    """
    valid_keys = get_valid_attacker_keys()
    is_loopback_client = is_loopback(request)
    cookie_token = request.cookies.get("optimus_attacker_session")

    # Opt-in local demo mode allowed ONLY on loopback interface when no credentials provided
    if config.LOCAL_DEMO_MODE and is_loopback_client and not authorization and not x_api_key and not cookie_token:
        return "local-demo-loopback"

    if not is_loopback_client and config.LOCAL_DEMO_MODE and not authorization and not x_api_key and not cookie_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Local demo mode is restricted to loopback interface. Remote requests require authentication.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not valid_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Attacker API authentication key is not configured on server.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = None
    if authorization:
        parts = authorization.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization scheme. Expected 'Bearer <token>'.",
                headers={"WWW-Authenticate": "Bearer"},
            )
    elif x_api_key:
        token = x_api_key.strip()
    elif cookie_token:
        token = cookie_token.strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header, X-API-Key, or attacker session cookie.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not any(hmac.compare_digest(token, vk) for vk in valid_keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unauthorized attacker API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token




app = FastAPI(
    title="AI Attacker & Adversarial Evaluation Console",
    description="Part 2 Adversarial Application for evaluating Organization Defender System.",
    version="1.0.0",
)

# Explicitly configured trusted CORS origins (not wildcard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

STATIC_DIR = Path(__file__).resolve().parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", include_in_schema=False)
def serve_attacker_portal():
    """Serve the standalone Attacker Console UI."""
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Attacker portal frontend file not found.",
        )
    return FileResponse(index_file, media_type="text/html")


@app.post("/api/attacker/auth/login")
def login_attacker_session(req: TokenLoginRequest, response: Response):
    """Establish a secure same-origin attacker console session via HttpOnly cookie."""
    valid_keys = get_valid_attacker_keys()
    if not valid_keys:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Attacker API key is not configured on server.",
        )

    if not any(hmac.compare_digest(req.token.strip(), vk) for vk in valid_keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid attacker API key.",
        )

    response.set_cookie(
        key="optimus_attacker_session",
        value=req.token.strip(),
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
        max_age=86400,
    )

    return {
        "authenticated": True,
        "mode": "cookie_session",
        "local_demo_mode": config.LOCAL_DEMO_MODE,
        "message": "Attacker session established successfully.",
    }


@app.post("/api/attacker/auth/logout")
def logout_attacker_session(response: Response):
    """Terminate the attacker console session and clear session cookie."""
    response.delete_cookie(
        key="optimus_attacker_session",
        path="/",
        httponly=True,
        samesite="lax",
    )
    return {
        "authenticated": False,
        "mode": "unauthenticated",
        "local_demo_mode": config.LOCAL_DEMO_MODE,
        "message": "Attacker session terminated.",
    }


@app.get("/api/attacker/auth/session")
def get_attacker_session_status(request: Request):
    """Check current attacker console authentication status."""
    valid_keys = get_valid_attacker_keys()
    cookie_token = request.cookies.get("optimus_attacker_session")
    auth_header = request.headers.get("authorization")
    x_token = request.headers.get("x-api-key")
    is_loopback_client = is_loopback(request)

    if cookie_token and any(hmac.compare_digest(cookie_token, vk) for vk in valid_keys):
        return {
            "authenticated": True,
            "mode": "cookie_session",
            "local_demo_mode": config.LOCAL_DEMO_MODE,
            "message": "Authenticated via secure session cookie.",
        }

    token = None
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    elif x_token:
        token = x_token.strip()

    if token and any(hmac.compare_digest(token, vk) for vk in valid_keys):
        return {
            "authenticated": True,
            "mode": "token_header",
            "local_demo_mode": config.LOCAL_DEMO_MODE,
            "message": "Authenticated via Authorization header.",
        }

    if config.LOCAL_DEMO_MODE and is_loopback_client:
        return {
            "authenticated": True,
            "mode": "demo_loopback",
            "local_demo_mode": True,
            "message": "Operating in local demo mode (loopback interface authorized).",
        }


    return {
        "authenticated": False,
        "mode": "unauthenticated",
        "local_demo_mode": config.LOCAL_DEMO_MODE,
        "message": "Authentication required.",
    }


@app.get("/api/attacker/status", dependencies=[Depends(verify_attacker_access)])
def get_attacker_status():
    """Check connectivity to Part 1 gateway and local state summary."""
    connected = False
    gateway_err = None
    try:
        attacker_state.fetch_observation()
        connected = True
    except Exception as e:
        gateway_err = str(e)

    return {
        "status": "online",
        "gateway_connected": connected,
        "gateway_error": gateway_err,
        "has_pending_proposal": attacker_state.pending_proposal is not None,
        "pending_proposal": attacker_state.pending_proposal.model_dump() if attacker_state.pending_proposal else None,
        "pending_proposal_id": attacker_state.pending_proposal_id,
        "pending_planner_label": attacker_state.pending_planner_label,
        "pending_strategy_rationale": attacker_state.pending_strategy_rationale,
        "pending_observed_telemetry": attacker_state.pending_observed_telemetry.model_dump() if attacker_state.pending_observed_telemetry else None,
        "pending_validation": attacker_state.pending_validation.model_dump() if attacker_state.pending_validation else None,
        "history_count": len(attacker_state.history),
        "experiments_count": len(attacker_state.experiments),
    }


@app.get("/api/attacker/observation", response_model=AttackerObservation, dependencies=[Depends(verify_attacker_access)])
def get_observation():
    """Fetch current restricted operational observation from the Part 1 gateway."""
    try:
        return attacker_state.fetch_observation()
    except GatewayClientError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to fetch observation from Attack Gateway: {e}",
        )


@app.post("/api/attacker/propose", dependencies=[Depends(verify_attacker_access)])
def generate_attack_proposal(req: ProposalGenerationRequest):
    """Generate candidate attack proposal via selected planner without executing."""
    try:
        (
            proposal,
            validation,
            planner_label,
            strategy_rationale,
            observed_telemetry,
        ) = attacker_state.generate_proposal(
            planner_type=req.planner,
            objective_hint=req.objective_hint,
        )
        return {
            "proposal_id": attacker_state.pending_proposal_id,
            "proposal": proposal.model_dump() if proposal else None,
            "validation": validation.model_dump(),
            "planner_label": planner_label,
            "strategy_rationale": strategy_rationale,
            "observed_telemetry": observed_telemetry.model_dump() if observed_telemetry else None,
            "message": "Candidate proposal generated. Human approval required before execution." if validation.valid else "Proposal was rejected or failed validation.",
        }
    except Exception as e:
        logger.error(f"Proposal generation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate attack proposal: {e}",
        )


@app.post("/api/attacker/execute", response_model=AttackFeedback, dependencies=[Depends(verify_attacker_access)])
def execute_attack(req: Optional[ExecuteAttackRequest] = None):
    """Human-in-the-loop action: Submit the pending validated proposal to Part 1 Attack Gateway."""
    proposal_id = req.proposal_id if req else None
    approved = req.approved if req else True
    try:
        feedback = attacker_state.execute_pending_proposal(proposal_id=proposal_id, approved=approved)
        return feedback
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except GatewayClientError as e:
        err_msg = str(e)
        if "HTTP 429" in err_msg:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=err_msg,
            )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Gateway execution error: {err_msg}",
        )


@app.post("/api/attacker/discard", dependencies=[Depends(verify_attacker_access)])
def discard_proposal():
    """Discard pending proposal without executing."""
    attacker_state.discard_pending_proposal()
    return {"message": "Pending proposal discarded."}


@app.get("/api/attacker/history", dependencies=[Depends(verify_attacker_access)])
def get_attack_history():
    """Return list of historical attack proposals and execution outcomes."""
    return [h.model_dump() for h in reversed(attacker_state.history)]


@app.get("/api/attacker/experiments", dependencies=[Depends(verify_attacker_access)])
def get_experiments():
    """Return immutable log of all executed adversarial evaluation experiments."""
    return [exp.model_dump() for exp in reversed(attacker_state.experiments)]


@app.post("/api/attacker/history/clear", dependencies=[Depends(verify_attacker_access)])
def clear_history():
    """Clear attacker proposal history and evaluation experiment records."""
    return attacker_state.clear_history()


@app.post("/api/attacker/reset", dependencies=[Depends(verify_attacker_access)])
def reset_system(req: Optional[AttackerResetRequest] = None):
    """Reset Part 1 Attack Gateway and local attacker state according to scope."""
    scope = req.scope if req else "all"
    res = attacker_state.reset(scope=scope)
    if not res.get("success", False):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=res.get("message", "Gateway reset failed."),
        )
    return res
