"""Attack Gateway API routes (Security Boundary between Part 1 and Part 2).

This module provides the strictly restricted, whitelist-enforced HTTP gateway through which
the external Part 2 AI Attacker requests simulated attacks and receives controlled feedback.
No internal DefenderService or simulator state is exposed.
"""

import hmac
import logging
import os
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status

from app.config import settings
from app.api.schemas import (
    AttackerAttackRequest,
    AttackerFeedbackResponse,
    AttackerObservationResponse,
    AttackerResetResponse,
)
from app.api.state import app_state
from app.simulator.scenarios import (
    inject_capacity_manipulation,
    inject_coordinated_manipulation,
    inject_inventory_manipulation,
    inject_multi_source_manipulation,
    inject_replay_attack,
    inject_sensor_spoofing,
)

logger = logging.getLogger("api.attack_gateway")


def verify_gateway_token(authorization: Optional[str] = Header(None)) -> str:
    """Validate Bearer token for Attack Gateway endpoints.

    Enforces that every /api/attacker/* request provides a valid Bearer token
    matching the server-configured ATTACK_GATEWAY_TOKEN environment variable.
    Returns HTTP 401 if missing, malformed, or invalid.
    Uses constant-time comparison to prevent timing attacks.
    """
    configured_token = os.getenv("ATTACK_GATEWAY_TOKEN") or settings.ATTACK_GATEWAY_TOKEN
    if not configured_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Attack Gateway authentication token is not configured on server.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization scheme. Expected 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = parts[1].strip()
    if not hmac.compare_digest(token, configured_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unauthorized gateway token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token


router = APIRouter(
    prefix="/attacker",
    tags=["Attack Gateway"],
    dependencies=[Depends(verify_gateway_token)],
)

# In-memory attack tracking and rate limiting (thread-safe)
_state_lock = threading.Lock()
_attack_counter: int = 0
_attack_history: Dict[str, AttackerFeedbackResponse] = {}

# Simple sliding-window rate limiter: max 15 requests per 60 seconds per client IP
RATE_LIMIT_MAX_REQUESTS = 15
RATE_LIMIT_WINDOW_SECONDS = 60
_rate_limit_records: Dict[str, List[float]] = defaultdict(list)


def check_rate_limit(client_ip: str) -> None:
    """Enforce a simple sliding-window rate limit on gateway requests."""
    now = time.time()
    with _state_lock:
        timestamps = _rate_limit_records[client_ip]
        # Prune timestamps older than window
        _rate_limit_records[client_ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW_SECONDS]
        if len(_rate_limit_records[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
            logger.warning(f"Rate limit exceeded for client {client_ip} on Attack Gateway.")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Maximum {RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_WINDOW_SECONDS} seconds.",
            )
        _rate_limit_records[client_ip].append(now)


@router.get("/observation", response_model=AttackerObservationResponse)
def get_attacker_observation() -> AttackerObservationResponse:
    """Retrieve restricted operational observation tailored specifically for the AI Attacker.
    
    Exposes only intentionally selected operational metrics.
    Does NOT expose ML scores, C1/C2/C3 definitions, thresholds, temporal states, or graph topology.
    """
    obs = app_state.warehouse.get_current_observation()
    return AttackerObservationResponse(
        target=app_state.warehouse.warehouse_id,
        inventory=obs.inventory,
        free_capacity=obs.free_capacity,
        temperature=obs.temperature,
        humidity=obs.humidity,
        occupancy=obs.occupancy,
    )


@router.post("/attack", response_model=AttackerFeedbackResponse)
def execute_attacker_attack(request: Request, body: AttackerAttackRequest) -> AttackerFeedbackResponse:
    """Execute a controlled, whitelisted simulated attack through the gateway adapter.
    
    Translates validated attack request to one of the 6 deterministic scenario mechanisms,
    evaluates via DefenderService, and returns strictly restricted feedback.
    """
    # 1. Rate limiting check
    client_ip = request.client.host if request.client else "127.0.0.1"
    check_rate_limit(client_ip)

    global _attack_counter
    with app_state._lock, _state_lock:
        _attack_counter += 1
        attack_id = f"ATK-{_attack_counter:04d}"

        # 2. Step warehouse to obtain up-to-date baseline observation
        base_obs = app_state.warehouse.step()

        # 3. Translate validated request into existing controlled scenario
        attack_type = body.attack_type
        target = body.target
        if attack_type == "capacity_manipulation":
            if target == "capacity":
                val = body.value if body.value is not None else 30.0
                attacked_obs = inject_capacity_manipulation(base_obs, total_capacity=val)
            else:
                val = body.value if body.value is not None else 40.0
                attacked_obs = inject_capacity_manipulation(base_obs, reported_free_capacity=val)
        elif attack_type == "inventory_manipulation":
            val = body.value if body.value is not None else 25.0
            attacked_obs = inject_inventory_manipulation(base_obs, manipulated_inventory=val)
        elif attack_type == "sensor_spoofing":
            if target == "temperature":
                val = body.value if body.value is not None else 28.0
                attacked_obs = inject_sensor_spoofing(base_obs, spoofed_temperature=val, spoofed_humidity=None)
            elif target == "humidity":
                val = body.value if body.value is not None else 95.0
                attacked_obs = inject_sensor_spoofing(base_obs, spoofed_temperature=None, spoofed_humidity=val)
            else:  # environmental_sensors
                temp_val = body.value if body.value is not None else 28.0
                attacked_obs = inject_sensor_spoofing(base_obs, spoofed_temperature=temp_val, spoofed_humidity=95.0)
        elif attack_type == "replay_attack":
            if app_state.warehouse.step_count <= 1:
                evolved = app_state.warehouse.step(inbound=3.0, outbound=0.0)
                app_state.defender.analyze(evolved)
            base_obs = app_state.warehouse.step()
            past_obs = app_state.warehouse.history[0]
            attacked_obs = inject_replay_attack(current_obs=base_obs, previous_obs=past_obs)
        elif attack_type == "coordinated_weak":
            delta = body.value if body.value is not None else -2.0
            attacked_obs = inject_coordinated_manipulation(
                base_obs,
                inventory_delta=delta,
                reported_free_capacity_delta=abs(delta) / 2,
            )
        elif attack_type == "multi_source":
            attacked_obs = inject_multi_source_manipulation(base_obs)
        else:
            # Pydantic schema validation rejects non-whitelisted types before this line
            raise HTTPException(status_code=400, detail=f"Unrecognized attack type: {attack_type}")

        # 4. Inject mutated observation into simulator and evaluate via DefenderService
        app_state.warehouse.inject_observation(attacked_obs)
        analysis = app_state.defender.analyze(attacked_obs)

        # 5. Formulate restricted feedback (hides internal pipeline details)
        classification = analysis.decision.classification
        detection_status = "DETECTED" if classification != "NORMAL" else "UNDETECTED"

        # Record missed attack in defender's self-hardening engine without leaking state or auto-activating
        if detection_status == "UNDETECTED":
            miss_report = app_state.defender.hardening_engine.record_miss(
                observation=attacked_obs,
                analysis=analysis,
                attack_type=attack_type,
                target=body.target,
                value=body.value,
                step=attacked_obs.step,
            )
            # Generate candidate proposal (held in PENDING_VALIDATION; operator approval strictly required)
            app_state.defender.hardening_engine.generate_proposal(miss_report)

        expose_classification = (
            os.getenv("GATEWAY_EXPOSE_CLASSIFICATION", "").lower() in ("true", "1", "yes")
            or settings.GATEWAY_EXPOSE_CLASSIFICATION
        )

        feedback = AttackerFeedbackResponse(
            attack_id=attack_id,
            execution="accepted",
            detection=detection_status,
            classification=classification if expose_classification else None,
        )

        _attack_history[attack_id] = feedback

        logger.info(
            f"Attack Gateway executed: id={attack_id}, type={attack_type}, "
            f"target={body.target}, objective='{body.objective}', "
            f"detection={detection_status}, "
            f"classification={'shielded' if not expose_classification else classification}"
        )

        return feedback


@router.get("/result/{attack_id}", response_model=AttackerFeedbackResponse)
def get_attack_result(attack_id: str) -> AttackerFeedbackResponse:
    """Retrieve restricted feedback for a previously submitted attack by unique ID."""
    clean_id = attack_id.strip().upper()
    with _state_lock:
        if clean_id not in _attack_history:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Attack ID '{attack_id}' not found.",
            )
        return _attack_history[clean_id]


@router.post("/reset", response_model=AttackerResetResponse)
def reset_attacker_environment() -> AttackerResetResponse:
    """Reset the warehouse simulation and defender pipeline to baseline state."""
    global _attack_counter
    with app_state._lock, _state_lock:
        app_state.reset()
        _attack_history.clear()
        _attack_counter = 0
        _rate_limit_records.clear()
        logger.info("Attack Gateway reset environment to initial baseline.")

    return AttackerResetResponse(
        success=True,
        message="Simulator and DefenderService successfully reset to baseline.",
    )
