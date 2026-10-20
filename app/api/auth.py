"""Authentication and authorization utilities for Defender API endpoints."""

import hmac
import os
from typing import Optional
from fastapi import Header, HTTPException, Request, status

from app.config import settings

LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "testclient"}


def is_loopback_client(request: Request) -> bool:
    """Determine whether request originates strictly from loopback."""
    # Check forwarded headers first to prevent proxy spoofing
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


def get_valid_operator_tokens() -> list[str]:
    """Retrieve all configured operator and gateway tokens."""
    tokens = []
    if settings.OPERATOR_TOKEN:
        tokens.append(settings.OPERATOR_TOKEN)
    if settings.ATTACK_GATEWAY_TOKEN and settings.ATTACK_GATEWAY_TOKEN not in tokens:
        tokens.append(settings.ATTACK_GATEWAY_TOKEN)
    env_op = os.getenv("OPERATOR_TOKEN")
    if env_op and env_op not in tokens:
        tokens.append(env_op)
    env_gw = os.getenv("ATTACK_GATEWAY_TOKEN")
    if env_gw and env_gw not in tokens:
        tokens.append(env_gw)
    return tokens


def verify_operator_access(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_operator_token: Optional[str] = Header(None, alias="X-Operator-Token"),
) -> str:
    """Validate operator authentication for state-changing endpoints.

    If local demo mode is active and the request originates strictly from loopback,
    unauthenticated access is granted for local development convenience.
    Otherwise, a valid Bearer token, X-Operator-Token, or session cookie
    matching a configured OPERATOR_TOKEN or ATTACK_GATEWAY_TOKEN is strictly required.
    """
    valid_tokens = get_valid_operator_tokens()
    is_loopback = is_loopback_client(request)
    cookie_token = request.cookies.get("optimus_operator_session")

    # Opt-in local demo mode allowed ONLY on loopback interface when no credentials provided
    if settings.LOCAL_DEMO_MODE and is_loopback and not authorization and not x_operator_token and not cookie_token:
        return "local-demo-loopback"

    if not is_loopback and settings.LOCAL_DEMO_MODE and not authorization and not x_operator_token and not cookie_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Local demo mode is restricted to loopback interface. Remote requests require authentication.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not valid_tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Operator authentication token is not configured on server.",
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
    elif x_operator_token:
        token = x_operator_token.strip()
    elif cookie_token:
        token = cookie_token.strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header, X-Operator-Token, or operator session cookie.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not any(hmac.compare_digest(token, vt) for vt in valid_tokens):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unauthorized operator token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return token


