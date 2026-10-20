"""Session and token authentication routes for Defender Operator access."""

import hmac
import os
from typing import Optional
from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.api.auth import get_valid_operator_tokens, is_loopback_client
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    token: str = Field(..., min_length=1, max_length=256, description="Operator authorization token")


class AuthSessionResponse(BaseModel):
    authenticated: bool
    mode: str
    local_demo_mode: bool
    message: str


@router.post("/login", response_model=AuthSessionResponse)
def login_operator_session(req: LoginRequest, response: Response, request: Request) -> AuthSessionResponse:
    """Establish a secure same-origin operator session via HttpOnly cookie."""
    valid_tokens = get_valid_operator_tokens()

    if not valid_tokens:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Operator token is not configured on the server.",
        )

    if not any(hmac.compare_digest(req.token.strip(), vt) for vt in valid_tokens):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid operator token.",
        )

    # Issue secure same-origin HttpOnly session cookie
    response.set_cookie(
        key="optimus_operator_session",
        value=req.token.strip(),
        httponly=True,
        samesite="lax",
        secure=False,  # Permits localhost HTTP development
        path="/",
        max_age=86400,
    )

    return AuthSessionResponse(
        authenticated=True,
        mode="cookie_session",
        local_demo_mode=settings.LOCAL_DEMO_MODE,
        message="Operator session authenticated successfully.",
    )


@router.post("/logout", response_model=AuthSessionResponse)
def logout_operator_session(response: Response) -> AuthSessionResponse:
    """Clear operator session cookie."""
    response.delete_cookie(
        key="optimus_operator_session",
        path="/",
        httponly=True,
        samesite="lax",
    )
    return AuthSessionResponse(
        authenticated=False,
        mode="unauthenticated",
        local_demo_mode=settings.LOCAL_DEMO_MODE,
        message="Operator session terminated.",
    )


@router.get("/session", response_model=AuthSessionResponse)
def get_session_status(request: Request) -> AuthSessionResponse:
    """Check current operator authentication status."""
    cookie_token = request.cookies.get("optimus_operator_session")
    auth_header = request.headers.get("authorization")
    x_token = request.headers.get("x-operator-token")
    is_loopback = is_loopback_client(request)

    valid_tokens = get_valid_operator_tokens()

    # Check cookie
    if cookie_token and any(hmac.compare_digest(cookie_token, vt) for vt in valid_tokens):
        return AuthSessionResponse(
            authenticated=True,
            mode="cookie_session",
            local_demo_mode=settings.LOCAL_DEMO_MODE,
            message="Authenticated via secure session cookie.",
        )

    # Check header
    token = None
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
    elif x_token:
        token = x_token.strip()

    if token and any(hmac.compare_digest(token, vt) for vt in valid_tokens):
        return AuthSessionResponse(
            authenticated=True,
            mode="token_header",
            local_demo_mode=settings.LOCAL_DEMO_MODE,
            message="Authenticated via Authorization header.",
        )

    # Check loopback demo mode
    if settings.LOCAL_DEMO_MODE and is_loopback:
        return AuthSessionResponse(
            authenticated=True,
            mode="demo_loopback",
            local_demo_mode=True,
            message="Operating in local demo mode (loopback interface authorized).",
        )

    return AuthSessionResponse(
        authenticated=False,
        mode="unauthenticated",
        local_demo_mode=settings.LOCAL_DEMO_MODE,
        message="Unauthenticated. Login required.",
    )
