"""User settings: profile, password, and API tokens."""
from __future__ import annotations

import asyncio
import secrets

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import csrf_protect, log_audit, require_user
from ..models import ApiToken, User
from ..render import Redirect, T
from ..security import (
    RateLimiter,
    get_client_ip,
    hash_password,
    sha256_hex,
    valid_email,
    verify_password,
)
from ..utils import utcnow

router = APIRouter(dependencies=[Depends(csrf_protect)])
token_limiter = RateLimiter()

API_SCOPES = ["links:read", "links:write", "bio:read", "bio:write"]


@router.get("/settings")
@router.get("/settings/profile")
async def settings_form(request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    return await T(request, "settings/profile.html", user=user)


@router.post("/settings")
@router.post("/settings/profile")
async def settings_update(
    request: Request,
    db: AsyncSession = Depends(get_db),
    display_name: str = Form(""),
    email: str = Form(""),
    email_password: str = Form(""),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    name = display_name.strip()[:80]
    if not name:
        return await T(request, "settings/profile.html", user=user, status=400,
                       error="Display name cannot be empty.")
    # A blank email means "unchanged".
    email_norm = valid_email(email) if email.strip() else user.email
    if not email_norm:
        return await T(request, "settings/profile.html", user=user, status=400,
                       error="Please enter a valid email address.")
    if email_norm != user.email:
        # Changing the login email requires the current password.
        if not verify_password(email_password, user.password_hash):
            return await T(request, "settings/profile.html", user=user, status=400,
                           error="Enter your current password to change your email.")
        taken = (
            await db.execute(select(User.id).where(User.email == email_norm))
        ).scalar_one_or_none()
        if taken is not None:
            return await T(request, "settings/profile.html", user=user, status=400,
                           error="That email is already in use.")
        user.email = email_norm
        await log_audit(db, "email_change", actor_id=user.id, ip=get_client_ip(request))
    user.display_name = name
    await log_audit(db, "profile_update", actor_id=user.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/settings", "Profile updated.")


@router.post("/settings/password")
async def settings_password(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user

    async def _fail(msg: str):
        return await T(request, "settings/profile.html", user=user, status=400,
                       error=msg)

    if not await asyncio.to_thread(verify_password, current_password, user.password_hash):
        return await _fail("Current password is incorrect.")
    if len(new_password) < 10:
        return await _fail("New password must be at least 10 characters.")
    if new_password != confirm_password:
        return await _fail("New passwords do not match.")
    user.password_hash = await asyncio.to_thread(hash_password, new_password)
    await log_audit(db, "password_change", actor_id=user.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/settings", "Password updated.")


@router.get("/settings/tokens")
async def tokens_list(request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    tokens = (
        await db.execute(
            select(ApiToken)
            .where(ApiToken.user_id == user.id)
            .order_by(ApiToken.created_at.desc())
        )
    ).scalars().all()
    return await T(request, "settings/tokens.html", user=user, tokens=tokens,
                   scopes=API_SCOPES)


@router.post("/settings/tokens")
async def token_create(
    request: Request,
    db: AsyncSession = Depends(get_db),
    name: str = Form(""),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if not token_limiter.allowed(f"token:{user.id}", 20, 3600):
        return Redirect("/settings/tokens", "Rate limit reached.", toast_type="error")
    name = name.strip()[:60]
    if not name:
        return Redirect("/settings/tokens", "Token name is required.", toast_type="error")
    form = await request.form()
    scopes = [s for s in API_SCOPES if form.get(f"scope_{s}")]
    if not scopes:
        return Redirect("/settings/tokens", "Select at least one scope.",
                        toast_type="error")
    raw = "lp_" + secrets.token_urlsafe(32)
    token = ApiToken(
        user_id=user.id,
        name=name,
        prefix=raw[:12],
        token_hash=sha256_hex(raw),
        scopes=" ".join(scopes),
    )
    db.add(token)
    await log_audit(db, "token_create", detail=f"name={name} scopes={' '.join(scopes)}",
                    actor_id=user.id, ip=get_client_ip(request))
    await db.commit()
    return await T(request, "settings/token_created.html", user=user,
                   token_secret=raw, token_name=name, scopes=scopes)


@router.post("/settings/tokens/{token_id}/revoke")
async def token_revoke(token_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    token = await db.get(ApiToken, token_id)
    if token is None or token.user_id != user.id:
        return Redirect("/settings/tokens", "Token not found.", toast_type="error")
    token.revoked = True
    await log_audit(db, "token_revoke", detail=f"name={token.name}",
                    actor_id=user.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/settings/tokens", "Token revoked.")
