"""Authentication: login, registration, logout, password change."""
from __future__ import annotations

import asyncio
import re
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_db
from ..deps import (
    clear_auth_cookies,
    csrf_protect,
    get_current_user,
    get_settings_cached,
    log_audit,
    require_user,
    set_auth_cookies,
)
from ..models import Session, User
from ..render import Redirect, T
from ..security import (
    RateLimiter,
    get_client_ip,
    hash_password,
    new_csrf_token,
    new_token,
    sha256_hex,
    valid_email,
    verify_password,
)
from ..utils import utcnow

router = APIRouter(dependencies=[Depends(csrf_protect)])
login_limiter = RateLimiter()
register_limiter = RateLimiter()

_SLUG_CLEAN = re.compile(r"[^a-z0-9_]+")


async def _unique_slug(db: AsyncSession, base: str) -> str:
    base = _SLUG_CLEAN.sub("_", base.lower()).strip("_") or "user"
    if len(base) < 3:
        base = (base + "_user")[:24]
    base = base[:24]
    slug = base
    i = 0
    while True:
        exists = (
            await db.execute(select(User.id).where(User.slug == slug))
        ).scalar_one_or_none()
        if exists is None:
            return slug
        i += 1
        slug = f"{base}_{i}"[:30]


async def _registration_open(request: Request) -> bool:
    stored = await get_settings_cached(request)
    return stored.get("registration_open", "1" if settings.REGISTRATION_OPEN else "0") == "1"


async def _create_session(
    db: AsyncSession, user: User, request: Request, ip: str
) -> tuple[str, str]:
    raw_token = new_token()
    csrf = new_csrf_token()
    db.add(
        Session(
            user_id=user.id,
            token_hash=sha256_hex(raw_token),
            csrf_token=csrf,
            expires_at=utcnow() + timedelta(days=settings.SESSION_DAYS),
            ip=ip[:64],
            ua=request.headers.get("user-agent", "")[:500],
        )
    )
    user.last_login_at = utcnow()
    await db.commit()
    return raw_token, csrf


@router.get("/login")
async def login_form(request: Request, db: AsyncSession = Depends(get_db)):
    user = await get_current_user(request, db)
    if user:
        return Redirect("/dashboard")
    return await T(request, "auth/login.html", next=request.query_params.get("next", ""))


@router.post("/login")
async def login_submit(
    request: Request,
    db: AsyncSession = Depends(get_db),
    email: str = Form(""),
    password: str = Form(""),
    next: str = Form(""),
):
    ip = get_client_ip(request)
    email_norm = valid_email(email)
    key = f"login:{ip}:{email_norm or 'invalid'}"
    if not login_limiter.allowed(key, 5, 300):
        return await T(
            request, "auth/login.html", status=429,
            error="Too many attempts. Please try again in a few minutes.", next=next,
            email=email,
        )
    user = None
    if email_norm:
        user = (
            await db.execute(select(User).where(User.email == email_norm))
        ).scalar_one_or_none()
    ok = False
    if user is not None and user.is_active:
        ok = await asyncio.to_thread(verify_password, password, user.password_hash)
    if not ok:
        await log_audit(db, "login_failed", detail=f"email={email_norm or 'invalid'}", ip=ip)
        await db.commit()
        return await T(
            request, "auth/login.html", status=401,
            error="Invalid email or password.", next=next, email=email,
        )
    raw_token, csrf = await _create_session(db, user, request, ip)
    await log_audit(db, "login", actor_id=user.id, ip=ip)
    await db.commit()
    if user.must_change_password:
        resp = Redirect("/change-password", "Please set a new password.")
    else:
        dest = next if next.startswith("/") and not next.startswith("//") else "/dashboard"
        resp = Redirect(dest, "Welcome back.")
    set_auth_cookies(resp, raw_token, csrf, request)
    return resp


@router.get("/register")
async def register_form(request: Request, db: AsyncSession = Depends(get_db)):
    user = await get_current_user(request, db)
    if user:
        return Redirect("/dashboard")
    if not await _registration_open(request):
        return await T(request, "auth/register.html", status=403,
                       error="Registration is currently closed.")
    return await T(request, "auth/register.html")


@router.post("/register")
async def register_submit(
    request: Request,
    db: AsyncSession = Depends(get_db),
    email: str = Form(""),
    password: str = Form(""),
    display_name: str = Form(""),
):
    if not await _registration_open(request):
        return await T(request, "auth/register.html", status=403,
                       error="Registration is currently closed.")
    ip = get_client_ip(request)
    if not register_limiter.allowed(f"register:{ip}", 10, 3600):
        return await T(request, "auth/register.html", status=429,
                       error="Too many attempts. Please try again later.",
                       email=email, display_name=display_name)
    email_norm = valid_email(email)
    name = display_name.strip()[:80]
    error = None
    if not email_norm:
        error = "Please enter a valid email address."
    elif len(password) < 10:
        error = "Password must be at least 10 characters."
    elif (await db.execute(select(User.id).where(User.email == email_norm))).scalar_one_or_none():
        error = "An account with that email already exists."
    if error:
        return await T(request, "auth/register.html", status=400, error=error,
                       email=email, display_name=display_name)
    slug = await _unique_slug(db, email_norm.split("@")[0])
    pw_hash = await asyncio.to_thread(hash_password, password)
    user = User(
        email=email_norm,
        password_hash=pw_hash,
        display_name=name or email_norm.split("@")[0],
        slug=slug,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await T(request, "auth/register.html", status=400,
                       error="An account with that email already exists.",
                       email=email, display_name=display_name)
    raw_token, csrf = await _create_session(db, user, request, ip)
    await log_audit(db, "register", actor_id=user.id, ip=ip)
    await db.commit()
    resp = Redirect("/dashboard", "Account created. Welcome!")
    set_auth_cookies(resp, raw_token, csrf, request)
    return resp


@router.post("/logout")
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    raw = request.cookies.get("lp_session", "")
    if raw:
        await db.execute(delete(Session).where(Session.token_hash == sha256_hex(raw)))
        await db.commit()
    resp = Redirect("/", toast="You have been signed out.")
    clear_auth_cookies(resp)
    return resp


@router.get("/change-password")
async def change_password_form(request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    return await T(request, "auth/change_password.html", user=user,
                   forced=user.must_change_password)


@router.post("/change-password")
async def change_password_submit(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    forced = user.must_change_password

    async def _fail(msg: str, status: int = 400):
        return await T(request, "auth/change_password.html", user=user,
                       status=status, error=msg, forced=forced)

    if not forced:
        # Voluntary change from settings: prove you know the current password.
        # The forced flow (must_change_password) just authenticated with the
        # temporary password, so there is nothing to re-prove — and the form
        # does not even render the field.
        if not await asyncio.to_thread(verify_password, current_password, user.password_hash):
            return await _fail("Current password is incorrect.")
    if len(new_password) < 10:
        return await _fail("New password must be at least 10 characters.")
    if new_password != confirm_password:
        return await _fail("New passwords do not match.")
    user.password_hash = await asyncio.to_thread(hash_password, new_password)
    user.must_change_password = False
    raw = request.cookies.get("lp_session", "")
    await db.execute(
        delete(Session).where(
            Session.user_id == user.id, Session.token_hash != sha256_hex(raw)
        )
    )
    await log_audit(db, "password_change", actor_id=user.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/dashboard", "Password updated.")
