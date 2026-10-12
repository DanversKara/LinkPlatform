"""Request dependencies: session auth, API tokens, CSRF, cached settings."""
from __future__ import annotations

import time
from typing import Optional
from urllib.parse import quote

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import utils
from .config import settings
from .db import AsyncSessionLocal, get_db
from .models import ApiToken, AuditLog, Session, Setting, User
from .security import constant_time_compare, get_client_ip, sha256_hex


class AuthRedirect(Exception):
    """Raised when an anonymous browser user hits a login-required page.

    Raising (instead of returning a redirect response) is what makes
    router-level ``Depends(require_user)`` actually enforce authentication:
    a returned response value from a dependency does NOT stop the endpoint
    from executing.
    """

    def __init__(self, url: str):
        super().__init__(url)
        self.url = url


async def get_current_user(
    request: Request, db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Return the logged-in user from the session cookie, or None. Never raises."""
    raw = request.cookies.get("lp_session", "")
    if not raw:
        return None
    try:
        row = (
            await db.execute(select(Session).where(Session.token_hash == sha256_hex(raw)))
        ).scalar_one_or_none()
        if row is None:
            return None
        if row.expires_at <= utils.utcnow():
            await db.delete(row)
            await db.commit()
            return None
        user = await db.get(User, row.user_id)
        if user is None or not user.is_active:
            return None
        request.state.user = user
        return user
    except Exception:
        return None


async def require_user(request: Request, db: AsyncSession = Depends(get_db)):
    """Require login. Returns the user; raises AuthRedirect (HTML) or 401 (API)."""
    user = await get_current_user(request, db)
    if user is None:
        if request.url.path.startswith("/api/"):
            raise HTTPException(status_code=401, detail="authentication required")
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        nxt = quote(target, safe="")
        qs = f"?next={nxt}" if nxt else ""
        raise AuthRedirect(f"/login{qs}")
    request.state.user = user
    return user


async def require_admin(request: Request, db: AsyncSession = Depends(get_db)):
    """Require an admin user. 403 otherwise (login redirect if anonymous HTML)."""
    user = await require_user(request, db)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin access required")
    request.state.user = user
    return user


async def get_api_user(
    request: Request, db: AsyncSession = Depends(get_db)
) -> tuple[User, ApiToken] | None:
    """Authenticate a ``Authorization: Bearer <token>`` API call."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    token = auth[7:].strip()
    if not token or len(token) > 160:
        return None
    try:
        row = (
            await db.execute(
                select(ApiToken).where(
                    ApiToken.token_hash == sha256_hex(token),
                    ApiToken.revoked == False,  # noqa: E712
                )
            )
        ).scalar_one_or_none()
        if row is None:
            return None
        user = await db.get(User, row.user_id)
        if user is None or not user.is_active:
            return None
        row.last_used_at = utils.utcnow()
        await db.commit()
        return (user, row)
    except Exception:
        try:
            await db.rollback()
        except Exception:
            pass
        return None


def require_api_scope(scope: str):
    """Dependency factory enforcing an API token scope."""

    async def _dep(request: Request, db: AsyncSession = Depends(get_db)) -> User:
        found = await get_api_user(request, db)
        if found is None:
            raise HTTPException(status_code=401, detail="invalid or missing API token")
        user, token = found
        if scope not in set(token.scopes.split()):
            raise HTTPException(status_code=403, detail=f"missing required scope: {scope}")
        return user

    return _dep


_CSRF_SKIP_PREFIXES = ("/api/v1", "/api/health")
_CSRF_SKIP_PATHS = {"/login", "/register"}


async def csrf_protect(request: Request):
    """CSRF check for state-changing HTML requests.

    Skipped for safe methods, the JSON API (bearer auth), and the
    login/register forms (no session exists yet). Everywhere else the
    ``lp_session`` cookie must be present and the ``x-csrf-token`` header
    (or ``_csrf`` form field) must match the ``lp_csrf`` cookie.
    """
    if request.method in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return
    path = request.url.path
    if path.startswith(_CSRF_SKIP_PREFIXES) or path in _CSRF_SKIP_PATHS:
        return
    if not request.cookies.get("lp_session"):
        raise HTTPException(status_code=403, detail="CSRF validation failed")
    token = request.headers.get("x-csrf-token", "")
    if not token:
        try:
            form = await request.form()
            value = form.get("_csrf", "")
            token = value if isinstance(value, str) else ""
        except Exception:
            token = ""
    cookie = request.cookies.get("lp_csrf", "")
    if not cookie or not token or not constant_time_compare(cookie, token):
        raise HTTPException(status_code=403, detail="CSRF validation failed")


_SETTINGS_TTL = 60.0


async def get_settings_cached(request: Request) -> dict[str, str]:
    """Read the settings table with a 60s in-memory TTL."""
    cache = request.app.state.settings_cache
    now = time.monotonic()
    if cache.get("expires", 0) > now:
        return cache["data"]
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(select(Setting))).scalars().all()
        data = {r.key: r.value for r in rows}
    request.app.state.settings_cache = {"expires": now + _SETTINGS_TTL, "data": data}
    return data


def clear_settings_cache(request_or_app) -> None:
    app = getattr(request_or_app, "app", request_or_app)
    app.state.settings_cache = {"expires": 0, "data": {}}


async def log_audit(
    db: AsyncSession,
    action: str,
    detail: str = "",
    actor_id: int | None = None,
    ip: str = "",
) -> None:
    """Append an audit log row. Flushes; the caller commits. Never raises."""
    try:
        db.add(
            AuditLog(
                action=action[:64],
                detail=detail[:2000],
                actor_id=actor_id,
                ip=ip[:64],
            )
        )
        await db.flush()
    except Exception:
        try:
            await db.rollback()
        except Exception:
            pass


def set_auth_cookies(response, session_token: str, csrf_token: str, request: Request) -> None:
    forwarded = request.headers.get("x-forwarded-proto", "") if settings.TRUST_PROXY else ""
    secure = settings.cookie_secure(request.url.scheme, forwarded)
    max_age = settings.SESSION_DAYS * 86400
    response.set_cookie(
        "lp_session", session_token, max_age=max_age, httponly=True,
        samesite="lax", secure=secure, path="/",
    )
    response.set_cookie(
        "lp_csrf", csrf_token, max_age=max_age, httponly=False,
        samesite="lax", secure=secure, path="/",
    )


def clear_auth_cookies(response) -> None:
    response.delete_cookie("lp_session", path="/")
    response.delete_cookie("lp_csrf", path="/")
