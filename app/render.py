"""HTML rendering helpers: standard template context and toast redirects."""
from __future__ import annotations

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .config import settings
from .deps import get_settings_cached
from .utils import flash

THEMES = [
    {"id": "default", "name": "Meadow"},
    {"id": "seasonal", "name": "Seasonal (changes monthly)"},
    {"id": "midnight", "name": "Midnight"},
    {"id": "sunset", "name": "Sunset"},
    {"id": "forest", "name": "Forest"},
    {"id": "ocean", "name": "Ocean"},
    {"id": "mono", "name": "Mono"},
]
THEME_IDS = {t["id"] for t in THEMES}


async def get_cfg(request: Request) -> dict:
    """Public site config: env defaults overridden by stored settings."""
    cfg = {
        "site_name": settings.SITE_NAME,
        "site_tagline": settings.SITE_TAGLINE,
        "base_url": settings.BASE_URL.rstrip("/"),
        "registration_open": settings.REGISTRATION_OPEN,
        "server_ip": "",
    }
    try:
        stored = await get_settings_cached(request)
        if stored.get("site_name"):
            cfg["site_name"] = stored["site_name"]
        if stored.get("site_tagline"):
            cfg["site_tagline"] = stored["site_tagline"]
        if "registration_open" in stored:
            cfg["registration_open"] = stored["registration_open"] == "1"
        if stored.get("server_ip"):
            cfg["server_ip"] = stored["server_ip"]
    except Exception:
        pass
    return cfg


async def T(request: Request, template_name: str, user=None, status: int = 200, **ctx) -> HTMLResponse:
    """Render a template with the standard context.

    Every template receives: ``request``, ``user``, ``cfg``, ``csrf``,
    ``toast``, ``toast_type``, and ``THEMES``.
    """
    try:
        status = int(status)
    except (TypeError, ValueError):
        raise ValueError(f"T(): status must be an int, got {status!r}")
    templates = request.app.state.templates
    qp = request.query_params
    path = request.url.path
    if path.startswith("/admin"):
        active = "admin"
    elif path.startswith("/links") or path.startswith("/s/"):
        active = "links"
    elif path.startswith("/bio") or path.startswith("/@"):
        active = "bio"
    elif path.startswith("/domains"):
        active = "domains"
    elif path.startswith("/files") or path.startswith("/uploads"):
        active = "files"
    elif path.startswith("/dashboard"):
        active = "dashboard"
    else:
        active = ""
    context = {
        "request": request,
        "user": user,
        "cfg": await get_cfg(request),
        "csrf": request.cookies.get("lp_csrf", ""),
        "toast": qp.get("toast"),
        "toast_type": qp.get("toast_type", "success"),
        "THEMES": THEMES,
        "active": active,
    }
    context.update(ctx)
    return templates.TemplateResponse(request, template_name, context, status_code=status)


def Redirect(url: str, toast: str | None = None, toast_type: str = "success") -> RedirectResponse:
    """303 redirect, optionally carrying a toast message."""
    if toast:
        url = flash(url, toast, toast_type)
    return RedirectResponse(url, status_code=303)
