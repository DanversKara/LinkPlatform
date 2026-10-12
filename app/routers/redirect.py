"""Public short-link redirects. Kept fast: the only await is the
non-blocking tracking enqueue."""
from __future__ import annotations

import re

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from ..config import settings
from ..db import AsyncSessionLocal
from ..models import Link
from ..render import THEMES
from ..security import get_client_ip, hash_ip
from ..tracking import ClickEvent, enqueue_click
from ..utils import parse_ua, utcnow

router = APIRouter()

_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


async def _not_found(request: Request, domain: dict | None):
    if domain and domain.get("notfound_url"):
        return RedirectResponse(domain["notfound_url"], status_code=302)
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request,
        "404.html",
        {
            "request": request,
            "user": None,
            "cfg": {"site_name": settings.SITE_NAME,
                    "site_tagline": settings.SITE_TAGLINE,
                    "base_url": settings.BASE_URL.rstrip("/"),
                    "registration_open": settings.REGISTRATION_OPEN},
            "csrf": "",
            "toast": None,
            "toast_type": "success",
            "THEMES": THEMES,
        },
        status_code=404,
    )


@router.get("/s/{code}")
async def short_redirect(code: str, request: Request):
    if not _CODE_RE.fullmatch(code):
        return await _not_found(request, request.scope.get("state", {}).get("domain"))
    state = request.scope.get("state", {})
    domain_id = state.get("domain_id")
    domain = state.get("domain")

    async with AsyncSessionLocal() as db:
        stmt = select(Link).where(Link.code == code, Link.is_active == True)  # noqa: E712
        if domain_id:
            stmt = stmt.where(Link.domain_id == domain_id)
        else:
            stmt = stmt.where(Link.domain_id.is_(None))
        link = (await db.execute(stmt)).scalar_one_or_none()

    now = utcnow()
    if link is None or (link.expires_at is not None and link.expires_at <= now):
        return await _not_found(request, domain)

    ip = get_client_ip(request)
    ua = request.headers.get("user-agent", "")[:500]
    device, browser, os_name = parse_ua(ua)
    await enqueue_click(
        ClickEvent(
            link_id=link.id,
            ip_hash=hash_ip(ip, settings.SECRET_KEY),
            ua=ua,
            referer=request.headers.get("referer", "")[:2048],
            device=device,
            browser=browser,
            os_name=os_name,
            ts=now,
        )
    )

    if link.landing_enabled:
        templates = request.app.state.templates
        return templates.TemplateResponse(
            request,
            "landing.html",
            {
                "request": request,
                "user": None,
                "cfg": {"site_name": settings.SITE_NAME,
                        "site_tagline": settings.SITE_TAGLINE,
                        "base_url": settings.BASE_URL.rstrip("/"),
                        "registration_open": settings.REGISTRATION_OPEN},
                "csrf": "",
                "toast": None,
                "toast_type": "success",
                "THEMES": THEMES,
                "link": link,
            },
        )
    return RedirectResponse(link.original_url, status_code=302)
