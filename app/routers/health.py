"""Health check + on-demand TLS permission endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select

from ..config import settings
from ..db import AsyncSessionLocal
from ..models import Domain

router = APIRouter()


@router.get("/api/health")
async def health():
    return {"ok": True, "version": "12.0.0"}


@router.get("/api/tls-check", include_in_schema=False)
async def tls_check(request: Request, domain: str = ""):
    """Caddy's on-demand TLS ``ask`` hook: 200 lets Caddy fetch a certificate
    for ``domain``, anything else refuses. Only the main host(s) and domains a
    user has added (pending or verified) qualify, so strangers can't make the
    server request certificates for arbitrary hostnames."""
    name = domain.strip().lower().rstrip(".")
    if not name:
        return PlainTextResponse("missing domain", status_code=400)
    if name in settings.allowed_hosts:
        return PlainTextResponse("ok")
    async with AsyncSessionLocal() as db:
        found = (
            await db.execute(select(Domain.id).where(Domain.domain == name))
        ).scalar_one_or_none()
    if found is not None:
        return PlainTextResponse("ok")
    return PlainTextResponse("unknown domain", status_code=404)
