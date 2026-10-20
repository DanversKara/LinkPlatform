"""LinkPlatform v12 application entrypoint."""
from __future__ import annotations

import asyncio
import logging
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import settings
from .db import AsyncSessionLocal, backup_checkpoint, init_db
from .deps import AuthRedirect
from .models import Domain
from .render import T
from .routers import (
    admin,
    api_v1,
    auth,
    bio,
    dashboard,
    domains,
    files,
    health,
    links,
    redirect,
    reports,
    settings_user,
)
from .tracking import click_writer, flush_tracking

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("linkplatform")


def _scope_state(scope) -> dict:
    return scope.setdefault("state", {})


def _host_from_scope(scope) -> str:
    for key, value in scope.get("headers", []):
        if key.decode("latin-1").lower() == "host":
            return value.decode("latin-1").split(":")[0].lower()
    return ""


async def _verified_domain_map(app) -> dict[str, dict]:
    """Verified custom domains, cached 5 minutes on app.state."""
    cache = app.state.domain_cache
    now = time.monotonic()
    if cache["expires"] > now:
        return cache["hosts"]
    hosts: dict[str, dict] = {}
    try:
        async with AsyncSessionLocal() as db:
            rows = (
                await db.execute(select(Domain).where(Domain.status == "verified"))
            ).scalars().all()
            for d in rows:
                hosts[d.domain.lower()] = {
                    "id": d.id,
                    "domain": d.domain,
                    "root_url": d.root_url or "",
                    "notfound_url": d.notfound_url or "",
                }
    except Exception:
        log.exception("failed to load verified domains")
    app.state.domain_cache = {"expires": now + 300, "hosts": hosts}
    return hosts


async def _is_registered_domain(host: str) -> bool:
    if not host:
        return False
    try:
        async with AsyncSessionLocal() as db:
            return (
                await db.execute(select(Domain.id).where(Domain.domain == host))
            ).scalar_one_or_none() is not None
    except Exception:
        return False


class HostValidationMiddleware:
    """Reject requests whose Host header is not explicitly allowed."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            host = _host_from_scope(scope)
            path = scope.get("path")
            # The TLS ask hook is called by Caddy as http://app:8000.
            if path == "/api/tls-check":
                await self.app(scope, receive, send)
                return
            domain_hosts = await _verified_domain_map(scope["app"])
            allowed = host in settings.allowed_hosts or host in domain_hosts
            # Verifying a *pending* custom domain hits /api/health through it.
            if not allowed and path == "/api/health":
                allowed = await _is_registered_domain(host)
            if not allowed:
                resp = PlainTextResponse("Invalid host header", status_code=400)
                await resp(scope, receive, send)
                return
        await self.app(scope, receive, send)


class RequestIDMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            _scope_state(scope)["request_id"] = secrets.token_hex(8)
        await self.app(scope, receive, send)


class AccessLogMiddleware:
    """Minimal access logging; skips health checks and static assets."""

    def __init__(self, app):
        self.app = app
        self.logger = logging.getLogger("linkplatform.access")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path == "/api/health" or path.startswith("/static"):
            await self.app(scope, receive, send)
            return
        start = time.monotonic()
        status_holder: dict = {}

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        await self.app(scope, receive, send_wrapper)
        ms = (time.monotonic() - start) * 1000
        rid = _scope_state(scope).get("request_id", "-")
        self.logger.info(
            "%s %s -> %s %.1fms rid=%s",
            scope.get("method"), path, status_holder.get("status", "?"), ms, rid,
        )


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                names = {k.decode("latin-1").lower() for k, _ in headers}

                def add(name: str, value: str):
                    if name not in names:
                        headers.append((name.encode("latin-1"), value.encode("latin-1")))

                add("x-content-type-options", "nosniff")
                add("x-frame-options", "SAMEORIGIN")
                add("referrer-policy", "strict-origin-when-cross-origin")
                add(
                    "content-security-policy",
                    "default-src 'self'; img-src 'self' data: https:; "
                    "style-src 'self' 'unsafe-inline'; script-src 'self'; "
                    "font-src 'self' data:; connect-src 'self'",
                )
                add("permissions-policy", "camera=(), microphone=(), geolocation=()")
                if scope.get("scheme") == "https":
                    add("strict-transport-security",
                        "max-age=31536000; includeSubDomains")
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)


class DomainScopeMiddleware:
    """Attach the verified custom domain (if any) to the request scope.

    On a custom domain, ``/`` redirects to the domain's root URL (or 404s);
    short codes are scoped to that domain in the redirect router.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            host = _host_from_scope(scope)
            domain = (await _verified_domain_map(scope["app"])).get(host)
            state = _scope_state(scope)
            state["domain_id"] = domain["id"] if domain else None
            state["domain"] = domain
            if domain and scope.get("path") == "/":
                if domain["root_url"]:
                    resp = RedirectResponse(domain["root_url"], status_code=302)
                else:
                    resp = PlainTextResponse("Not found", status_code=404)
                await resp(scope, receive, send)
                return
        await self.app(scope, receive, send)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    task = asyncio.create_task(click_writer(app))
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    await flush_tracking()
    await backup_checkpoint()


app = FastAPI(
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.state.settings_cache = {"expires": 0, "data": {}}
app.state.domain_cache = {"expires": 0, "hosts": {}}
app.state.templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def _static_version() -> str:
    """Short hash of the static files, appended as ?v=… so browsers and
    CDNs (e.g. Cloudflare) fetch new CSS/JS after every upgrade."""
    import hashlib
    h = hashlib.sha1()
    for f in sorted(STATIC_DIR.rglob("*")):
        if f.is_file() and f.suffix in (".css", ".js"):
            h.update(f.name.encode())
            h.update(f.read_bytes())
    return h.hexdigest()[:10]


app.state.templates.env.globals["sv"] = _static_version()

# Added last = outermost. Outermost -> innermost order:
# HostValidation, RequestID, AccessLog, SecurityHeaders, DomainScope.
app.add_middleware(DomainScopeMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(AccessLogMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(HostValidationMiddleware)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(health.router)
app.include_router(api_v1.router)
app.include_router(redirect.router)
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(links.router)
app.include_router(bio.router)
app.include_router(domains.router)
app.include_router(files.router)
app.include_router(settings_user.router)
app.include_router(reports.router)
app.include_router(admin.router)
# Must stay last: /{code} only catches paths no real page claimed.
app.add_api_route("/{code}", redirect.bare_code_redirect, methods=["GET"],
                  include_in_schema=False)


@app.exception_handler(AuthRedirect)
async def auth_redirect_handler(request: Request, exc: AuthRedirect):
    return RedirectResponse(exc.url, status_code=303)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed."
        return JSONResponse({"error": detail}, status_code=exc.status_code)
    try:
        if exc.status_code == 404:
            return await T(request, "404.html", status=404)
        message = exc.detail if isinstance(exc.detail, str) else "An error occurred."
        return await T(request, "error.html", status=exc.status_code,
                       code=exc.status_code, message=message)
    except Exception:
        return PlainTextResponse("Server error", status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    log.exception("unhandled error rid=%s",
                  request.scope.get("state", {}).get("request_id", "-"))
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "internal server error"}, status_code=500)
    try:
        return await T(request, "error.html", status=500,
                       code=500, message="Something went wrong.")
    except Exception:
        return PlainTextResponse("Server error", status_code=500)
