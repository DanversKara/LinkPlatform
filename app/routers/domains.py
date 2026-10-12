"""Custom domains: claim, verify (via HTTP reachability), manage."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import csrf_protect, log_audit, require_user
from ..models import Domain, Link, User
from ..render import Redirect, T
from ..security import RateLimiter, get_client_ip, valid_domain, valid_url
from ..utils import utcnow

router = APIRouter(prefix="/domains", dependencies=[Depends(csrf_protect)])
domain_limiter = RateLimiter()


async def _get_domain(db: AsyncSession, domain_id: int, user: User) -> Domain | None:
    domain = await db.get(Domain, domain_id)
    if domain is None:
        return None
    if domain.user_id != user.id and user.role != "admin":
        return None
    return domain


@router.get("")
async def domains_list(request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    rows = (
        await db.execute(
            select(Domain)
            .where(Domain.user_id == user.id)
            .order_by(Domain.created_at.desc())
        )
    ).scalars().all()
    counts = {}
    if rows:
        for d in rows:
            counts[d.id] = (
                await db.execute(
                    select(func.count()).select_from(Link).where(Link.domain_id == d.id)
                )
            ).scalar_one()
    return await T(request, "domains/list.html", user=user, domains=rows,
                   link_counts=counts)


@router.get("/new")
async def domain_new_form(request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    return await T(request, "domains/form.html", user=user, domain=None)


@router.post("/new")
async def domain_create(
    request: Request,
    db: AsyncSession = Depends(get_db),
    domain: str = Form(""),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if not domain_limiter.allowed(f"domain:{user.id}", 10, 3600):
        return await T(request, "domains/form.html", user=user, domain=None,
                       error="Rate limit reached.", status=429)
    name = valid_domain(domain)
    if not name:
        return await T(request, "domains/form.html", user=user, domain=None,
                       error="Please enter a valid domain name (e.g. go.example.com).",
                       status=400, form={"domain": domain})
    db.add(Domain(user_id=user.id, domain=name, status="pending"))
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await T(request, "domains/form.html", user=user, domain=None,
                       error="That domain is already registered.", status=400,
                       form={"domain": domain})
    await log_audit(db, "domain_create", detail=f"domain={name}", actor_id=user.id,
                    ip=get_client_ip(request))
    await db.commit()
    return Redirect(
        "/domains",
        "Domain added. Point its DNS A record at this server, then click Verify.",
    )


@router.get("/{domain_id}")
async def domain_edit_form(domain_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    domain = await _get_domain(db, domain_id, user)
    if domain is None:
        return await T(request, "404.html", user=user, status=404)
    return await T(request, "domains/form.html", user=user, domain=domain)


@router.post("/{domain_id}")
async def domain_update(
    domain_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    root_url: str = Form(""),
    notfound_url: str = Form(""),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    domain = await _get_domain(db, domain_id, user)
    if domain is None:
        return await T(request, "404.html", user=user, status=404)

    async def _fail(msg: str):
        return await T(request, "domains/form.html", user=user, domain=domain,
                       error=msg, status=400)

    root = valid_url(root_url) if root_url.strip() else ""
    if root_url.strip() and not root:
        return await _fail("Root URL must be a valid http(s) URL or empty.")
    notfound = valid_url(notfound_url) if notfound_url.strip() else ""
    if notfound_url.strip() and not notfound:
        return await _fail("Not-found URL must be a valid http(s) URL or empty.")
    domain.root_url = root or ""
    domain.notfound_url = notfound or ""
    await db.commit()
    return Redirect("/domains", "Domain settings saved.")


@router.post("/{domain_id}/verify")
async def domain_verify(domain_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    domain = await _get_domain(db, domain_id, user)
    if domain is None:
        return await T(request, "404.html", user=user, status=404)
    if domain.status == "verified":
        return Redirect("/domains", "Domain is already verified.")
    ok = False
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                f"http://{domain.domain}/api/health",
                headers={"Host": domain.domain},
                follow_redirects=False,
            )
            ok = resp.status_code == 200 and resp.json().get("ok") is True
    except Exception:
        ok = False
    if ok:
        domain.status = "verified"
        domain.verified_at = utcnow()
        await log_audit(db, "domain_verify", detail=f"domain={domain.domain}",
                        actor_id=user.id, ip=get_client_ip(request))
        await db.commit()
        return Redirect("/domains", f"{domain.domain} verified.")
    return Redirect(
        "/domains",
        f"Could not reach http://{domain.domain}/api/health from here. "
        "Make sure the DNS A record points at this server and try again.",
        toast_type="error",
    )


@router.post("/{domain_id}/delete")
async def domain_delete(domain_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    domain = await _get_domain(db, domain_id, user)
    if domain is None:
        return await T(request, "404.html", user=user, status=404)
    name = domain.domain
    await db.execute(
        update(Link).where(Link.domain_id == domain.id).values(domain_id=None)
    )
    await db.delete(domain)
    await log_audit(db, "domain_delete", detail=f"domain={name}", actor_id=user.id,
                    ip=get_client_ip(request))
    await db.commit()
    return Redirect("/domains", "Domain removed. Its links now use the main domain.")
