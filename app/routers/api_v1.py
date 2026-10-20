"""JSON API v1 (bearer token auth). All errors use {"error": "..."}."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import require_api_scope
from ..models import BioLink, Click, Domain, Link, User
from ..render import THEME_IDS
from ..security import valid_code, valid_hex_color, valid_slug, valid_url
from ..utils import gen_code, paginate, short_url_for, utcnow

from .bio import RESERVED_SLUGS

router = APIRouter(prefix="/api/v1")

read = require_api_scope("links:read")
write = require_api_scope("links:write")


class LinkCreate(BaseModel):
    url: str
    code: str | None = None
    title: str = ""
    domain: str | None = None
    expires_at: datetime | None = None
    is_active: bool = True


class LinkUpdate(BaseModel):
    url: str | None = None
    title: str | None = None
    is_active: bool | None = None
    expires_at: datetime | None = None


class BioUpdate(BaseModel):
    display_name: str | None = None
    bio: str | None = None
    slug: str | None = None
    theme: str | None = None
    accent_color: str | None = None


def _short_url(request: Request, link: Link, domain_name: str | None = None) -> str:
    return short_url_for(request, link.code, domain_name)


async def _domain_name(db: AsyncSession, link: Link) -> str | None:
    if not link.domain_id:
        return None
    d = await db.get(Domain, link.domain_id)
    return d.domain if d else None


def _link_json(request: Request, link: Link, domain_name: str | None) -> dict:
    return {
        "id": link.id,
        "code": link.code,
        "url": link.original_url,
        "title": link.title,
        "short_url": _short_url(request, link, domain_name),
        "domain": domain_name,
        "is_active": link.is_active,
        "expires_at": link.expires_at.isoformat() if link.expires_at else None,
        "clicks": link.clicks_cached,
        "landing_enabled": link.landing_enabled,
        "created_at": link.created_at.isoformat() if link.created_at else None,
    }


async def _api_link(db: AsyncSession, user: User, id_or_code: str) -> Link | None:
    link = None
    if id_or_code.isdigit():
        link = await db.get(Link, int(id_or_code))
    if link is None and valid_code(id_or_code):
        link = (
            await db.execute(select(Link).where(Link.code == id_or_code))
        ).scalar_one_or_none()
    if link is not None and (link.user_id == user.id or user.role == "admin"):
        return link
    return None


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


@router.get("/me")
async def api_me(user: User = Depends(read)):
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "slug": user.slug,
        "role": user.role,
    }


@router.get("/links")
async def api_links_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(read),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
):
    stmt = select(Link).where(Link.user_id == user.id)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    pg = paginate(total, page, per_page)
    rows = (
        await db.execute(
            stmt.order_by(Link.created_at.desc())
            .offset(pg["offset"]).limit(pg["per_page"])
        )
    ).scalars().all()
    items = [_link_json(request, l, await _domain_name(db, l)) for l in rows]
    return {"items": items, "page": pg["page"], "per_page": pg["per_page"],
            "total": total, "pages": pg["pages"]}


@router.post("/links", status_code=201)
async def api_link_create(
    request: Request,
    payload: LinkCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(write),
):
    url = valid_url(payload.url)
    if not url:
        raise HTTPException(400, "Invalid url: must be an http(s) URL.")
    code = (payload.code or "").strip()
    if code:
        if not valid_code(code):
            raise HTTPException(400, "Invalid code: 3-64 chars, letters/numbers/-/_.")

        exists = (await db.execute(select(Link.id).where(Link.code == code))).scalar_one_or_none()
        if exists is not None:
            raise HTTPException(409, "Code is already taken.")
    else:
        for _ in range(10):
            code = gen_code(6)
            exists = (
                await db.execute(select(Link.id).where(Link.code == code))
            ).scalar_one_or_none()
            if exists is None:
                break
        else:
            raise HTTPException(500, "Could not generate a unique code.")
    domain_id = None
    if payload.domain:
        d = (
            await db.execute(select(Domain).where(Domain.domain == payload.domain.strip().lower()))
        ).scalar_one_or_none()
        if d is None or d.status != "verified" or (
            d.user_id != user.id and user.role != "admin"
        ):
            raise HTTPException(400, "Domain is not available.")
        domain_id = d.id
    expiry = _as_utc(payload.expires_at)
    if expiry is not None and expiry <= utcnow():
        raise HTTPException(400, "expires_at must be in the future.")
    link = Link(
        user_id=user.id, code=code, domain_id=domain_id, original_url=url,
        title=(payload.title or "")[:200], is_active=payload.is_active,
        expires_at=expiry,
    )
    db.add(link)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Code is already taken.")
    return _link_json(request, link, await _domain_name(db, link))


@router.get("/links/{id_or_code}")
async def api_link_get(
    id_or_code: str, request: Request,
    db: AsyncSession = Depends(get_db), user: User = Depends(read),
):
    link = await _api_link(db, user, id_or_code)
    if link is None:
        raise HTTPException(404, "Link not found.")
    return _link_json(request, link, await _domain_name(db, link))


@router.put("/links/{id_or_code}")
async def api_link_update(
    id_or_code: str, payload: LinkUpdate, request: Request,
    db: AsyncSession = Depends(get_db), user: User = Depends(write),
):
    link = await _api_link(db, user, id_or_code)
    if link is None:
        raise HTTPException(404, "Link not found.")
    if payload.url is not None:
        url = valid_url(payload.url)
        if not url:
            raise HTTPException(400, "Invalid url.")
        link.original_url = url
    if payload.title is not None:
        link.title = payload.title[:200]
    if payload.is_active is not None:
        link.is_active = bool(payload.is_active)
    if payload.expires_at is not None:
        expiry = _as_utc(payload.expires_at)
        if expiry <= utcnow():
            raise HTTPException(400, "expires_at must be in the future.")
        link.expires_at = expiry
    await db.commit()
    return _link_json(request, link, await _domain_name(db, link))


@router.delete("/links/{id_or_code}")
async def api_link_delete(
    id_or_code: str, db: AsyncSession = Depends(get_db), user: User = Depends(write),
):
    link = await _api_link(db, user, id_or_code)
    if link is None:
        raise HTTPException(404, "Link not found.")
    await db.delete(link)
    await db.commit()
    return {"ok": True}


@router.get("/links/{code}/stats")
async def api_link_stats(
    code: str, request: Request,
    db: AsyncSession = Depends(get_db), user: User = Depends(read),
):
    link = await _api_link(db, user, code)
    if link is None:
        raise HTTPException(404, "Link not found.")
    days = [utcnow().date() - timedelta(days=i) for i in range(29, -1, -1)]
    counts = [0] * 30
    since = utcnow() - timedelta(days=30)
    for ts in (
        await db.execute(
            select(Click.ts).where(Click.link_id == link.id, Click.ts >= since)
        )
    ).scalars().all():
        idx = (ts.date() - days[0]).days
        if 0 <= idx < 30:
            counts[idx] += 1
    return {
        "code": link.code,
        "total_clicks": link.clicks_cached,
        "daily": [
            {"date": d.isoformat(), "clicks": counts[i]} for i, d in enumerate(days)
        ],
    }


@router.get("/bio")
async def api_bio_get(db: AsyncSession = Depends(get_db), user: User = Depends(read)):
    links = (
        await db.execute(
            select(BioLink)
            .where(BioLink.user_id == user.id)
            .order_by(BioLink.position, BioLink.id)
        )
    ).scalars().all()
    return {
        "slug": user.slug,
        "display_name": user.display_name,
        "bio": user.bio,
        "theme": user.theme,
        "accent_color": user.accent_color,
        "avatar": user.avatar_path,
        "links": [
            {"id": l.id, "title": l.title, "url": l.url,
             "position": l.position, "is_active": l.is_active}
            for l in links
        ],
    }


@router.put("/bio")
async def api_bio_update(
    payload: BioUpdate, db: AsyncSession = Depends(get_db), user: User = Depends(write)
):
    if payload.display_name is not None:
        name = payload.display_name.strip()[:80]
        if not name:
            raise HTTPException(400, "display_name cannot be empty.")
        user.display_name = name
    if payload.bio is not None:
        user.bio = payload.bio.strip()[:500]
    if payload.slug is not None:
        slug = payload.slug.strip().lower()
        if not valid_slug(slug):
            raise HTTPException(400, "Invalid slug.")
        if slug != user.slug and slug in RESERVED_SLUGS:
            raise HTTPException(400, "Slug is reserved.")
        if slug != user.slug:
            taken = (
                await db.execute(select(User.id).where(User.slug == slug))
            ).scalar_one_or_none()
            if taken is not None:
                raise HTTPException(409, "Slug is already taken.")
            user.slug = slug
    if payload.theme is not None:
        if payload.theme not in THEME_IDS:
            raise HTTPException(400, "Invalid theme.")
        user.theme = payload.theme
    if payload.accent_color is not None:
        accent = valid_hex_color(payload.accent_color)
        if not accent:
            raise HTTPException(400, "accent_color must look like #6366f1.")
        user.accent_color = accent
    await db.commit()
    return {"ok": True, "slug": user.slug}
