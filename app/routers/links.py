"""Link management: create, edit, delete, toggle, stats, QR, landing pages."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import csrf_protect, log_audit, require_user
from ..models import Click, Domain, Link, StoredFile, User
from ..render import Redirect, T
from ..security import RateLimiter, get_client_ip, valid_code, valid_url
from ..utils import gen_code, paginate, short_url_for, qr_png_bytes, ref_domain, svg_bars, svg_line_chart, utcnow

router = APIRouter(prefix="/links", dependencies=[Depends(csrf_protect)])
create_limiter = RateLimiter()


async def _get_link(db: AsyncSession, link_id: int, user: User) -> Link | None:
    link = await db.get(Link, link_id)
    if link is None:
        return None
    if link.user_id != user.id and user.role != "admin":
        return None
    return link


async def _verified_domains(db: AsyncSession, user: User) -> list[Domain]:
    stmt = select(Domain).where(Domain.status == "verified")
    if user.role != "admin":
        stmt = stmt.where(Domain.user_id == user.id)
    return (await db.execute(stmt.order_by(Domain.domain))).scalars().all()


async def _resolve_domain(db: AsyncSession, user: User, domain_id: str) -> Domain | None:
    try:
        did = int(domain_id)
    except (TypeError, ValueError):
        return None
    domain = await db.get(Domain, did)
    if domain is None or domain.status != "verified":
        return None
    if domain.user_id != user.id and user.role != "admin":
        return None
    return domain


def _short_url(request: Request, link: Link, domain_name: str | None = None) -> str:
    return short_url_for(request, link.code, domain_name)


def _parse_expiry(value: str) -> datetime | None:
    """Parse datetime-local or date input. Returns aware UTC or raises ValueError."""
    value = (value or "").strip()
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError("invalid date")


async def _unique_code(db: AsyncSession) -> str:
    for _ in range(10):
        code = gen_code(6)
        exists = (
            await db.execute(select(Link.id).where(Link.code == code))
        ).scalar_one_or_none()
        if exists is None:
            return code
    raise RuntimeError("could not generate a unique code")


@router.get("")
async def links_list(
    request: Request, db: AsyncSession = Depends(get_db),
    q: str = "", page: int = 1,
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    stmt = select(Link).where(Link.user_id == user.id)
    if q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                Link.code.ilike(like),
                Link.title.ilike(like),
                Link.original_url.ilike(like),
            )
        )
    total = (
        await db.execute(select(func.count()).select_from(stmt.subquery()))
    ).scalar_one()
    pg = paginate(total, page, 20)
    rows = (
        await db.execute(
            stmt.order_by(Link.created_at.desc())
            .offset(pg["offset"])
            .limit(pg["per_page"])
        )
    ).scalars().all()
    domain_names = {}
    if rows:
        dids = {r.domain_id for r in rows if r.domain_id}
        if dids:
            drows = (
                await db.execute(select(Domain).where(Domain.id.in_(dids)))
            ).scalars().all()
            domain_names = {d.id: d.domain for d in drows}
    short_urls = {
        r.id: _short_url(request, r, domain_names.get(r.domain_id)) for r in rows
    }
    return await T(request, "links/list.html", user=user, links=rows,
                   q=q, pg=pg, pagination=pg, domain_names=domain_names,
                   short_urls=short_urls)


@router.get("/new")
async def link_new_form(request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    domains = await _verified_domains(db, user)
    # ?url=… prefill (from the homepage "Shorten" box)
    prefill = request.query_params.get("url", "").strip()[:2048]
    return await T(request, "links/form.html", user=user, link=None,
                   is_new=True, user_domains=domains, errors={}, prefill_url=prefill)


@router.post("/new")
async def link_create(
    request: Request,
    db: AsyncSession = Depends(get_db),
    original_url: str = Form(""),
    code: str = Form(""),
    title: str = Form(""),
    domain_id: str = Form(""),
    expires_at: str = Form(""),
    is_active: str | None = Form(None),
    landing_enabled: str | None = Form(None),
    landing_title: str = Form(""),
    landing_body: str = Form(""),
    landing_image: str = Form(""),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if not create_limiter.allowed(f"linkcreate:{user.id}", 60, 3600):
        domains = await _verified_domains(db, user)
        return await T(request, "links/form.html", user=user, link=None,
                       is_new=True, user_domains=domains,
                       errors={"form": "Rate limit reached. Please slow down."},
                       status=429)

    def _form_link():
        return SimpleNamespace(
            original_url=original_url, code=code, title=title,
            domain_id=int(domain_id) if domain_id.strip().isdigit() else None,
            expires_at=expires_at, is_active=is_active is not None,
            landing_enabled=landing_enabled is not None,
            landing_title="", landing_body="", landing_image="",
        )

    async def _fail(msg: str, status: int = 400):
        domains = await _verified_domains(db, user)
        return await T(request, "links/form.html", user=user, link=_form_link(),
                       is_new=True, user_domains=domains,
                       errors={"form": msg}, status=status)

    url = valid_url(original_url)
    if not url:
        return await _fail("Please enter a valid http(s) URL.")
    code = code.strip()
    if code:
        if not valid_code(code):
            return await _fail("Custom code must be 3-64 chars: letters, numbers, - and _.")
        exists = (
            await db.execute(select(Link.id).where(Link.code == code))
        ).scalar_one_or_none()
        if exists is not None:
            return await _fail("That code is already taken.")
    else:
        code = await _unique_code(db)
    domain = None
    if domain_id.strip():
        domain = await _resolve_domain(db, user, domain_id)
        if domain is None:
            return await _fail("Selected domain is not available.")
    try:
        expiry = _parse_expiry(expires_at)
    except ValueError:
        return await _fail("Expiry date is invalid.")
    if expiry is not None and expiry <= utcnow():
        return await _fail("Expiry must be in the future.")
    link = Link(
        user_id=user.id,
        code=code,
        domain_id=domain.id if domain else None,
        original_url=url,
        title=title.strip()[:200],
        is_active=is_active is not None,
        expires_at=expiry,
        landing_enabled=landing_enabled is not None,
        landing_title=landing_title.strip()[:160],
        landing_body=landing_body.strip()[:2000],
        landing_image=(valid_url(landing_image) or "")[:2048] if landing_image.strip() else "",
    )
    db.add(link)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await _fail("That code is already taken.")
    await log_audit(db, "link_create", detail=f"code={code}", actor_id=user.id,
                    ip=get_client_ip(request))
    await db.commit()
    return Redirect(f"/links/{link.id}", "Link created.")


@router.get("/{link_id}")
async def link_edit_form(link_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    link = await _get_link(db, link_id, user)
    if link is None:
        return await T(request, "404.html", user=user, status=404)
    domains = await _verified_domains(db, user)
    files = (
        await db.execute(
            select(StoredFile)
            .where(StoredFile.user_id == user.id)
            .order_by(StoredFile.created_at.desc())
            .limit(50)
        )
    ).scalars().all()
    domain_names = {}
    if link.domain_id:
        d = await db.get(Domain, link.domain_id)
        if d:
            domain_names[d.id] = d.domain
    return await T(request, "links/form.html", user=user, link=link,
                   is_new=False, user_domains=domains, errors={},
                   short_url=_short_url(request, link, domain_names.get(link.domain_id)))


@router.get("/{link_id}/edit")
async def link_edit_form_alias(link_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    return await link_edit_form(link_id, request, db)


@router.post("/{link_id}")
@router.post("/{link_id}/edit")
async def link_update(
    link_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    original_url: str = Form(""),
    code: str = Form(""),
    title: str = Form(""),
    domain_id: str = Form(""),
    expires_at: str = Form(""),
    is_active: str | None = Form(None),
    landing_enabled: str | None = Form(None),
    landing_title: str = Form(""),
    landing_body: str = Form(""),
    landing_image: str = Form(""),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    link = await _get_link(db, link_id, user)
    if link is None:
        return await T(request, "404.html", user=user, status=404)

    async def _fail(msg: str, status: int = 400):
        domains = await _verified_domains(db, user)
        return await T(request, "links/form.html", user=user, link=link,
                       is_new=False, user_domains=domains,
                       errors={"form": msg}, status=status)

    url = valid_url(original_url)
    if not url:
        return await _fail("Please enter a valid http(s) URL.")
    code = code.strip()
    if not valid_code(code):
        return await _fail("Code must be 3-64 chars: letters, numbers, - and _.")
    if code != link.code:
        exists = (
            await db.execute(select(Link.id).where(Link.code == code))
        ).scalar_one_or_none()
        if exists is not None:
            return await _fail("That code is already taken.")
    domain = None
    if domain_id.strip():
        domain = await _resolve_domain(db, user, domain_id)
        if domain is None:
            return await _fail("Selected domain is not available.")
    try:
        expiry = _parse_expiry(expires_at)
    except ValueError:
        return await _fail("Expiry date is invalid.")
    if expiry is not None and expiry <= utcnow():
        return await _fail("Expiry must be in the future.")
    link.original_url = url
    link.code = code
    link.title = title.strip()[:200]
    link.domain_id = domain.id if domain else None
    link.expires_at = expiry
    link.is_active = is_active is not None
    link.landing_enabled = landing_enabled is not None
    link.landing_title = landing_title.strip()[:160]
    link.landing_body = landing_body.strip()[:2000]
    img_in = landing_image.strip()
    link.landing_image = (valid_url(img_in) or "")[:2048] if img_in else ""
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        return await _fail("That code is already taken.")
    await log_audit(db, "link_update", detail=f"code={code}", actor_id=user.id,
                    ip=get_client_ip(request))
    await db.commit()
    return Redirect(f"/links/{link.id}", "Link updated.")


@router.get("/{link_id}/delete")
async def link_delete_form(link_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    link = await _get_link(db, link_id, user)
    if link is None:
        return await T(request, "404.html", user=user, status=404)
    return await T(request, "links/delete.html", user=user, link=link)


@router.post("/{link_id}/delete")
async def link_delete(link_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    link = await _get_link(db, link_id, user)
    if link is None:
        return await T(request, "404.html", user=user, status=404)
    code = link.code
    await db.delete(link)
    await log_audit(db, "link_delete", detail=f"code={code}", actor_id=user.id,
                    ip=get_client_ip(request))
    await db.commit()
    return Redirect("/links", "Link deleted.")


@router.post("/{link_id}/toggle")
async def link_toggle(link_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    link = await _get_link(db, link_id, user)
    if link is None:
        return await T(request, "404.html", user=user, status=404)
    link.is_active = not link.is_active
    await db.commit()
    return Redirect(f"/links/{link.id}",
                    "Link enabled." if link.is_active else "Link disabled.")


@router.get("/{link_id}/stats")
async def link_stats(link_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    link = await _get_link(db, link_id, user)
    if link is None:
        return await T(request, "404.html", user=user, status=404)

    days = [utcnow().date() - timedelta(days=i) for i in range(29, -1, -1)]
    labels = [d.strftime("%m-%d") for d in days]
    counts = [0] * 30
    since = utcnow() - timedelta(days=30)
    clicks = (
        await db.execute(
            select(Click).where(Click.link_id == link.id, Click.ts >= since)
        )
    ).scalars().all()
    ref_counter: Counter = Counter()
    dev_counter: Counter = Counter()
    brw_counter: Counter = Counter()
    os_counter: Counter = Counter()
    ctry_counter: Counter = Counter()
    for c in clicks:
        idx = (c.ts.date() - days[0]).days
        if 0 <= idx < 30:
            counts[idx] += 1
        rd = ref_domain(c.referer)
        ref_counter[rd or "(direct)"] += 1
        dev_counter[c.device or "Unknown"] += 1
        brw_counter[c.browser or "Unknown"] += 1
        os_counter[c.os_name or "Unknown"] += 1
        ctry_counter[c.country or "Unknown"] += 1
    chart = svg_line_chart(list(zip(labels, counts)))
    ref_bars = svg_bars(ref_counter.most_common(8))

    recent = (
        await db.execute(
            select(Click)
            .where(Click.link_id == link.id)
            .order_by(Click.ts.desc())
            .limit(20)
        )
    ).scalars().all()
    seven_days_ago = utcnow() - timedelta(days=7)
    clicks_7d = sum(1 for c in clicks if c.ts >= seven_days_ago)
    unique_ips = len({c.ip_hash for c in clicks if c.ip_hash})
    domain_name = None
    if link.domain_id:
        d = await db.get(Domain, link.domain_id)
        domain_name = d.domain if d else None
    return await T(
        request, "links/stats.html", user=user, link=link,
        chart_svg_30d=chart, ref_bars=ref_bars,
        total=link.clicks_cached,
        clicks_30d=len(clicks),
        clicks_7d=clicks_7d,
        unique_ips=unique_ips,
        top_referers=ref_counter.most_common(10),
        top_devices=dev_counter.most_common(8),
        top_browsers=brw_counter.most_common(8),
        top_countries=ctry_counter.most_common(8),
        recent=recent,
        short_url=_short_url(request, link, domain_name),
    )


@router.get("/{link_id}/qr.png")
async def link_qr(link_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    link = await _get_link(db, link_id, user)
    if link is None:
        return await T(request, "404.html", user=user, status=404)
    domain_name = None
    if link.domain_id:
        d = await db.get(Domain, link.domain_id)
        domain_name = d.domain if d else None
    png = qr_png_bytes(_short_url(request, link, domain_name))
    return Response(content=png, media_type="image/png",
                    headers={"Cache-Control": "public, max-age=86400"})
