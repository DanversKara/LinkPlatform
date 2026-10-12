"""Landing page and user dashboard."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import csrf_protect, get_current_user, require_user
from ..models import Click, Link, ProfileView
from ..render import Redirect, T
from ..utils import svg_line_chart, utcnow

router = APIRouter(dependencies=[Depends(csrf_protect)])


@router.get("/")
async def index(request: Request, db: AsyncSession = Depends(get_db)):
    user = await get_current_user(request, db)
    if user:
        return Redirect("/dashboard")
    return await T(request, "index.html")


@router.get("/dashboard")
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user

    link_ids = (
        await db.execute(select(Link.id).where(Link.user_id == user.id))
    ).scalars().all()
    links_count = len(link_ids)
    total_clicks = (
        await db.execute(
            select(func.coalesce(func.sum(Link.clicks_cached), 0)).where(
                Link.user_id == user.id
            )
        )
    ).scalar_one()
    total_views = (
        await db.execute(
            select(func.count()).select_from(ProfileView).where(
                ProfileView.user_id == user.id
            )
        )
    ).scalar_one()

    days = [utcnow().date() - timedelta(days=i) for i in range(13, -1, -1)]
    labels = [d.strftime("%m-%d") for d in days]
    counts = [0] * 14
    if link_ids:
        since = utcnow() - timedelta(days=14)
        rows = (
            await db.execute(
                select(Click.ts).where(
                    Click.link_id.in_(link_ids), Click.ts >= since
                )
            )
        ).scalars().all()
        for ts in rows:
            idx = (ts.date() - days[0]).days
            if 0 <= idx < 14:
                counts[idx] += 1
    chart = svg_line_chart(list(zip(labels, counts)))

    top_links = (
        await db.execute(
            select(Link)
            .where(Link.user_id == user.id)
            .order_by(Link.clicks_cached.desc())
            .limit(5)
        )
    ).scalars().all()

    recent_clicks: list[dict] = []
    if link_ids:
        rows = (
            await db.execute(
                select(Click, Link.code)
                .join(Link, Click.link_id == Link.id)
                .where(Click.link_id.in_(link_ids))
                .order_by(Click.ts.desc())
                .limit(10)
            )
        ).all()
        recent_clicks = [
            {
                "ts": click.ts,
                "code": code,
                "device": click.device,
                "browser": click.browser,
                "referer": click.referer,
            }
            for click, code in rows
        ]

    return await T(
        request, "dashboard.html", user=user,
        links_count=links_count,
        clicks_total=int(total_clicks),
        views_total=int(total_views),
        ctr=None,
        chart_svg=chart,
        top_links=top_links,
        recent_clicks=recent_clicks,
    )
