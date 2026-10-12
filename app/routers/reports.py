"""Abuse reports against bio profiles."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select

from ..db import AsyncSessionLocal, get_db
from ..deps import csrf_protect, get_current_user, log_audit
from ..models import Report, User
from ..render import Redirect, T
from ..security import RateLimiter, get_client_ip, valid_email, valid_slug

router = APIRouter(dependencies=[Depends(csrf_protect)])
report_limiter = RateLimiter()


@router.get("/report/{slug}")
async def report_form(slug: str, request: Request, db=Depends(get_db)):
    user = await get_current_user(request, db)
    if not valid_slug(slug):
        return await T(request, "404.html", user=user, status=404)
    async with AsyncSessionLocal() as sdb:
        target = (
            await sdb.execute(
                select(User).where(User.slug == slug, User.is_active == True)  # noqa: E712
            )
        ).scalar_one_or_none()
    if target is None:
        return await T(request, "404.html", user=user, status=404)
    return await T(request, "report.html", user=user, target_slug=slug)


@router.get("/report")
async def report_form_generic(request: Request, db=Depends(get_db)):
    user = await get_current_user(request, db)
    return await T(request, "report.html", user=user, target_slug="")


@router.post("/report/{slug}")
async def report_submit(
    slug: str,
    request: Request,
    reason: str = Form(""),
    reporter_email: str = Form(""),
):
    return await _submit_report(request, slug, reason, reporter_email)


@router.post("/report")
async def report_submit_generic(
    request: Request,
    reason: str = Form(""),
    reporter_email: str = Form(""),
):
    return await _submit_report(request, "", reason, reporter_email)


async def _submit_report(request: Request, slug: str, reason: str,
                         reporter_email: str):
    ip = get_client_ip(request)
    back = f"/@{slug}" if slug else "/report"
    if not report_limiter.allowed(f"report:{ip}", 5, 3600):
        return Redirect(back, "Too many reports. Try again later.",
                        toast_type="error")
    reason = reason.strip()
    email_in = reporter_email.strip()
    email = valid_email(email_in) if email_in else ""
    if not (10 <= len(reason) <= 500):
        return Redirect(back, "Reason must be 10-500 characters.",
                        toast_type="error")
    if email_in and not email:
        return Redirect(back, "Reporter email is invalid.", toast_type="error")
    async with AsyncSessionLocal() as db:
        if slug:
            target = (
                await db.execute(
                    select(User).where(User.slug == slug, User.is_active == True)  # noqa: E712
                )
            ).scalar_one_or_none()
            if target is None:
                return Redirect("/", "Profile not found.", toast_type="error")
        db.add(Report(target_slug=slug, reporter_email=email or "", reason=reason))
        await log_audit(db, "report_create", detail=f"target={slug or '-'}", ip=ip)
        await db.commit()
    return Redirect(back, "Report submitted. Thank you.")
