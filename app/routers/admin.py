"""Admin panel: overview, users, links, domains, reports, files, settings, audit."""
from __future__ import annotations

import ipaddress
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import clear_settings_cache, csrf_protect, log_audit, require_admin
from ..models import (
    AuditLog,
    Click,
    Domain,
    Link,
    ProfileView,
    Report,
    Setting,
    StoredFile,
    User,
)
from ..render import Redirect, T
from ..security import get_client_ip
from ..utils import paginate, svg_line_chart, utcnow

from .files import delete_stored_file

router = APIRouter(
    prefix="/admin", dependencies=[Depends(require_admin), Depends(csrf_protect)]
)


def _admin(request: Request) -> User:
    return request.state.user


def _fmt_size(n: int) -> str:
    n = int(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n:.1f} TB"


async def _other_admin_exists(db: AsyncSession, exclude_id: int) -> bool:    return (
        await db.execute(
            select(func.count())
            .select_from(User)
            .where(User.role == "admin", User.is_active == True, User.id != exclude_id)  # noqa: E712
        )
    ).scalar_one() > 0


@router.get("")
async def admin_index(request: Request, db: AsyncSession = Depends(get_db)):
    user = _admin(request)
    users = (await db.execute(select(func.count()).select_from(User))).scalar_one()
    links = (await db.execute(select(func.count()).select_from(Link))).scalar_one()
    clicks = (await db.execute(select(func.count()).select_from(Click))).scalar_one()
    views = (await db.execute(select(func.count()).select_from(ProfileView))).scalar_one()
    reports_open = (
        await db.execute(
            select(func.count()).select_from(Report).where(Report.status == "open")
        )
    ).scalar_one()

    days = [utcnow().date() - timedelta(days=i) for i in range(13, -1, -1)]
    labels = [d.strftime("%m-%d") for d in days]
    click_counts = [0] * 14
    signup_counts = [0] * 14
    since = utcnow() - timedelta(days=14)
    for ts in (
        await db.execute(select(Click.ts).where(Click.ts >= since))
    ).scalars().all():
        idx = (ts.date() - days[0]).days
        if 0 <= idx < 14:
            click_counts[idx] += 1
    for ts in (
        await db.execute(select(User.created_at).where(User.created_at >= since))
    ).scalars().all():
        idx = (ts.date() - days[0]).days
        if 0 <= idx < 14:
            signup_counts[idx] += 1
    clicks_chart = svg_line_chart(list(zip(labels, click_counts)))
    signups_chart = svg_line_chart(list(zip(labels, signup_counts)))

    recent_audit = (
        await db.execute(select(AuditLog).order_by(AuditLog.ts.desc()).limit(10))
    ).scalars().all()
    return await T(
        request, "admin/dashboard.html", user=user,
        users_count=users, links_count=links, clicks_count=clicks,
        views_count=views, reports_open=reports_open,
        chart_svg=clicks_chart, audit_lines=recent_audit,
    )


@router.get("/users")
async def admin_users(
    request: Request, db: AsyncSession = Depends(get_db), q: str = "", page: int = 1
):
    user = _admin(request)
    stmt = select(User)
    if q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(User.email.ilike(like), User.display_name.ilike(like),
                User.slug.ilike(like))
        )
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    pg = paginate(total, page, 25)
    rows = (
        await db.execute(
            stmt.order_by(User.created_at.desc()).offset(pg["offset"]).limit(pg["per_page"])
        )
    ).scalars().all()
    return await T(request, "admin/users.html", user=user, users=rows, q=q, pg=pg,
                   total=total)


@router.post("/users/{user_id}/toggle-active")
@router.post("/users/{user_id}/toggle")
async def admin_user_toggle(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    admin = _admin(request)
    target = await db.get(User, user_id)
    if target is None:
        return Redirect("/admin/users", "User not found.", toast_type="error")
    if target.id == admin.id:
        return Redirect("/admin/users", "You cannot deactivate yourself.",
                        toast_type="error")
    target.is_active = not target.is_active
    await log_audit(db, "user_toggle_active",
                    detail=f"user={target.email} active={target.is_active}",
                    actor_id=admin.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/admin/users", "User updated.")


@router.post("/users/{user_id}/verify")
async def admin_user_verify(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    """Give or remove the "Verified" badge on a user's bio page."""
    admin = _admin(request)
    target = await db.get(User, user_id)
    if target is None:
        return Redirect("/admin/users", "User not found.", toast_type="error")
    target.is_verified = not target.is_verified
    await log_audit(db, "user_verify",
                    detail=f"user={target.email} verified={target.is_verified}",
                    actor_id=admin.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/admin/users",
                    f"{target.display_name or target.email} is now verified." if target.is_verified
                    else f"Removed verification from {target.display_name or target.email}.")


@router.post("/users/{user_id}/set-role")
@router.post("/users/{user_id}/role")
async def admin_user_role(
    user_id: int, request: Request, db: AsyncSession = Depends(get_db),
    role: str = Form(""),
):
    admin = _admin(request)
    target = await db.get(User, user_id)
    if target is None:
        return Redirect("/admin/users", "User not found.", toast_type="error")
    if role not in ("user", "admin"):
        return Redirect("/admin/users", "Invalid role.", toast_type="error")
    if target.id == admin.id:
        return Redirect("/admin/users", "You cannot change your own role.",
                        toast_type="error")
    if target.role == "admin" and role != "admin":
        if not await _other_admin_exists(db, target.id):
            return Redirect("/admin/users",
                            "Cannot demote the last active admin.", toast_type="error")
    target.role = role
    await log_audit(db, "user_set_role", detail=f"user={target.email} role={role}",
                    actor_id=admin.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/admin/users", "Role updated.")


@router.post("/users/{user_id}/delete")
async def admin_user_delete(user_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    admin = _admin(request)
    target = await db.get(User, user_id)
    if target is None:
        return Redirect("/admin/users", "User not found.", toast_type="error")
    if target.id == admin.id:
        return Redirect("/admin/users", "You cannot delete yourself.", toast_type="error")
    if target.role == "admin" and not await _other_admin_exists(db, target.id):
        return Redirect("/admin/users", "Cannot delete the last active admin.",
                        toast_type="error")
    for f in (
        await db.execute(select(StoredFile).where(StoredFile.user_id == target.id))
    ).scalars().all():
        delete_stored_file(f)
    email = target.email
    await db.delete(target)
    await log_audit(db, "user_delete", detail=f"user={email}", actor_id=admin.id,
                    ip=get_client_ip(request))
    await db.commit()
    return Redirect("/admin/users", "User deleted.")


@router.get("/links")
async def admin_links(
    request: Request, db: AsyncSession = Depends(get_db), q: str = "", page: int = 1
):
    user = _admin(request)
    stmt = select(Link, User.email).join(User, Link.user_id == User.id)
    if q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(Link.code.ilike(like), Link.title.ilike(like),
                Link.original_url.ilike(like), User.email.ilike(like))
        )
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    pg = paginate(total, page, 25)
    rows = (
        await db.execute(
            stmt.order_by(Link.created_at.desc()).offset(pg["offset"]).limit(pg["per_page"])
        )
    ).all()
    links = []
    for l, e in rows:
        l.owner_email = e
        links.append(l)
    return await T(request, "admin/links.html", user=user,
                   links=links, q=q, pg=pg, total=total)


@router.post("/links/{link_id}/toggle")
async def admin_link_toggle(link_id: int, request: Request,
                            db: AsyncSession = Depends(get_db)):
    admin = _admin(request)
    link = await db.get(Link, link_id)
    if link is None:
        return Redirect("/admin/links", "Link not found.", toast_type="error")
    link.is_active = not link.is_active
    await log_audit(db, "link_toggle",
                    detail=f"code={link.code} active={link.is_active}",
                    actor_id=admin.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/admin/links", "Link updated.")


@router.post("/links/{link_id}/delete")
async def admin_link_delete(link_id: int, request: Request,
                            db: AsyncSession = Depends(get_db)):
    admin = _admin(request)
    link = await db.get(Link, link_id)
    if link is None:
        return Redirect("/admin/links", "Link not found.", toast_type="error")
    code = link.code
    await db.delete(link)
    await log_audit(db, "link_delete", detail=f"code={code}",
                    actor_id=admin.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/admin/links", "Link deleted.")


@router.get("/domains")
async def admin_domains(request: Request, db: AsyncSession = Depends(get_db)):
    user = _admin(request)
    rows = (
        await db.execute(
            select(Domain, User.email)
            .join(User, Domain.user_id == User.id)
            .order_by(Domain.created_at.desc())
        )
    ).all()
    domains = []
    for d, e in rows:
        d.owner_email = e
        domains.append(d)
    return await T(request, "admin/domains.html", user=user, domains=domains)


@router.post("/domains/{domain_id}/approve")
async def admin_domain_approve(domain_id: int, request: Request,
                               db: AsyncSession = Depends(get_db)):
    admin = _admin(request)
    domain = await db.get(Domain, domain_id)
    if domain is None:
        return Redirect("/admin/domains", "Domain not found.", toast_type="error")
    domain.status = "verified"
    domain.verified_at = utcnow()
    await log_audit(db, "domain_approve", detail=f"domain={domain.domain}",
                    actor_id=admin.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/admin/domains", "Domain approved.")


@router.post("/domains/{domain_id}/reject")
@router.post("/domains/{domain_id}/delete")
async def admin_domain_reject(domain_id: int, request: Request,
                              db: AsyncSession = Depends(get_db)):
    admin = _admin(request)
    domain = await db.get(Domain, domain_id)
    if domain is None:
        return Redirect("/admin/domains", "Domain not found.", toast_type="error")
    name = domain.domain
    await db.execute(
        update(Link).where(Link.domain_id == domain.id).values(domain_id=None)
    )
    await db.delete(domain)
    await log_audit(db, "domain_reject", detail=f"domain={name}",
                    actor_id=admin.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/admin/domains", "Domain rejected and removed.")


@router.get("/reports")
async def admin_reports(
    request: Request, db: AsyncSession = Depends(get_db),
    status: str = "open", page: int = 1,
):
    user = _admin(request)
    stmt = select(Report)
    if status in ("open", "resolved"):
        stmt = stmt.where(Report.status == status)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    pg = paginate(total, page, 25)
    rows = (
        await db.execute(
            stmt.order_by(Report.created_at.desc()).offset(pg["offset"]).limit(pg["per_page"])
        )
    ).scalars().all()
    return await T(request, "admin/reports.html", user=user, reports=rows,
                   pg=pg, total=total)


@router.post("/reports/{report_id}/resolve")
async def admin_report_resolve(report_id: int, request: Request,
                               db: AsyncSession = Depends(get_db)):
    admin = _admin(request)
    report = await db.get(Report, report_id)
    if report is None:
        return Redirect("/admin/reports", "Report not found.", toast_type="error")
    report.status = "resolved"
    await log_audit(db, "report_resolve", detail=f"report={report.id}",
                    actor_id=admin.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/admin/reports", "Report resolved.")


@router.post("/reports/{report_id}/delete")
async def admin_report_delete(report_id: int, request: Request,
                              db: AsyncSession = Depends(get_db)):
    _admin(request)
    report = await db.get(Report, report_id)
    if report is None:
        return Redirect("/admin/reports", "Report not found.", toast_type="error")
    await db.delete(report)
    await db.commit()
    return Redirect("/admin/reports", "Report deleted.")


@router.get("/files")
async def admin_files(request: Request, db: AsyncSession = Depends(get_db), page: int = 1):
    user = _admin(request)
    stmt = select(StoredFile, User.email).join(User, StoredFile.user_id == User.id)
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    pg = paginate(total, page, 25)
    rows = (
        await db.execute(
            stmt.order_by(StoredFile.created_at.desc())
            .offset(pg["offset"]).limit(pg["per_page"])
        )
    ).all()
    files = []
    total_size = 0
    for f, e in rows:
        f.owner_email = e
        files.append(f)
        total_size += f.size or 0
    grand_total_size = (
        await db.execute(select(func.coalesce(func.sum(StoredFile.size), 0)))
    ).scalar_one()
    return await T(request, "admin/files.html", user=user,
                   files=files, pg=pg, total=total,
                   total_size=_fmt_size(grand_total_size))


@router.post("/files/{file_id}/delete")
async def admin_file_delete(file_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    admin = _admin(request)
    row = await db.get(StoredFile, file_id)
    if row is None:
        return Redirect("/admin/files", "File not found.", toast_type="error")
    delete_stored_file(row)
    await db.delete(row)
    await log_audit(db, "file_delete", detail=f"name={row.stored_name}",
                    actor_id=admin.id, ip=get_client_ip(request))
    await db.commit()
    return Redirect("/admin/files", "File deleted.")


@router.get("/settings")
async def admin_settings_form(request: Request, db: AsyncSession = Depends(get_db)):
    user = _admin(request)
    rows = (await db.execute(select(Setting))).scalars().all()
    values = {r.key: r.value for r in rows}
    return await T(request, "admin/settings.html", user=user, values=values)


@router.post("/settings")
async def admin_settings_save(
    request: Request,
    db: AsyncSession = Depends(get_db),
    site_name: str = Form(""),
    site_tagline: str = Form(""),
    registration_open: str | None = Form(None),
    click_retention_days: str = Form("90"),
    server_ip: str = Form(""),
    smtp_host: str = Form(""),
    smtp_port: str = Form("587"),
    smtp_user: str = Form(""),
    smtp_password: str = Form(""),
    smtp_from: str = Form(""),
):
    user = _admin(request)

    async def _fail(msg: str):
        rows = (await db.execute(select(Setting))).scalars().all()
        return await T(request, "admin/settings.html", user=user,
                       values={r.key: r.value for r in rows},
                       error=msg, status=400)

    site_name = site_name.strip()[:60]
    site_tagline = site_tagline.strip()[:160]
    if not site_name:
        return await _fail("Site name cannot be empty.")
    try:
        retention = int(click_retention_days)
        if not 1 <= retention <= 3650:
            raise ValueError()
    except ValueError:
        return await _fail("Click retention must be 1-3650 days.")
    server_ip = server_ip.strip()
    if server_ip:
        try:
            ipaddress.ip_address(server_ip)
        except ValueError:
            return await _fail("Server IP is not a valid IP address.")
    try:
        port = int(smtp_port)
        if not 1 <= port <= 65535:
            raise ValueError()
    except ValueError:
        return await _fail("SMTP port is invalid.")

    values = {
        "site_name": site_name,
        "site_tagline": site_tagline,
        "registration_open": "1" if registration_open is not None else "0",
        "click_retention_days": str(retention),
        "server_ip": server_ip,
        "smtp_host": smtp_host.strip()[:255],
        "smtp_port": str(port),
        "smtp_user": smtp_user.strip()[:255],
        "smtp_from": smtp_from.strip()[:255],
    }
    for key, value in values.items():
        row = await db.get(Setting, key)
        if row is None:
            db.add(Setting(key=key, value=value))
        else:
            row.value = value
    if smtp_password:
        row = await db.get(Setting, "smtp_password")
        if row is None:
            db.add(Setting(key="smtp_password", value=smtp_password))
        else:
            row.value = smtp_password
    await log_audit(db, "settings_update", actor_id=user.id, ip=get_client_ip(request))
    await db.commit()
    clear_settings_cache(request)
    return Redirect("/admin/settings", "Settings saved.")


@router.get("/audit")
async def admin_audit(
    request: Request, db: AsyncSession = Depends(get_db), q: str = "", page: int = 1
):
    user = _admin(request)
    stmt = select(AuditLog)
    if q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(AuditLog.action.ilike(like), AuditLog.detail.ilike(like)))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    pg = paginate(total, page, 50)
    rows = (
        await db.execute(
            stmt.order_by(AuditLog.ts.desc()).offset(pg["offset"]).limit(pg["per_page"])
        )
    ).scalars().all()
    return await T(request, "admin/audit.html", user=user, entries=rows, q=q, pg=pg,
                   page=pg["page"], pages=pg["pages"])
