"""Public bio profiles (@slug) and the bio editor."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..bio_icons import BIO_ICONS, ICON_CHOICES, UI_ICONS, resolve_icon
from ..bio_style import (
    BRAND_COLORS, EFFECTS, LINK_KIND_IDS, LINK_KINDS, NOTICE_KINDS, PALETTES,
    bio_prefs, palette_for, palette_payload, prefs_from_form, section_icon,
)
from ..config import settings
from ..db import AsyncSessionLocal, get_db
from ..deps import csrf_protect, log_audit, require_user
from ..models import BioLink, User
from ..render import THEME_IDS, THEMES, Redirect, T
from ..security import RateLimiter, get_client_ip, hash_ip, valid_bio_url, valid_hex_color, valid_slug
from ..tracking import ViewEvent, enqueue_view
from ..utils import parse_ua

from .files import UploadError, store_upload

router = APIRouter(dependencies=[Depends(csrf_protect)])
bio_limiter = RateLimiter()

RESERVED_SLUGS = {
    "s", "api", "admin", "login", "register", "logout", "dashboard",
    "links", "bio", "domains", "files", "settings", "report", "uploads",
    "static", "health",
}

EDIT_URL = "/bio/edit"
LINKS_TAB = "/bio/edit?tab=links"


def _public_cfg() -> dict:
    return {"site_name": settings.SITE_NAME,
            "site_tagline": settings.SITE_TAGLINE,
            "base_url": settings.BASE_URL.rstrip("/"),
            "registration_open": settings.REGISTRATION_OPEN}


def link_view(bl: BioLink) -> dict:
    """Template-ready view of one bio link (icon SVG, tile colour, kind)."""
    kind = bl.kind if (bl.kind or "") in LINK_KIND_IDS else "link"
    icon = resolve_icon(bl.icon or "", bl.url if kind == "link" else "")
    if not icon:
        icon = {"copy": "copy", "text": "star"}.get(kind, "link")
    svg = BIO_ICONS.get(icon) or UI_ICONS.get(icon) or BIO_ICONS["link"]
    color = valid_hex_color(bl.color or "") or BRAND_COLORS.get(icon, "")
    return {
        "id": bl.id, "kind": kind, "title": bl.title, "url": bl.url or "",
        "desc": bl.description or "", "section": (bl.section or "").strip(),
        "icon": icon, "icon_key": bl.icon or "", "svg": svg, "color": color,
        "custom_color": bl.color or "", "active": bl.is_active,
    }


def group_sections(items: list[dict]) -> list[dict]:
    """Group link views into sections, preserving first-appearance order."""
    sections: list[dict] = []
    index: dict[str, dict] = {}
    for it in items:
        key = it["section"]
        sec = index.get(key)
        if sec is None:
            ico = section_icon(key)
            sec = {"name": key, "svg": BIO_ICONS.get(ico, BIO_ICONS["star"]),
                   "cards": [], "notices": [], "entries": []}
            index[key] = sec
            sections.append(sec)
        sec["entries"].append(it)
        (sec["notices"] if it["kind"] in NOTICE_KINDS else sec["cards"]).append(it)
    return sections


async def _user_links(db: AsyncSession, user_id: int, active_only: bool = False) -> list[BioLink]:
    q = select(BioLink).where(BioLink.user_id == user_id)
    if active_only:
        q = q.where(BioLink.is_active == True)  # noqa: E712
    return list((await db.execute(q.order_by(BioLink.position, BioLink.id))).scalars().all())


# ---------------------------------------------------------------------------
# Public page
# ---------------------------------------------------------------------------
@router.get("/@{slug}")
async def bio_view(slug: str, request: Request):
    templates = request.app.state.templates

    def not_found():
        return templates.TemplateResponse(
            request, "404.html",
            {"request": request, "user": None, "csrf": "", "toast": None,
             "toast_type": "success", "THEMES": THEMES, "cfg": _public_cfg()},
            status_code=404,
        )

    if not valid_slug(slug):
        return not_found()
    async with AsyncSessionLocal() as db:
        profile = (
            await db.execute(select(User).where(User.slug == slug, User.is_active == True))  # noqa: E712
        ).scalar_one_or_none()
        if profile is None:
            return not_found()
        links = await _user_links(db, profile.id, active_only=True)
        items = [link_view(bl) for bl in links]

    theme = profile.theme if profile.theme in THEME_IDS else "default"
    prefs = bio_prefs(profile)
    palette = dict(palette_for(theme))
    if prefs["custom_accent"] and valid_hex_color(profile.accent_color or ""):
        palette["primary"] = profile.accent_color
    sections = group_sections(items)
    social_links = [it for it in items
                    if it["section"].lower() == "social media" and it["kind"] == "link"]

    # ?preview=1 is the editor's live-preview iframe: don't count it as a view.
    preview = request.query_params.get("preview") == "1"
    if not preview:
        ua = request.headers.get("user-agent", "")
        device, _, _ = parse_ua(ua)
        await enqueue_view(ViewEvent(
            user_id=profile.id,
            ip_hash=hash_ip(get_client_ip(request), settings.SECRET_KEY),
            referer=request.headers.get("referer", "")[:2048],
            device=device,
        ))

    year = datetime.now(timezone.utc).year
    footer = prefs["footer_text"] or f"© {year} {profile.display_name}"
    return templates.TemplateResponse(
        request,
        "bio/view.html",
        {
            "request": request, "user": None, "cfg": _public_cfg(), "csrf": "",
            "toast": request.query_params.get("toast"),
            "toast_type": request.query_params.get("toast_type", "success"),
            "THEMES": THEMES,
            "profile_user": profile,
            "bio_links": items,
            "sections": sections,
            "social_links": social_links,
            "ui": UI_ICONS,
            "theme": theme,
            "palette": palette,
            "prefs": prefs,
            "preview": preview,
            "footer_text": footer,
            "palette_json": palette_payload(),
        },
    )


# ---------------------------------------------------------------------------
# Editor
# ---------------------------------------------------------------------------
async def _render_editor(request: Request, db: AsyncSession, user: User,
                         errors: dict | None = None, status: int = 200):
    links = await _user_links(db, user.id)
    items = [link_view(bl) for bl in links]
    section_names = []
    for it in items:
        if it["section"] and it["section"] not in section_names:
            section_names.append(it["section"])
    for default in ("Social Media", "Contact", "MISC. Links"):
        if default not in section_names:
            section_names.append(default)
    icon_opts = [{"key": k, "label": lbl,
                  "svg": BIO_ICONS.get(k, ""), "color": BRAND_COLORS.get(k, "")}
                 for k, lbl in ICON_CHOICES]
    tab = request.query_params.get("tab", "profile")
    if tab not in ("profile", "appearance", "links"):
        tab = "profile"
    return await T(
        request, "bio/edit.html", user=user, status=status,
        errors=errors or {},
        bio_links=links,
        items=items,
        sections=group_sections(items),
        section_names=section_names,
        icon_opts=icon_opts,
        icon_choices=ICON_CHOICES,
        bio_icons=BIO_ICONS,
        resolve_icon=resolve_icon,
        prefs=bio_prefs(user),
        palettes=PALETTES,
        effects=EFFECTS,
        link_kinds=LINK_KINDS,
        palette_json=palette_payload(),
        tab=tab,
        now_year=datetime.now(timezone.utc).year,
        verified_svg=UI_ICONS["verified"],
        stats={"total": len(items), "visible": sum(1 for i in items if i["active"]),
               "sections": len([s for s in section_names if any(i["section"] == s for i in items)])},
    )


@router.get("/bio/edit")
@router.get("/bio")
async def bio_edit_form(request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    return await _render_editor(request, db, user)


@router.post("/bio/edit")
@router.post("/bio")
async def bio_edit_submit(
    request: Request,
    db: AsyncSession = Depends(get_db),
    display_name: str = Form(""),
    bio: str = Form(""),
    slug: str = Form(""),
    theme: str = Form("default"),
    accent_color: str = Form(""),
    remove_avatar: str | None = Form(None),
    avatar: UploadFile | None = File(None),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user

    async def _fail(msg: str, status: int = 400):
        return await _render_editor(request, db, user, errors={"form": msg}, status=status)

    name = display_name.strip()[:80]
    if not name:
        return await _fail("Display name cannot be empty.")
    slug = slug.strip().lower()
    if not valid_slug(slug):
        return await _fail("Handle must be 3-30 chars: lowercase letters, numbers, _.")
    if slug != user.slug and slug in RESERVED_SLUGS:
        return await _fail("That handle is reserved.")
    if slug != user.slug:
        taken = (await db.execute(select(User.id).where(User.slug == slug))).scalar_one_or_none()
        if taken is not None:
            return await _fail("That handle is already taken.")
    if theme not in THEME_IDS:
        theme = "default"
    accent = valid_hex_color(accent_color)
    if accent_color.strip() and not accent:
        return await _fail("Accent color must look like #6366f1.")

    form = await request.form()
    user.display_name = name
    user.bio = bio.strip()[:500]
    user.slug = slug
    user.theme = theme
    if accent:
        user.accent_color = accent
    # Appearance prefs are only replaced when the editor sent them, so older
    # clients (and the API) that post just the profile fields don't reset them.
    if form.get("prefs_present"):
        user.bio_prefs = json.dumps(prefs_from_form(form))
    if remove_avatar is not None:
        user.avatar_path = None
    elif avatar is not None and avatar.filename:
        try:
            stored = await store_upload(avatar, user.id, db)
        except UploadError as e:
            return await _fail(str(e))
        user.avatar_path = f"/uploads/{stored.stored_name}"
    await log_audit(db, "bio_update", actor_id=user.id, ip=get_client_ip(request))
    await db.commit()
    back = str(form.get("_return_tab") or "")
    dest = f"{EDIT_URL}?tab={back}" if back in ("profile", "appearance") else EDIT_URL
    return Redirect(dest, "Profile saved.")


def _clean_link_fields(kind: str, title: str, url: str, icon: str, description: str,
                       section: str, color: str, use_color: str | None):
    """Validate link form fields. Returns (values, error)."""
    kind = kind if kind in LINK_KIND_IDS else "link"
    title = title.strip()
    if not title or len(title) > 100:
        return None, "Title must be 1-100 characters."
    url = url.strip()
    if kind == "link" or url:
        url_norm = valid_bio_url(url)
        if not url_norm:
            return None, "Please enter a valid http(s) or mailto: URL."
    else:
        url_norm = ""
    icon = icon.strip()[:40]
    if icon and icon not in BIO_ICONS:
        icon = ""
    limit = 600 if kind in NOTICE_KINDS else 160
    desc = description.strip()[:limit]
    if kind == "copy" and not desc:
        return None, "A copy card needs the text to copy (put it in the description)."
    col = valid_hex_color(color) if use_color is not None else None
    return {"kind": kind, "title": title[:100], "url": url_norm, "icon": icon,
            "description": desc, "section": section.strip()[:60],
            "color": col or ""}, None


@router.post("/bio/links")
async def bio_link_add(
    request: Request,
    db: AsyncSession = Depends(get_db),
    title: str = Form(""),
    url: str = Form(""),
    icon: str = Form(""),
    description: str = Form(""),
    section: str = Form(""),
    kind: str = Form("link"),
    color: str = Form(""),
    use_color: str | None = Form(None),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    if not bio_limiter.allowed(f"biolink:{user.id}", 60, 3600):
        return Redirect(LINKS_TAB, "Rate limit reached.", toast_type="error")
    vals, err = _clean_link_fields(kind, title, url, icon, description, section, color, use_color)
    if err:
        return Redirect(LINKS_TAB, err, toast_type="error")
    max_pos = (
        await db.execute(
            select(func.coalesce(func.max(BioLink.position), -1)).where(BioLink.user_id == user.id)
        )
    ).scalar_one()
    bl = BioLink(user_id=user.id, position=int(max_pos) + 1, **vals)
    db.add(bl)
    await db.commit()
    return Redirect(f"{LINKS_TAB}#link-{bl.id}", "Added.")


async def _owned_bio_link(db: AsyncSession, user: User, link_id: int) -> BioLink | None:
    link = await db.get(BioLink, link_id)
    if link is None or link.user_id != user.id:
        return None
    return link


@router.post("/bio/links/{link_id}/edit")
async def bio_link_edit(
    link_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    title: str = Form(""),
    url: str = Form(""),
    icon: str = Form(""),
    description: str = Form(""),
    section: str = Form(""),
    kind: str = Form("link"),
    color: str = Form(""),
    use_color: str | None = Form(None),
    is_active: str | None = Form(None),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    link = await _owned_bio_link(db, user, link_id)
    if link is None:
        return Redirect(LINKS_TAB, "Link not found.", toast_type="error")
    vals, err = _clean_link_fields(kind, title, url, icon, description, section, color, use_color)
    if err:
        return Redirect(f"{LINKS_TAB}#link-{link_id}", err, toast_type="error")
    for k, v in vals.items():
        setattr(link, k, v)
    link.is_active = is_active is not None
    await db.commit()
    return Redirect(f"{LINKS_TAB}#link-{link_id}", "Saved.")


@router.post("/bio/links/{link_id}/toggle")
async def bio_link_toggle(link_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    link = await _owned_bio_link(db, user, link_id)
    wants_json = "application/json" in request.headers.get("accept", "")
    if link is None:
        if wants_json:
            return JSONResponse({"detail": "Link not found."}, status_code=404)
        return Redirect(LINKS_TAB, "Link not found.", toast_type="error")
    link.is_active = not link.is_active
    await db.commit()
    if wants_json:
        return JSONResponse({"ok": True, "id": link.id, "is_active": link.is_active})
    return Redirect(f"{LINKS_TAB}#link-{link_id}",
                    "Now visible." if link.is_active else "Hidden from your page.")


@router.post("/bio/links/{link_id}/delete")
async def bio_link_delete(link_id: int, request: Request, db: AsyncSession = Depends(get_db)):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    link = await _owned_bio_link(db, user, link_id)
    if link is None:
        return Redirect(LINKS_TAB, "Link not found.", toast_type="error")
    await db.delete(link)
    await db.commit()
    return Redirect(LINKS_TAB, "Removed.")


@router.post("/bio/links/{link_id}/move")
async def bio_link_move(
    link_id: int, request: Request, db: AsyncSession = Depends(get_db),
    direction: str = Form(""),
):
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    link = await _owned_bio_link(db, user, link_id)
    if link is None:
        return Redirect(LINKS_TAB, "Link not found.", toast_type="error")
    neighbor = None
    if direction == "up":
        neighbor = (
            await db.execute(
                select(BioLink)
                .where(BioLink.user_id == user.id, BioLink.position < link.position)
                .order_by(BioLink.position.desc(), BioLink.id.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
    elif direction == "down":
        neighbor = (
            await db.execute(
                select(BioLink)
                .where(BioLink.user_id == user.id, BioLink.position > link.position)
                .order_by(BioLink.position.asc(), BioLink.id.asc())
                .limit(1)
            )
        ).scalar_one_or_none()
    if neighbor is not None:
        link.position, neighbor.position = neighbor.position, link.position
        await db.commit()
    return Redirect(f"{LINKS_TAB}#link-{link_id}")


@router.post("/bio/links/reorder")
async def bio_links_reorder(request: Request, db: AsyncSession = Depends(get_db)):
    """Drag-and-drop reorder. Body: {"ids": [3, 1, 2], "sections": {"3": "Contact"}}.

    ``ids`` is the full new order; ``sections`` (optional) moves links that
    were dropped into a different section.
    """
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return JSONResponse({"detail": "Not signed in."}, status_code=401)
    try:
        body = await request.json()
        ids = [int(x) for x in body.get("ids", [])]
        moved = {int(k): str(v)[:60] for k, v in (body.get("sections") or {}).items()}
    except (ValueError, TypeError, AttributeError):
        return JSONResponse({"detail": "Bad request."}, status_code=400)
    links = {bl.id: bl for bl in await _user_links(db, user.id)}
    if sorted(ids) != sorted(links):
        return JSONResponse({"detail": "Link list changed; reload the page."}, status_code=409)
    for pos, lid in enumerate(ids):
        links[lid].position = pos
        if lid in moved:
            links[lid].section = moved[lid].strip()
    await db.commit()
    return JSONResponse({"ok": True})


@router.get("/bio/links")
async def bio_links_json(request: Request, db: AsyncSession = Depends(get_db)):
    """JSON list of the current user's bio links (used by the editor UI)."""
    user = await require_user(request, db)
    if isinstance(user, RedirectResponse):
        return user
    links = await _user_links(db, user.id)
    return JSONResponse([
        {"id": l.id, "title": l.title, "url": l.url, "position": l.position,
         "is_active": l.is_active, "kind": l.kind or "link", "section": l.section or "",
         "description": l.description or "", "icon": l.icon or "", "color": l.color or ""}
        for l in links
    ])
