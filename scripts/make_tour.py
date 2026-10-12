#!/usr/bin/env python3
"""Full visual tour of LinkPlatform v12.

Seeds a throwaway demo database, renders every page of the real app to static
HTML, and assembles a browsable offline gallery. All demo content is fictional
(example.com / @example.com).

Why static HTML instead of screenshots: no working screenshot route exists for
local previews in this environment (headless Chromium cannot reach the local
app or even file:// URLs here), so the tour ships as live pages the user opens
in their own browser — full CSS, working theme toggle, and the bio tech
animation all run.

Requires: project venv (fastapi, pillow, .../requirements.txt).

Usage:
    /tmp/lp12venv/bin/python scripts/make_tour.py [--out DIR]

Output: <out>/index.html + one .html per page + static/ + uploads/.
Re-run any time the UI changes.
"""
import argparse
import asyncio
import hashlib
import os
import secrets
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

OUT_DEFAULT = Path.home() / "workspace" / "your_files" / "linkplatform-v12-tour"

ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "TourAdminPass123!"
ALEX_EMAIL = "alex@example.com"
ALEX_PASSWORD = "TourDemoPass123!"


def setup_env(data_dir: Path):
    os.environ.update(
        DATA_DIR=str(data_dir),
        SECRET_KEY="tour-" + "k" * 59,
        ALLOWED_HOSTS="127.0.0.1,localhost,testserver",
        ADMIN_EMAIL=ADMIN_EMAIL,
        ADMIN_PASSWORD=ADMIN_PASSWORD,
        REGISTRATION_OPEN="true",
        TRUST_PROXY="false",
        SECURE_COOKIES="false",
    )


def make_avatar(path: Path):
    from PIL import Image, ImageDraw, ImageFont

    size = 256
    img = Image.new("RGB", (size, size), "#0b1020")
    d = ImageDraw.Draw(img)
    for y in range(size):
        r = int(34 + (y / size) * 40)
        g = int(211 - (y / size) * 120)
        b = int(238 - (y / size) * 60)
        d.line([(0, y), (size, y)], fill=(r, g, b))
    try:
        font = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 96)
    except OSError:
        font = ImageFont.load_default()
    d.text((size // 2, size // 2), "AR", fill="white", font=font, anchor="mm")
    img.save(path, "PNG")


def make_sample_image(path: Path, text: str):
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (640, 360), "#16213e")
    d = ImageDraw.Draw(img)
    for x in range(0, 640, 40):
        d.line([(x, 0), (x, 360)], fill="#1e2c52")
    for y in range(0, 360, 40):
        d.line([(0, y), (640, y)], fill="#1e2c52")
    d.text((320, 180), text, fill="#e94560", anchor="mm")
    img.save(path, "PNG")


async def seed(data_dir: Path):
    from sqlalchemy import select

    from app.db import AsyncSessionLocal, init_db
    from app.models import (ApiToken, BioLink, Click, Domain, Link, Report,
                            StoredFile, User)
    from app.security import hash_password

    await init_db()
    now = datetime.now(timezone.utc)

    async with AsyncSessionLocal() as db:
        admin = (await db.execute(
            select(User).where(User.email == ADMIN_EMAIL))).scalar_one()
        admin.display_name = "Site Admin"
        admin.must_change_password = False

        alex = User(
            email=ALEX_EMAIL,
            password_hash=hash_password(ALEX_PASSWORD),
            display_name="Alex Rivera",
            role="user",
            is_active=True,
            slug="alex",
            bio="I build things for the web. This is a demo profile showing off "
                "LinkPlatform v12 bio pages: sections, brand icons, and the tech header.",
            accent_color="#22d3ee",
            must_change_password=False,
        )
        db.add(alex)
        await db.flush()

        uploads = data_dir / "uploads"
        uploads.mkdir(parents=True, exist_ok=True)
        avatar_name = secrets.token_hex(8) + ".png"
        make_avatar(uploads / avatar_name)
        alex.avatar_path = f"/uploads/{avatar_name}"

        bio_links = [
            ("YouTube", "https://youtube.com/@alexrivera.demo", "youtube",
             "New video every Friday", "Social Media"),
            ("X", "https://x.com/alexrivera_demo", "x",
             "Hot takes and ship logs", "Social Media"),
            ("Instagram", "https://instagram.com/alexrivera.demo", "instagram",
             "Desk setups and dogs", "Social Media"),
            ("GitHub", "https://github.com/alexrivera-demo", "github",
             "Open-source bits", "Social Media"),
            ("Personal site", "https://alexrivera.example.com", "globe",
             "Blog, talks, and contact", "Projects"),
            ("Widget factory", "https://example.com/widgets", "link",
             "Widgets, shipped weekly", "Projects"),
            ("Email me", "mailto:alex.rivera@example.com", "email",
             "I read everything", ""),
        ]
        for i, (title, url, icon, desc, section) in enumerate(bio_links):
            db.add(BioLink(user_id=alex.id, title=title, url=url, position=i,
                           icon=icon, description=desc, section=section))

        launch = Link(user_id=alex.id, code="launch",
                      original_url="https://example.com/launch",
                      title="Product launch", clicks_cached=132)
        blog = Link(user_id=alex.id, code="blog",
                    original_url="https://example.com/blog",
                    title="Blog", clicks_cached=48)
        old = Link(user_id=alex.id, code="old-demo",
                   original_url="https://example.com/old",
                   title="Old demo", is_active=False, clicks_cached=7)
        db.add_all([launch, blog, old])
        await db.flush()

        uas = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120",
               "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/605",
               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/121"]
        refs = ["https://t.co/", "https://www.google.com/", ""]
        countries = ["US", "US", "CA", "GB", "DE"]
        for i in range(60):
            db.add(Click(
                link_id=launch.id,
                ts=now - timedelta(days=i % 14, hours=i % 24),
                ip_hash=hashlib.sha256(f"demo-ip-{i}".encode()).hexdigest(),
                ua=uas[i % 3], referer=refs[i % 3], country=countries[i % 5],
                device="desktop" if i % 3 == 0 else "mobile",
                browser="Chrome", os_name="Windows"))

        db.add(Domain(user_id=alex.id, domain="links.example.com",
                      status="pending",
                      root_url="https://example.com",
                      notfound_url="https://example.com/404"))

        stored = secrets.token_hex(16) + ".png"
        make_sample_image(uploads / stored, "press-kit.png")
        db.add(StoredFile(user_id=alex.id, stored_name=stored,
                          original_name="press-kit.png",
                          mime="image/png",
                          size=(uploads / stored).stat().st_size))

        db.add(ApiToken(user_id=alex.id, name="CI deploy",
                        prefix="lp_demo01",
                        token_hash=hashlib.sha256(
                            b"demo-token-secret").hexdigest(),
                        scopes="links:read links:write"))

        db.add(Report(target_slug="alex", reporter_email="abuse@example.com",
                      reason="Demo report: the link text on this profile looks "
                             "misleading. (Seeded for the tour.)",
                      status="open"))

        await db.commit()
    return {"launch_id": launch.id}


# (filename, path, caption, group, client)
PAGES = [
    ("01-landing.html", "/", "Landing page", "Public pages", "anon"),
    ("02-login.html", "/login", "Login", "Public pages", "anon"),
    ("03-register.html", "/register", "Registration", "Public pages", "anon"),
    ("04-bio-public.html", "/@alex", "Public bio page — tech header, mini social icons, sections", "Public pages", "anon"),
    ("05-report.html", "/report", "Report abuse form", "Public pages", "anon"),
    ("06-api-docs.html", "/api/docs", "Interactive API docs (Swagger)", "Public pages", "anon"),
    ("07-dashboard.html", "/dashboard", "Dashboard (dark theme)", "Your account", "alex"),
    ("08-dashboard-light.html", "/dashboard", "Dashboard (light theme)", "Your account", "alex_light"),
    ("09-links.html", "/links", "Short links list", "Your account", "alex"),
    ("10-link-new.html", "/links/new", "Create a short link", "Your account", "alex"),
    ("11-link-stats.html", "/links/{launch_id}/stats", "Per-link click stats", "Your account", "alex"),
    ("12-bio-edit.html", "/bio/edit", "Bio editor — avatar, sections, brand icons", "Your account", "alex"),
    ("13-files.html", "/files", "File uploads", "Your account", "alex"),
    ("14-domains.html", "/domains", "Custom domains", "Your account", "alex"),
    ("15-domain-new.html", "/domains/new", "Add a custom domain", "Your account", "alex"),
    ("16-settings.html", "/settings", "Account settings", "Your account", "alex"),
    ("17-settings-profile.html", "/settings/profile", "Profile settings", "Your account", "alex"),
    ("18-settings-tokens.html", "/settings/tokens", "API tokens", "Your account", "alex"),
    ("19-admin.html", "/admin", "Admin overview", "Admin", "admin"),
    ("20-admin-users.html", "/admin/users", "User management", "Admin", "admin"),
    ("21-admin-links.html", "/admin/links", "All links", "Admin", "admin"),
    ("22-admin-domains.html", "/admin/domains", "Domain approvals", "Admin", "admin"),
    ("23-admin-files.html", "/admin/files", "All uploaded files", "Admin", "admin"),
    ("24-admin-reports.html", "/admin/reports", "Abuse reports", "Admin", "admin"),
    ("25-admin-settings.html", "/admin/settings", "Site settings", "Admin", "admin"),
    ("26-admin-audit.html", "/admin/audit", "Audit log", "Admin", "admin"),
]

LIGHT_SEED = ('<script>try{localStorage.setItem("lp-theme","light")}'
              'catch(e){}</script>')


def localize(html: str, light: bool = False) -> str:
    # make the page work from file:// — relative asset paths
    html = html.replace('href="/static/', 'href="static/')
    html = html.replace('src="/static/', 'src="static/')
    html = html.replace("url(/static/", "url(static/")
    html = html.replace('href="/uploads/', 'href="uploads/')
    html = html.replace('src="/uploads/', 'src="uploads/')
    if light:
        html = html.replace('<script src="static/js/theme-init.js">',
                            LIGHT_SEED + '<script src="static/js/theme-init.js">')
    return html


def render(out: Path, launch_id: int):
    from fastapi.testclient import TestClient

    from app.main import app

    clients = {}
    with TestClient(app) as anon:
        clients["anon"] = anon
        for name, email, password in [("alex", ALEX_EMAIL, ALEX_PASSWORD),
                                     ("admin", ADMIN_EMAIL, ADMIN_PASSWORD)]:
            c = TestClient(app)
            c.__enter__()
            r = c.post("/login", data={"email": email, "password": password})
            assert r.status_code in (200, 302, 303), (name, r.status_code)
            clients[name] = c
        # light-theme variant reuses alex's session
        clients["alex_light"] = clients["alex"]

        shots = []
        for filename, path, caption, group, who in PAGES:
            path = path.format(launch_id=launch_id)
            r = clients[who].get(path)
            assert r.status_code == 200, (path, r.status_code)
            html = localize(r.text, light=(who == "alex_light"))
            (out / filename).write_text(html)
            shots.append((filename, caption, group))

        for c in (clients["alex"], clients["admin"]):
            c.__exit__(None, None, None)
    return shots


GALLERY_CSS = """
body{font-family:system-ui,-apple-system,sans-serif;background:#0b1020;color:#e5e7eb;margin:0;padding:32px;max-width:1200px;margin:0 auto}
h1{font-size:28px;margin:32px 0 8px}p.sub{color:#9ca3af;margin:0 0 16px;line-height:1.6}
h2{font-size:20px;margin:40px 0 16px;color:#22d3ee}
.list{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
a.page{display:block;background:#111a30;border:1px solid #1e2c52;border-radius:10px;padding:14px 16px;color:inherit;text-decoration:none}
a.page:hover{border-color:#22d3ee}a.page b{display:block;font-size:15px}a.page span{color:#9ca3af;font-size:13px}
.phone{width:390px;max-width:100%;height:700px;border:10px solid #1e2c52;border-radius:36px;overflow:hidden;margin:8px 0 0}
.phone iframe{width:100%;height:100%;border:0;background:#fff}
.note{background:#111a30;border:1px solid #1e2c52;border-radius:10px;padding:14px 16px;color:#9ca3af;font-size:14px;line-height:1.6}
"""


def write_gallery(out: Path, shots):
    groups = {}
    for name, caption, group in shots:
        groups.setdefault(group, []).append((name, caption))
    parts = ["<html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
             "<title>LinkPlatform v12 — visual tour</title><style>" + GALLERY_CSS + "</style></head><body>",
             "<h1>LinkPlatform v12 — visual tour</h1>",
             "<p class=sub>Every page of the app, rendered from a live demo instance with fictional data. "
             "These are real pages — click through, toggle the light/dark theme, watch the bio header animation. "
             "Forms won't submit (no server behind them), but everything you <i>see</i> is exactly what the app looks like.</p>",
             "<div class=note><b style='color:#e5e7eb'>Tip: mobile preview.</b> The public bio page is fully responsive — "
             "here it is in a phone frame:<div class=phone><iframe src='04-bio-public.html' title='mobile bio preview'></iframe></div></div>"]
    for group, items in groups.items():
        parts.append(f"<h2>{group}</h2><div class=list>")
        for name, caption in items:
            parts.append(f"<a class=page href='{name}'><b>{caption}</b><span>{name}</span></a>")
        parts.append("</div>")
    parts.append("<p class=sub style='margin-top:40px'>Generated by <code>scripts/make_tour.py</code> — re-run it after any UI change.</p>")
    parts.append("</body></html>")
    (out / "index.html").write_text("\n".join(parts))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_DEFAULT))
    ap.add_argument("--keep-data", action="store_true",
                    help="keep the seeded DATA_DIR for inspection")
    args = ap.parse_args()

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    data_dir = Path(tempfile.mkdtemp(prefix="lp12tour_"))
    setup_env(data_dir)

    print("== seeding demo data ==", flush=True)
    info = asyncio.run(seed(data_dir))

    print("== rendering pages ==", flush=True)
    shots = render(out, info["launch_id"])
    print(f"== {len(shots)} pages ==", flush=True)

    print("== copying assets ==", flush=True)
    shutil.copytree(PROJECT / "app" / "static", out / "static")
    shutil.copytree(data_dir / "uploads", out / "uploads")
    write_gallery(out, shots)
    print("tour written to", out)

    if not args.keep_data:
        shutil.rmtree(data_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
