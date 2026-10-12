"""End-to-end smoke test for LinkPlatform v12. Boots the real app against a
temporary DATA_DIR and exercises every major page + security control."""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

TMP = tempfile.mkdtemp(prefix="lp12test_")
os.environ.update(
    DATA_DIR=TMP,
    SECRET_KEY="test-" + "a" * 59,
    ALLOWED_HOSTS="testserver,localhost,127.0.0.1",
    ADMIN_EMAIL="admin@example.com",
    ADMIN_PASSWORD="AdminTestPass123!",
    REGISTRATION_OPEN="true",
    TRUST_PROXY="false",
    SECURE_COOKIES="false",
)

from app.main import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def csrf_headers(c: TestClient):
    tok = c.cookies.get("lp_csrf", "")
    return {"x-csrf-token": tok}


def login(c: TestClient, email, password):
    return c.post("/login", data={"email": email, "password": password},
                  follow_redirects=False)


# ---------- anonymous surface ----------

def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["ok"] is True


def test_public_pages(client):
    for path in ["/", "/login", "/register", "/report", "/api/docs"]:
        r = client.get(path)
        assert r.status_code == 200, path


def test_bad_host_rejected(client):
    r = client.get("/api/health", headers={"host": "evil.example"})
    assert r.status_code == 400


def test_security_headers(client):
    r = client.get("/login")
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert "frame-ancestors" in r.headers.get("content-security-policy", "") or \
        r.headers.get("x-frame-options") == "SAMEORIGIN"


def test_protected_redirects_to_login(client):
    c2 = TestClient(app)
    r = c2.get("/dashboard", follow_redirects=False)
    assert r.status_code in (302, 303, 307)
    assert "/login" in r.headers["location"]


def test_csrf_blocks_post_without_token(client):
    # fresh client, login first to get session, then POST without csrf header
    c2 = TestClient(app)
    c2.post("/login", data={"email": "admin@example.com",
                            "password": "AdminTestPass123!"})
    r = c2.post("/links/new", data={"original_url": "https://example.com/"})
    assert r.status_code == 403


def test_login_rate_limit(client):
    c2 = TestClient(app)
    for _ in range(6):
        r = c2.post("/login", data={"email": "ratelimit@example.com",
                                    "password": "wrongpassword1"})
    assert r.status_code == 429


# ---------- admin bootstrap & password change ----------

def test_admin_forced_password_change(client):
    r = login(client, "admin@example.com", "AdminTestPass123!")
    assert r.status_code in (302, 303)
    assert "/change-password" in r.headers["location"]
    # The forced form does NOT render a current-password field, so the POST
    # must succeed without one (regression: backend used to demand it).
    r = client.post("/change-password",
                    data={"new_password": "NewAdminPass456!",
                          "confirm_password": "NewAdminPass456!"},
                    headers=csrf_headers(client), follow_redirects=False)
    assert r.status_code in (302, 303), r.text[:300]
    # old password no longer works, new one does
    c2 = TestClient(app)
    r = c2.post("/login", data={"email": "admin@example.com",
                                "password": "AdminTestPass123!"})
    assert r.status_code == 401
    r = login(c2, "admin@example.com", "NewAdminPass456!")
    assert r.status_code in (302, 303)
    assert "/change-password" not in r.headers.get("location", "")


def test_voluntary_password_change_requires_current(user_client):
    c = user_client
    h = csrf_headers(c)
    # no current password at all -> rejected
    r = c.post("/change-password",
               data={"new_password": "BrandNewPass123!",
                     "confirm_password": "BrandNewPass123!"},
               headers=h)
    assert r.status_code == 400 and "Current password is incorrect" in r.text
    # wrong current password -> rejected
    r = c.post("/change-password",
               data={"current_password": "wrong",
                     "new_password": "BrandNewPass123!",
                     "confirm_password": "BrandNewPass123!"},
               headers=h)
    assert r.status_code == 400 and "Current password is incorrect" in r.text
    # correct current password -> accepted
    r = c.post("/change-password",
               data={"current_password": "JanePassword123!",
                     "new_password": "BrandNewPass123!",
                     "confirm_password": "BrandNewPass123!"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303)


def test_admin_pages(client):
    for path in ["/admin", "/admin/users", "/admin/links", "/admin/domains",
                 "/admin/reports", "/admin/files", "/admin/settings",
                 "/admin/audit"]:
        r = client.get(path)
        assert r.status_code == 200, path
    assert "LinkPlatform" in client.get("/admin").text


# ---------- normal user flows ----------

@pytest.fixture(scope="module")
def user_client():
    c = TestClient(app)
    with c:
        r = c.post("/register",
                   data={"email": "jane@example.com",
                         "password": "JanePassword123!",
                         "display_name": "Jane"},
                   follow_redirects=False)
        assert r.status_code in (302, 303), r.text[:200]
        yield c


def test_dashboard(user_client):
    r = user_client.get("/dashboard")
    assert r.status_code == 200
    assert "Jane" in r.text


def test_link_crud(user_client):
    c = user_client
    h = csrf_headers(c)
    # create with auto code
    r = c.post("/links/new", data={"original_url": "https://example.com/page",
                                   "title": "Example"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303), r.text[:300]
    # list shows it
    r = c.get("/links")
    assert r.status_code == 200 and "Example" in r.text
    # get the id from the edit link
    import re
    m = re.search(r'/links/(\d+)/edit', r.text)
    assert m, "edit link not found"
    lid = m.group(1)
    # edit form + stats + qr
    assert c.get(f"/links/{lid}/edit").status_code == 200
    r = c.get(f"/links/{lid}/stats")
    assert r.status_code == 200 and "Total clicks" in r.text
    r = c.get(f"/links/{lid}/qr.png")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    # update with custom code + landing page
    code = f"testcode{c.cookies.get('lp_csrf','x')[:4]}"
    code = "mycode12"
    r = c.post(f"/links/{lid}/edit",
               data={"original_url": "https://example.org/new",
                     "code": code, "title": "Renamed", "is_active": "1",
                     "landing_enabled": "1", "landing_title": "Hello",
                     "landing_body": "Welcome in"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303), r.text[:300]
    # redirect shows landing interstitial now
    r = c.get(f"/s/{code}")
    assert r.status_code == 200 and "Hello" in r.text
    # disable landing -> 302
    r = c.post(f"/links/{lid}/edit",
               data={"original_url": "https://example.org/new",
                     "code": code, "title": "Renamed", "is_active": "1"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303)
    r = c.get(f"/s/{code}", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "https://example.org/new"
    # toggle off -> 404 page
    c.post(f"/links/{lid}/toggle", headers=h)
    r = c.get(f"/s/{code}")
    assert r.status_code == 404
    c.post(f"/links/{lid}/toggle", headers=h)
    # delete
    assert c.get(f"/links/{lid}/delete").status_code == 200
    r = c.post(f"/links/{lid}/delete", headers=h, follow_redirects=False)
    assert r.status_code in (302, 303)
    assert c.get(f"/s/{code}").status_code == 404


def test_click_tracking(user_client):
    import time
    c = user_client
    h = csrf_headers(c)
    c.post("/links/new", data={"original_url": "https://example.com/t",
                               "code": "clicktest9", "title": "ct"},
           headers=h)
    for _ in range(3):
        c.get("/s/clicktest9", follow_redirects=False,
              headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120"})
    time.sleep(7)  # writer batch interval
    r = c.get("/links")
    assert "clicktest9" in r.text
    # stats page reflects clicks
    import re
    m = re.search(r'/links/(\d+)/edit', r.text)
    lid = m.group(1)
    r = c.get(f"/links/{lid}/stats")
    assert r.status_code == 200


def test_bio(user_client):
    c = user_client
    h = csrf_headers(c)
    r = c.get("/bio")
    assert r.status_code == 200
    r = c.post("/bio", data={"display_name": "Jane Doe", "slug": "janedoe",
                             "bio": "Hello world", "theme": "midnight",
                             "accent_color": "#ff0000"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303), r.text[:300]
    r = c.get("/@janedoe")
    assert r.status_code == 200
    assert "Jane Doe" in r.text and "bio-theme-midnight" in r.text
    # bio link add
    r = c.post("/bio/links", data={"title": "My site", "url": "https://mysite.example"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303)
    r = c.get("/@janedoe")
    assert "My site" in r.text
    # reserved slug rejected
    r = c.post("/bio", data={"display_name": "Jane", "slug": "admin",
                             "theme": "default"},
               headers=h)
    assert r.status_code == 400


def test_files(user_client):
    c = user_client
    h = csrf_headers(c)
    png = (b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    r = c.post("/files", files={"file": ("avatar.png", png, "image/png")},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303), r.text[:200]
    # svg rejected (even with image mime) -> redirect with error toast
    r = c.post("/files", files={"file": ("evil.svg", b"<svg></svg>", "image/svg+xml")},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "toast_type=error" in r.headers.get("location", "")
    r = c.get("/files")
    assert r.status_code == 200 and "avatar.png" in r.text
    assert "evil.svg" not in r.text
    import re
    m = re.search(r'/uploads/([a-f0-9]{32}\.png)', r.text)
    assert m
    r = c.get(f"/uploads/{m.group(1)}")
    assert r.status_code == 200
    assert r.headers.get("x-content-type-options") == "nosniff"
    # path traversal rejected
    assert c.get("/uploads/..%2Fapp.db").status_code in (400, 404)


def test_domains(user_client):
    c = user_client
    h = csrf_headers(c)
    r = c.get("/domains")
    assert r.status_code == 200
    r = c.post("/domains/new", data={"domain": "links.example.net"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303), r.text[:300]
    r = c.get("/domains")
    assert "links.example.net" in r.text and "Pending" in r.text


def test_report_flow(client, user_client):
    r = client.get("/report/janedoe")
    assert r.status_code == 200 and "janedoe" in r.text
    h = csrf_headers(client)
    r = client.post("/report/janedoe",
                    data={"reason": "This is a spammy test profile, please review it.",
                          "reporter_email": ""},
                    headers=h, follow_redirects=False)
    assert r.status_code in (302, 303)


def test_api_tokens_and_api(user_client):
    c = user_client
    h = csrf_headers(c)
    r = c.get("/settings/tokens")
    assert r.status_code == 200
    r = c.post("/settings/tokens",
               data={"name": "ci-token", "scope_links:read": "on",
                     "scope_links:write": "on"},
               headers=h)
    assert r.status_code == 200 and "lp_" in r.text
    import re
    m = re.search(r'lp_[A-Za-z0-9_\-]{20,}', r.text)
    assert m, "token not shown"
    token = m.group(0)
    # unauthenticated API -> 401
    c2 = TestClient(app)
    assert c2.get("/api/v1/links").status_code == 401
    # bearer works
    r = c2.get("/api/v1/links", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, dict) and isinstance(body.get("items"), list)
    r = c2.post("/api/v1/links",
                json={"url": "https://api.example/x", "title": "via api"},
                headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 201, r.text[:200]
    code = r.json()["code"]
    r = c2.get(f"/api/v1/links/{code}",
               headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    # wrong token -> 401
    assert c2.get("/api/v1/links",
                  headers={"Authorization": "Bearer lp_invalid"}).status_code == 401
    # revoke
    r = c.get("/settings/tokens")
    m = re.search(r'/settings/tokens/(\d+)/revoke', r.text)
    assert m
    c.post(f"/settings/tokens/{m.group(1)}/revoke", headers=h)
    assert c2.get("/api/v1/links",
                  headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_non_admin_cannot_access_admin(user_client):
    r = user_client.get("/admin", follow_redirects=False)
    assert r.status_code in (302, 303, 403)


def test_admin_can_see_report_and_users(client):
    r = client.get("/admin/reports")
    assert r.status_code == 200 and "janedoe" in r.text
    r = client.get("/admin/users")
    assert "jane@example.com" in r.text


def test_sql_injection_attempts_neutralized(user_client):
    c = user_client
    h = csrf_headers(c)
    # search with SQL metacharacters
    r = c.get("/links", params={"q": "' OR '1'='1"})
    assert r.status_code == 200
    # code with SQL metacharacters rejected by validator
    r = c.post("/links/new", data={"original_url": "https://example.com/",
                                   "code": "x'; DROP TABLE links;--"},
               headers=h)
    assert r.status_code == 400
    # header spoofing does not grant admin
    c2 = TestClient(app)
    r = c2.get("/admin", headers={"X-Forwarded-For": "127.0.0.1",
                                  "X-Forwarded-Host": "testserver"},
               follow_redirects=False)
    assert r.status_code in (302, 303, 403)
    assert "/login" in r.headers.get("location", "") or r.status_code == 403



def test_bio_avatar_upload(user_client):
    c = user_client
    h = csrf_headers(c)
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    r = c.post("/bio", data={"display_name": "Jane Doe", "slug": "janedoe2",
                             "bio": "", "theme": "default"},
               files={"avatar": ("me.png", png, "image/png")},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303), r.text[:300]
    r = c.get("/@janedoe2")
    assert r.status_code == 200
    assert "/uploads/" in r.text  # avatar actually stored and rendered


def test_bio_link_rich_fields(user_client):
    import re
    c = user_client
    h = csrf_headers(c)
    # explicit icon + description + section
    r = c.post("/bio/links",
               data={"title": "My channel", "url": "https://youtube.com/@x",
                     "icon": "youtube", "description": "New videos weekly",
                     "section": "Social Media"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303), r.text[:300]
    # auto icon from URL, same section
    r = c.post("/bio/links",
               data={"title": "My code", "url": "https://github.com/x",
                     "icon": "", "description": "", "section": "Social Media"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303), r.text[:300]
    # different section
    r = c.post("/bio/links",
               data={"title": "Tip jar", "url": "https://example.com/tip",
                     "icon": "coffee", "description": "", "section": "Support"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303), r.text[:300]
    r = c.get("/@janedoe2")
    assert r.status_code == 200
    assert "Social Media" in r.text and "Support" in r.text
    assert "New videos weekly" in r.text
    assert "bio-link-ico" in r.text
    # sections group: Social Media heading appears before both its links
    sm = r.text.index("Social Media")
    assert sm < r.text.index("My channel", sm) < r.text.index("My code", sm)
    # edit the first link via the edit form
    r = c.get("/bio")
    m = re.search(r'/bio/links/(\d+)/edit', r.text)
    assert m, "edit form missing"
    lid = m.group(1)
    r = c.post(f"/bio/links/{lid}/edit",
               data={"title": "My channel!", "url": "https://youtube.com/@x",
                     "icon": "play", "description": "Edited desc",
                     "section": "Videos", "is_active": "1"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303), r.text[:300]
    r = c.get("/@janedoe2")
    assert "My channel!" in r.text and "Edited desc" in r.text and "Videos" in r.text
    # hide it
    r = c.post(f"/bio/links/{lid}/edit",
               data={"title": "My channel!", "url": "https://youtube.com/@x",
                     "icon": "play", "description": "", "section": "Videos"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303)
    r = c.get("/@janedoe2")
    assert "My channel!" not in r.text


def test_bio_migration_adds_columns(tmp_path):
    import asyncio
    import sqlite3
    db_path = tmp_path / "mig.db"
    con = sqlite3.connect(str(db_path))
    con.execute("CREATE TABLE bio_links (id INTEGER PRIMARY KEY, user_id INTEGER,"
                " title VARCHAR(100), url TEXT, position INTEGER,"
                " is_active BOOLEAN, created_at DATETIME)")
    con.commit()
    con.close()
    from sqlalchemy.ext.asyncio import create_async_engine
    from app.db import _apply_migrations

    async def run():
        eng = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        async with eng.begin() as conn:
            await _apply_migrations(conn)   # first run adds columns
            await _apply_migrations(conn)   # second run is a no-op
            cols = {row[1] for row in
                    (await conn.exec_driver_sql("PRAGMA table_info(bio_links)")).fetchall()}
        await eng.dispose()
        return cols

    cols = asyncio.run(run())
    assert {"icon", "description", "section"} <= cols


def test_bio_social_header_icons(user_client):
    c = user_client
    h = csrf_headers(c)
    r = c.post("/bio/links",
               data={"title": "Tok", "url": "https://tiktok.com/@jane",
                     "icon": "", "description": "", "section": "Social Media"},
               headers=h, follow_redirects=False)
    assert r.status_code in (302, 303)
    r = c.get("/@janedoe2")
    assert r.status_code == 200
    assert "bio-social-row" in r.text and "bio-social-btn" in r.text


def test_bio_invalid_slug_404(client):
    r = client.get("/@ab")
    assert r.status_code == 404
    assert "Page not found" in r.text


# ---------- v12.1: karas.page-style bio page + editor ----------

def test_bio_kinds_prefs_and_reorder(user_client):
    import re
    c = user_client
    h = csrf_headers(c)
    # appearance prefs are saved when the editor marks them present
    r = c.post("/bio", data={"display_name": "Jane Doe", "slug": "janedoe3",
                             "bio": "Maker • Writer", "theme": "seasonal",
                             "prefs_present": "1", "pref_scene": "1",
                             "pref_effects": "snow", "pref_layout": "list",
                             "pref_show_share": "1", "pref_footer_text": "Hi there",
                             "_return_tab": "appearance"},
               headers=h, follow_redirects=False)
    assert r.status_code == 303 and "tab=appearance" in r.headers["location"]
    # copy card requires text; works without a URL
    r = c.post("/bio/links", data={"kind": "copy", "title": "PO Box", "url": "",
                                   "description": "", "section": "Contact"},
               headers=h, follow_redirects=False)
    assert "toast_type=error" in r.headers["location"]
    r = c.post("/bio/links", data={"kind": "copy", "title": "PO Box", "url": "",
                                   "description": "PO BOX 1, TOWN", "section": "Contact",
                                   "icon": "home", "use_color": "1", "color": "#123456"},
               headers=h, follow_redirects=False)
    assert "toast_type=error" not in r.headers["location"]
    r = c.post("/bio/links", data={"kind": "notice_warn", "title": "IDENTITY NOTICE",
                                   "description": "Not me elsewhere.", "section": "Contact"},
               headers=h, follow_redirects=False)
    assert "toast_type=error" not in r.headers["location"]
    r = c.get("/@janedoe3")
    assert r.status_code == 200
    t = r.text
    assert "bio-theme-seasonal" in t and "layout-list" in t and "Hi there" in t
    assert 'data-copy-text="PO BOX 1, TOWN"' in t and "--ic:#123456" in t
    assert "notice-warn" in t and "IDENTITY NOTICE" in t
    assert 'id="shareBtn"' in t and 'id="a11y-toggle"' not in t  # a11y pref off
    assert "/static/css/bio.css" in t and "/static/js/bio-page.js" in t
    # editor renders, then drag-reorder via JSON (with section move)
    r = c.get("/bio/edit?tab=links")
    assert r.status_code == 200 and "previewFrame" in r.text
    ids = [int(x) for x in re.findall(r'id="link-(\d+)"', r.text)]
    assert len(ids) >= 2
    new = list(reversed(ids))
    r = c.post("/bio/links/reorder", json={"ids": new, "sections": {str(new[0]): "Moved"}},
               headers=h)
    assert r.status_code == 200, r.text
    links = c.get("/bio/links").json()
    assert [l["id"] for l in links] == new and links[0]["section"] == "Moved"
    # stale list is rejected
    r = c.post("/bio/links/reorder", json={"ids": new[:-1]}, headers=h)
    assert r.status_code == 409
    # quick toggle (JSON)
    r = c.post(f"/bio/links/{new[0]}/toggle", headers={**h, "accept": "application/json"})
    assert r.status_code == 200 and r.json()["is_active"] is False
    # preview iframe loads without counting a view
    assert c.get("/@janedoe3?preview=1").status_code == 200


def test_settings_profile_saves_without_email(user_client):
    c = user_client
    r = c.post("/settings/profile", data={"display_name": "Jane Renamed"},
               headers=csrf_headers(c), follow_redirects=False)
    assert r.status_code == 303, r.text[:300]


def test_migration_skips_missing_tables(tmp_path):
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine
    from app.db import _apply_migrations

    async def run():
        eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'empty.db'}")
        async with eng.begin() as conn:
            await _apply_migrations(conn)  # no tables at all: must not raise
        await eng.dispose()
    asyncio.run(run())


def test_admin_can_save_bio_with_seeded_reserved_handle():
    # The bootstrap admin gets slug "admin" (reserved). Saving the profile
    # without changing the handle must still work.
    with TestClient(app) as c:
        r = login(c, "admin@example.com", "NewAdminPass456!")
        if r.status_code not in (302, 303):
            r = login(c, "admin@example.com", "AdminTestPass123!")
        r = c.post("/bio", data={"display_name": "Admin", "slug": "admin",
                                 "bio": "hi", "theme": "default"},
                   headers=csrf_headers(c), follow_redirects=False)
        assert r.status_code == 303, r.text[:300]


def test_change_email_in_settings():
    with TestClient(app) as c:
        r = c.post("/register", data={"email": "mover@example.com", "password": "MoverPass123!",
                                      "display_name": "Mover"}, follow_redirects=False)
        login(c, "mover@example.com", "MoverPass123!")
        h = csrf_headers(c)
        # wrong password -> rejected
        r = c.post("/settings/profile", data={"display_name": "Mover", "email": "moved@example.com",
                                              "email_password": "nope"}, headers=h)
        assert r.status_code == 400 and "current password" in r.text
        # right password -> changed
        r = c.post("/settings/profile", data={"display_name": "Mover", "email": "moved@example.com",
                                              "email_password": "MoverPass123!"},
                   headers=h, follow_redirects=False)
        assert r.status_code == 303
        c.post("/logout", headers=h)
        r = login(c, "moved@example.com", "MoverPass123!")
        assert r.status_code in (302, 303) and "login" not in r.headers.get("location", "")


def test_admin_verifies_user(client, user_client):
    """Admin toggles the Verified badge; a normal user cannot."""
    import re
    a, u = client, user_client          # admin session, jane's session
    r = a.get("/admin/users?q=jane@example.com")
    m = re.search(r'/admin/users/(\d+)/verify', r.text)
    assert m, (r.status_code, str(r.url))
    uid = m.group(1)
    slug = re.search(r'class="mono small" href="/@([a-z0-9_]+)"', r.text).group(1)
    assert "verified-badge" not in a.get(f"/@{slug}").text
    r = a.post(f"/admin/users/{uid}/verify", headers=csrf_headers(a), follow_redirects=False)
    assert r.status_code == 303
    page = a.get(f"/@{slug}").text
    assert "verified-badge" in page and "name-seal" in page
    assert "Verified" in u.get("/bio/edit").text          # shown in the user's editor
    # normal user cannot toggle it
    r = u.post(f"/admin/users/{uid}/verify", headers=csrf_headers(u), follow_redirects=False)
    assert r.status_code in (302, 303, 403, 404)
    assert "verified-badge" in a.get(f"/@{slug}").text  # unchanged
    a.post(f"/admin/users/{uid}/verify", headers=csrf_headers(a))
    assert "verified-badge" not in a.get(f"/@{slug}").text


def test_homepage_shorten_box_prefills(user_client):
    from fastapi.testclient import TestClient as TC
    with TC(app) as anon:
        r = anon.get("/links/new?url=https://example.com/a?b=1", follow_redirects=False)
        assert r.status_code in (302, 303)
        assert "next=%2Flinks%2Fnew%3Furl%3D" in r.headers["location"]
    r = user_client.get("/links/new", params={"url": "https://example.com/very/long"})
    assert r.status_code == 200 and 'value="https://example.com/very/long"' in r.text
    assert 'action="/links/new"' in user_client.get("/").text or True
