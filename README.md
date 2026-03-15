# 🔗 LinkPlatform

**Self-hosted link shortener + bio profile platform. Your server, your data, no subscriptions.**

A full alternative to Bitly + Linktree built on FastAPI, PostgreSQL, React, and NGINX — installed with a single bash script.

---

## ✨ What it does

**Link shortening** — Create short URLs, track clicks, add landing pages before redirects, generate QR codes.

**Bio profile pages** — Beautiful `/@username` pages with tabs, social icons, theme presets, custom CSS, and more. Server-rendered HTML so they're fast and SEO-friendly.

**Click analytics** — Per-link charts showing clicks over time, top countries, devices, and referers. Powered by a Redis queue and background worker so redirects never slow down.

**Admin dashboard** — Manage users, links, pages, navigation, email templates, SMTP, reports, files, and custom domains all from one panel.

---

## 🚀 Install

```bash
bash v11_8_2.sh
```

The script handles everything: checks for Docker (installs it on Debian/Ubuntu if missing), generates secrets, builds containers, seeds the database, and installs the `linkplatform` CLI.

**Default login after install:**

| Field | Value |
|-------|-------|
| Email | `admin@admin.admin` |
| Password | `admin` |

Change this immediately after first login.

---

## 🌐 URLs

| URL | What's there |
|-----|-------------|
| `http://localhost` | Main entry point (NGINX on port 80) |
| `http://localhost/dashboard` | Link dashboard |
| `http://localhost/@yourslug` | Your public bio profile |
| `http://localhost:8000/docs` | Interactive API docs |
| `http://localhost:3000` | Frontend direct (dev) |

---

## 🐳 Services

| Container | Purpose | Port |
|-----------|---------|------|
| `nginx` | Reverse proxy, rate limiting, security headers | 80 |
| `frontend` | React dashboard (Vite) | 3000 |
| `backend` | FastAPI — API, redirects, profile pages | 8000 |
| `db` | PostgreSQL 15 | internal |
| `redis` | Click event queue + cache | internal |
| `worker` | Background click processor | — |
| `cleanup` | Hourly old-data pruner | — |

**Minimum setup** (if you don't need analytics): `db`, `backend`, `frontend`, `nginx` is enough. Redis and the workers are only required for click analytics.

> **Why do profile pages go to port 8000?**
> `/@slug` pages are Jinja2 templates rendered by FastAPI — real HTML, not a React app. This makes them fast, SEO-friendly, and readable by social media link preview scrapers without any JavaScript.

---

## 🖥️ CLI

```bash
linkplatform start        # Start all services
linkplatform stop         # Stop all services
linkplatform restart      # Restart all services
linkplatform status       # Show container status
linkplatform logs         # Tail backend logs
linkplatform logs nginx   # Tail NGINX logs
linkplatform worker       # Tail click worker logs
linkplatform backup       # Backup the database
linkplatform update       # Rebuild containers with new code
linkplatform shell        # Open backend bash shell
linkplatform db           # Open psql shell
linkplatform redis        # Open redis-cli
```

---

## ⚙️ Configuration

Edit the top of the install script before running:

```bash
SITE_NAME="LinkPlatform"
SITE_EMOJI="🔗"
SITE_TAGLINE="Shorten, track, and manage your links."
BACKEND_PORT=8000
FRONTEND_PORT=3000
ADMIN_EMAIL="admin@admin.admin"
ADMIN_PASSWORD="admin"
```

After install, site settings (name, tagline, SMTP, etc.) are editable live from **Admin → Settings** — no restart needed.

---

## ✨ Features

<details>
<summary><strong>🔗 Link Shortening</strong></summary>

- Short URLs at `/s/CODE`
- Custom short codes
- Per-link click tracking
- Toggle links active/inactive
- Landing page mode — `/l/CODE` shows a preview page before redirecting
- QR code generation built in
- Landing page themes (default, light, dark)

</details>

<details>
<summary><strong>🎨 Bio Profile Pages</strong></summary>

- Public pages at `/@username`
- 14 built-in seasonal themes (May Flowers, Halloween, Christmas, etc.)
- Custom HTML/CSS theme override
- Tab system — organize links into sections (links, social, contact, text, video, gallery)
- Per-tab background images, opacity, text color, and style (solid/glass/frost/transparent)
- Social icon row with custom icons
- Profile photo with shape (circle/rounded/square) and effect (pulse/glow/rainbow)
- Header image with half/full/cover banner modes and adjustable opacity
- Daily status bubble shown on your profile photo
- @slug display styles (vertical rotated, vertical straight, horizontal, hidden)
- Password-protected profiles
- Sensitive content + age restriction gates
- Cookie consent popup
- Verified badge, share button, remove branding option
- Profile view counter

</details>

<details>
<summary><strong>📊 Click Analytics</strong></summary>

- Clicks per day chart (last 14 days)
- Total clicks and unique visitors
- Top 5 countries, devices, referers
- Redis queue — clicks are processed asynchronously so redirects are never blocked
- Falls back to direct DB writes if Redis is unavailable
- Click data retention configurable (default 90 days)
- Access via the 📊 button on any link in the dashboard

</details>

<details>
<summary><strong>🌐 Custom Domains</strong></summary>

- Users can point their own domain to their profile
- Admin grants per-user custom domain access
- DNS A-record verification built in
- Root redirect + 404 redirect configurable per domain
- Short links work on custom domains: `yourdomain.com/s/CODE`

</details>

<details>
<summary><strong>🛡️ Security</strong></summary>

- JWT auth with access + refresh tokens
- Two-factor authentication (TOTP) with backup codes
- Password reset via email
- NGINX rate limiting: auth 10/min, API 30/min, redirects 120/min
- Security headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy
- Profile password protection
- User ban, suspend, and role system (user / moderator / admin)
- Auto-generated SECRET_KEY on install

</details>

<details>
<summary><strong>👑 Admin Dashboard</strong></summary>

- User management: ban, suspend, impersonate, role change, delete
- Per-user custom domain access toggle
- All links overview with delete
- Platform statistics (users, clicks, profile views, messages, reports)
- Profile reports — review, dismiss, delete
- File upload manager
- Site settings (name, tagline, SMTP, etc.)
- Navigation manager (add/edit/reorder/hide, supports external URLs)
- Pages manager (custom HTML pages at `/p/slug` with SEO metadata)
- Email template editor with test send
- SMTP configuration

</details>

<details>
<summary><strong>📬 Messaging</strong></summary>

- User-to-user messaging by @slug
- Guest contact form
- Inbox, sent, compose
- Unread count badge in navbar
- Replies route to the original sender correctly
- System notifications (report alerts) are clearly labelled and non-replyable

</details>

---

## 📦 Backups

```bash
linkplatform backup
# Saved to ~/link-platform-backups/db_YYYYMMDD_HHMMSS.sql
# Keeps the 10 most recent automatically
```

---

## 🗂️ Project Structure

```
link-platform/
├── backend/
│   └── app/
│       ├── routers/       # auth, links, profile, admin, messages, analytics...
│       ├── services/      # redis_client, analytics_service, redirect_service
│       ├── workers/       # click_processor, cleanup_worker
│       ├── templates/     # Jinja2 HTML (public profiles, landing pages, custom pages)
│       ├── uploads/       # user-uploaded files (persisted via Docker volume)
│       ├── models.py
│       ├── schemas.py
│       ├── auth.py
│       ├── config.py
│       ├── database.py
│       ├── email_utils.py
│       └── main.py
├── frontend/
│   └── src/
│       ├── pages/         # Dashboard, BioProfile, Analytics, Admin, Messages...
│       ├── components/    # Navbar, Toast, LinkCard, EmptyState
│       ├── context/       # AuthContext, ThemeContext
│       ├── styles/        # theme.css (light/dark)
│       └── api.js         # Axios + auto token refresh
├── nginx/
│   └── nginx.conf
├── docker-compose.yml
├── .env
├── backup.sh
└── linkplatform           # CLI tool
```

---

## 🎨 Themes

| Theme | Season | Theme | Season |
|-------|--------|-------|--------|
| 🌺 May Flowers | Default | 🎃 Halloween | October |
| ❄️ Winter Frost | January | 🦃 Thanksgiving | November |
| 💖 Valentine's Love | February | 🎄 Christmas | December |
| 🍀 St. Patrick's Day | March | 🎉 New Year's | Special |
| 🐰 Easter | April | 🇺🇸 4th of July | July |
| 🌈 Summer Pride | June | 🌅 Summer Heat | August |
| 🔧 Labor Day | September | ✏️ Custom | Your own CSS |

Each theme includes colors, particle effects (petals, snow, hearts, bats, confetti, fireflies, leaves, stars, bunnies), and a full CSS override block.

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI, SQLAlchemy, PostgreSQL, Uvicorn |
| Frontend | React 18, Vite, React Router v6, Axios |
| Public pages | Jinja2 templates (server-rendered HTML) |
| Auth | JWT (python-jose), bcrypt, pyotp (2FA) |
| Queue | Redis + background worker |
| Proxy | NGINX |
| Containers | Docker, Docker Compose |
| Email | SMTP (DB-configurable), Jinja2 templates |

---

## 📄 License

Self-hosted. No proprietary code. Run it on your own server.
