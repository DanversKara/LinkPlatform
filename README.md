# 🔗 LinkPlatform

> Shorten, track, and manage your links. Create beautiful bio profiles.

A self-hosted link management and bio profile platform — your own Linktree alternative with full analytics, custom domains, admin controls, and a one-command Docker installer.

\---

## ✨ Features

### 🔗 Link Management

* URL shortener with custom short codes
* QR code generation per link
* Click analytics — country, device, browser, referrer
* Landing page builder per link (custom title, body, image, theme)
* Link enable/disable toggle

### 👤 Bio Profiles

* Custom `/@slug` profile pages
* Profile photo + header image (half banner, full banner, or cover)
* Bio description, header text, sub-header text
* Multiple profile themes (May Flowers, Midnight Purple, Ocean Breeze, and more)
* Custom CSS editor for full control
* Social icon links
* Tabbed profile sections with independent link lists
* Daily status message
* Profile password protection
* Age restriction + cookie consent popup
* Profile redirect (send all visitors to a URL)
* Remove branding option

### 📊 Analytics

* Per-link charts — clicks/day, top countries, devices, referrers
* Admin stats dashboard — users, clicks, profile views, messages, reports
* Redis-queued click processing (zero redirect slowdown)
* Configurable retention (default 90 days)

### 🌐 Custom Domains

* Users add their own domain — DNS A record → server IP
* Admin grants per-user domain access
* Domain-aware short links (`/s/CODE` resolves per domain owner)
* Root domain redirect + custom 404 redirect per domain
* DNS A record verification button

### 🔒 Security \& Auth

* JWT access + refresh tokens
* Two-factor authentication (TOTP / authenticator app)
* Password reset via email
* Per-user ban / suspend controls
* NGINX rate limiting (auth, API, redirect zones)
* Security headers (X-Frame-Options, CSP, HSTS-ready)

### 🛠️ Admin Panel

* User management — roles, ban, suspend, delete
* Domain management — grant/revoke per user
* Navigation editor — custom nav links
* Page manager — create custom CMS pages
* Email template editor — customise all transactional emails
* SMTP settings (editable via UI, no redeploy needed)
* File upload manager — upload and copy asset URLs
* Reports dashboard — review/dismiss/delete profile reports

### 💬 Messages

* Contact form on every bio profile
* Guest messages (no account needed)
* Thread replies
* Unread count badge

\---

## 🚀 Quick Install

### Prerequisites

* Ubuntu / Debian server (Docker auto-installs if missing)
* OR any machine with Docker + docker-compose already installed

### One-command deploy

```bash
bash v11\\\_8\\\_3.sh
```

That's it. The script:

1. Installs Docker if needed
2. Generates a secure `SECRET\\\_KEY`
3. Builds and starts all 6 containers
4. Seeds the admin account
5. Prints your login URL

\---

## ⚙️ Configuration

Edit the top of `v11\\\_8\\\_3.sh` before running:

```bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║          ⚙️  SITE CONFIGURATION — Edit values here              ║
# ╚══════════════════════════════════════════════════════════════════╝

SITE\\\_NAME="LinkPlatform"
SITE\\\_EMOJI="🔗"
SITE\\\_TAGLINE="Shorten, track, and manage your links."

DEPLOY\\\_DOMAIN=""       # e.g. "mylinks.com" — leave blank for localhost only

ADMIN\\\_EMAIL="admin@admin.admin"
ADMIN\\\_PASSWORD="admin"
DEFAULT\\\_THEME\\\_COLOR="#a78bfa"
```

### `DEPLOY\\\_DOMAIN` — the magic variable

Set this once and the installer automatically configures:

|What|How|
|-|-|
|NGINX `server\\\_name`|Patched to accept your domain + `www.`|
|Vite `allowedHosts`|Your domain added so Vite dev server allows it|
|Backend `BASE\\\_URL`|Set to `http://yourdomain.com`|
|CORS origins|`http://` and `https://` variants added|

The app works on **localhost**, **local IP**, and **your domain** simultaneously from first boot — no extra steps.

\---

## 🏗️ Architecture

```
Browser
  │
  ▼
NGINX :80          ← reverse proxy, rate limiting, security headers
  ├── /api/\\\*       → FastAPI backend :8000
  ├── /s/\\\* /l/\\\*    → FastAPI (short link redirects)
  ├── /@slug       → FastAPI (bio profile pages — server-rendered)
  └── /\\\*           → Vite frontend :3000 (React SPA)

FastAPI            ← Python, SQLAlchemy, JWT auth, Jinja2 templates
PostgreSQL         ← primary data store
Redis              ← click event queue
Click Worker       ← background processor (Redis → PostgreSQL)
Cleanup Worker     ← prunes click data older than retention window
```

### Services

|Container|Image|Role|
|-|-|-|
|`nginx`|nginx:alpine|Reverse proxy|
|`frontend`|node:alpine (Vite)|React SPA dev server|
|`backend`|python:3.11-slim|FastAPI API + profile renderer|
|`worker`|python:3.11-slim|Async click processor|
|`cleanup`|python:3.11-slim|Click data retention|
|`db`|postgres:15-alpine|Primary database|
|`redis`|redis:7-alpine|Click event queue|

\---

## 🖥️ CLI

After install, a `linkplatform` CLI is available globally:

```bash
linkplatform start        # Start all 6 services
linkplatform stop         # Stop all services
linkplatform restart      # Restart all services
linkplatform logs         # Tail backend logs
linkplatform logs nginx   # Tail NGINX logs
linkplatform worker       # Tail click worker logs
linkplatform status       # Container status
linkplatform backup       # Backup PostgreSQL database
linkplatform update       # Rebuild with latest code
linkplatform shell        # Backend bash shell
linkplatform db           # psql shell
linkplatform redis        # redis-cli
```

\---

## 💾 Backups

```bash
linkplatform backup
# Saves to \\\~/link-platform-backups/db\\\_YYYYMMDD\\\_HHMMSS.sql
# Keeps the 10 most recent backups automatically
```

\---

## 🔄 Upgrading

Re-run the installer — it detects an existing install, stops containers, overwrites code files, and restarts. **Database and uploaded files are safe.**

```bash
bash v11\\\_8\\\_3.sh
```

For a full reset (**destroys all data**):

```bash
cd \\\~/link-platform
docker-compose down -v
bash v11\\\_8\\\_3.sh
```

\---

## 🌐 HTTPS / SSL

The installer sets up HTTP on port 80. For production with HTTPS, point a reverse proxy (Caddy, Traefik, or certbot + nginx) in front of port 80, or add a second NGINX config with Let's Encrypt. A built-in SSL option is on the roadmap.

\---

## 📁 Directory Structure

```
\\\~/link-platform/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI app, routes, migrations
│   │   ├── models.py        # SQLAlchemy models
│   │   ├── config.py        # Settings (pydantic-settings)
│   │   ├── auth.py          # JWT + password utilities
│   │   ├── routers/         # Route modules
│   │   ├── services/        # Redis client, redirect service
│   │   ├── workers/         # Click processor, cleanup worker
│   │   └── templates/       # Jinja2 HTML (bio profiles, emails)
│   ├── Dockerfile
│   ├── requirements.txt
│   └── .env
├── frontend/
│   ├── src/
│   │   ├── pages/           # React page components
│   │   ├── components/      # Shared UI components
│   │   ├── context/         # Auth + Theme context providers
│   │   └── styles/          # Global CSS + theme variables
│   ├── vite.config.js
│   └── package.json
├── nginx/
│   └── nginx.conf
├── docker-compose.yml
├── backup.sh
└── linkplatform             # CLI tool
```

\---

## 🔑 Default Credentials

|Field|Value|
|-|-|
|Email|`admin@admin.admin`|
|Password|`admin`|

**Change these immediately after first login.**

\---

## 📋 Version History

|Version|Highlights|
|-|-|
|**v11.8.3**|`DEPLOY\\\_DOMAIN` variable, relative API URLs (no CORS), NGINX rate limit fix (30r/m→30r/s), no-cache headers for Vite chunks, nav trailing slash 307 fix|
|v11.8.2|Vite `allowedHosts` auto-patch, stale dep cache fix (`--force`), internal health check URLs|
|v11.8.1|`click\\\_events` relationship fix, single-worker startup race fix, Vite HMR NGINX routing fix|
|v11.8.0|Redis click queue, async click worker, cleanup worker, analytics system, NGINX reverse proxy, named Docker volumes|
|v11.7.9|Branded custom domains, DNS verification, domain-aware short links|
|v11.7.8|DB migration fixes|
|v11.7.x|Admin stats, reports, file manager, profile view tracking, page SEO metadata|

\---

## 🛟 Troubleshooting

**503 errors on dashboard**

```bash
linkplatform logs nginx   # Check rate limit errors
linkplatform restart
```

**Backend not starting**

```bash
linkplatform logs         # Check for DB connection errors
# DB may still be initialising — wait 30s and retry
```

**Frontend blank page**

```bash
# Clear browser cache (hard refresh: Ctrl+Shift+R)
linkplatform logs         # Check frontend container
```

**Cleanup worker error: relation "clicks" does not exist**
This is harmless on a fresh install — the cleanup worker runs before the backend creates tables. It self-resolves within the hour.

\---

## 📄 License

MIT — do whatever you want with it.

\---

*Built with FastAPI · React · PostgreSQL · Redis · Docker*



