# 🔗 LinkPlatform

> Shorten, track, and manage your links. Create beautiful bio profiles.

A self-hosted link management and bio profile platform — your own Linktree alternative with full analytics, custom domains, admin controls, and a one-command Docker installer.

---

## ✨ Features

### 🔗 Link Management
- URL shortener with custom short codes
- Full short URL displayed on every link card (e.g. `https://yoursite.com/s/abc123`)
- QR code generation per link
- Click analytics — country, device, browser, referrer
- Landing page builder per link (custom title, body, image, theme)
- Link enable/disable toggle

### 👤 Bio Profiles
- Custom `/@slug` profile pages
- Profile photo + header image (half banner, full banner, or cover)
- Bio description, header text, sub-header text
- Multiple profile themes (May Flowers, Midnight Purple, Ocean Breeze, and more)
- Custom CSS editor for full control
- Social icon links
- Tabbed profile sections with independent link lists
- Daily status message
- Profile password protection
- Age restriction + cookie consent popup
- Profile redirect (send all visitors to a URL)
- Remove branding option

### 📊 Analytics
- Per-link charts — clicks/day, top countries, devices, referrers
- Admin stats dashboard — users, clicks, profile views, messages, reports
- Redis-queued click processing (zero redirect slowdown)
- Configurable retention (default 90 days)

### 🌐 Custom Domains
- Users add their own domain — DNS A record → server IP
- Admin grants per-user domain access via toggle
- **Cloudflare proxy supported** — auto-detected via IP range check + HTTP reachability
- **"I'm using Cloudflare" self-approve button** — users activate without waiting for admin
- Domain-aware short links (`/s/CODE` resolves per domain owner)
- Root domain redirect + custom 404 redirect per domain
- DNS A record verification button

### 🔒 Security & Auth
- JWT access + refresh tokens
- Two-factor authentication (TOTP / authenticator app)
- Password reset via email
- Per-user ban / suspend controls
- NGINX rate limiting — auth (10r/m), API (30r/s burst 50), redirect (60r/s)
- Security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, etc.)

### 💬 Messages
- Contact form on every bio profile
- Guest messages (no account needed)
- Thread replies
- Unread count badge

### 🛠️ Admin Panel
- User management — roles, ban, suspend, delete
- Domain management — grant/revoke per user, view all domains and status
- Navigation editor — custom nav links
- Page manager — create custom CMS pages
- Email template editor — customise all transactional emails
- SMTP settings (editable via UI, no redeploy needed)
- File upload manager — upload and copy asset URLs
- Reports dashboard — review/dismiss/delete profile reports
- Statistics dashboard — users, clicks, profile views, messages

---

## 🚀 Quick Install

### Prerequisites
- Ubuntu / Debian server (Docker auto-installs if missing)
- OR any machine with Docker + docker-compose already installed

### One-command deploy

```bash
bash v11_8_3.sh
```

That's it. The script:
1. Installs Docker if needed
2. Generates a secure `SECRET_KEY`
3. Builds and starts all 6 containers
4. Seeds the admin account
5. Prints your login URL

---

## ⚙️ Configuration

Edit the top of `v11_8_3.sh` before running:

```bash
SITE_NAME="LinkPlatform"
SITE_EMOJI="🔗"
SITE_TAGLINE="Shorten, track, and manage your links."

DEPLOY_DOMAIN=""       # e.g. "mylinks.com" — leave blank for localhost only

ADMIN_EMAIL="admin@admin.admin"
ADMIN_PASSWORD="admin"
DEFAULT_THEME_COLOR="#a78bfa"
```

> ⚠️ Change `ADMIN_EMAIL` and `ADMIN_PASSWORD` before going live.

### `DEPLOY_DOMAIN` — set once, works everywhere

Set this to your domain and the installer automatically configures:

| What | How |
|------|-----|
| NGINX `server_name` | Patched to accept your domain + `www.` |
| Vite `allowedHosts` | `true` — accepts all hostnames safely behind NGINX |
| Backend `BASE_URL` | Set to `http://yourdomain.com` |
| CORS origins | `http://` and `https://` variants included |

The app works on **localhost**, **local IP**, and **your domain** simultaneously from first boot. All API calls use relative paths so there are never cross-origin issues.

---

## 🌐 Custom Domain Setup (for users)

Once an admin enables custom domains for your account:

1. Go to **Bio Profile → Domain tab**
2. Enter your domain (e.g. `mylinks.com`)
3. At your DNS provider, add an **A record**:

| Type | Name | Value | TTL |
|------|------|-------|-----|
| A | @ | Your server IP | 3600 |

4. Click **🔍 Verify DNS**

### Using Cloudflare?

If your domain uses Cloudflare's orange-cloud proxy, click **🔶 I'm using Cloudflare** instead. This self-approves the domain immediately — no admin needed, no IP matching required. Your links go live as soon as Cloudflare routes traffic to the server.

---

## 🏗️ Architecture

```
Browser
  │
  ▼
NGINX :80              ← reverse proxy, rate limiting, security headers
  ├── /api/*           → FastAPI backend :8000
  ├── /s/* /l/*        → FastAPI (short link redirects)
  ├── /@slug           → FastAPI (bio profile pages — server-rendered Jinja2)
  └── /*               → Vite frontend :3000 (React SPA)

FastAPI                ← Python, SQLAlchemy, JWT auth, Jinja2 templates
PostgreSQL             ← primary data store
Redis                  ← click event queue
Click Worker           ← background processor (Redis → PostgreSQL)
Cleanup Worker         ← prunes click data older than retention window
```

### Services

| Container | Image | Role |
|-----------|-------|------|
| `nginx` | nginx:alpine | Reverse proxy, rate limiting |
| `frontend` | node:alpine (Vite) | React SPA dev server |
| `backend` | python:3.11-slim | FastAPI API + profile renderer |
| `worker` | python:3.11-slim | Async click processor |
| `cleanup` | python:3.11-slim | Click data retention |
| `db` | postgres:15-alpine | Primary database |
| `redis` | redis:7-alpine | Click event queue |

---

## 🖥️ CLI

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

---

## 💾 Backups

```bash
linkplatform backup
# Saves to ~/link-platform-backups/db_YYYYMMDD_HHMMSS.sql
# Keeps the 10 most recent backups automatically
```

---

## 🔄 Upgrading

Re-run the installer — detects existing install, stops containers, overwrites code, restarts. **Database and uploads are safe.**

```bash
bash v11_8_3.sh
```

Full reset (**destroys all data**):

```bash
cd ~/link-platform && docker-compose down -v
bash v11_8_3.sh
```

---

## 🌐 HTTPS / SSL

The installer sets up HTTP on port 80. For production HTTPS the easiest path is Cloudflare orange-cloud proxy — point your domain at the server, enable the proxy, SSL is handled automatically.

For self-managed SSL use Caddy or certbot in front of port 80.

---

## 📁 Directory Structure

```
~/link-platform/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI app, routes, DB migrations
│   │   ├── models.py              # SQLAlchemy models
│   │   ├── config.py              # Settings (pydantic-settings + .env)
│   │   ├── auth.py                # JWT + password utilities
│   │   ├── routers/
│   │   │   ├── links.py           # Link CRUD
│   │   │   ├── profile.py         # Bio profile
│   │   │   ├── custom_domains.py  # Domain mgmt + CF-aware verification
│   │   │   ├── analytics.py       # Click analytics
│   │   │   ├── admin.py           # Admin endpoints
│   │   │   └── ...
│   │   ├── services/              # Redis client, redirect service
│   │   ├── workers/               # Click processor, cleanup worker
│   │   └── templates/             # Jinja2 HTML (bio profiles, emails)
│   ├── Dockerfile
│   ├── requirements.txt
│   └── .env
├── frontend/
│   ├── src/
│   │   ├── pages/                 # React page components
│   │   ├── components/            # Navbar, LinkCard, Toast…
│   │   ├── context/               # Auth + Theme context providers
│   │   └── styles/                # Global CSS + theme variables
│   ├── vite.config.js             # allowedHosts: true, --force on start
│   └── package.json
├── nginx/
│   └── nginx.conf                 # Rate limits, proxy rules, security headers
├── docker-compose.yml
├── backup.sh
└── linkplatform                   # CLI tool
```

---

## 🔑 Default Credentials

| Field | Value |
|-------|-------|
| Email | `admin@admin.admin` |
| Password | `admin` |

**Change these before going live.**

---

## 🛟 Troubleshooting

| Symptom | Fix |
|---------|-----|
| 503 errors after login | Rate limiter was too tight on older installs — `linkplatform update` |
| Short links show `/s/code` not full URL | Fixed v11.8.3 — `linkplatform update` |
| Can't create links ("Failed") | Fixed v11.8.3 — POST body was lost on 307 redirect — `linkplatform update` |
| Domain stuck on "Pending DNS" (Cloudflare) | Click **🔶 I'm using Cloudflare** to self-approve |
| Blank page on domain | Hard refresh (Ctrl+Shift+R) — fixed in v11.8.3 |
| `relation "clicks" does not exist` in cleanup logs | Harmless on fresh install, self-resolves within 1 hour |
| Backend not starting | `linkplatform logs` — DB may still be initialising, wait 30s |

---

## 📋 Version History

| Version | Highlights |
|---------|-----------|
| **v11.8.3** | `DEPLOY_DOMAIN`, relative API URLs, full URL on link cards, fix link creation (POST 307), Cloudflare self-approve, NGINX rate limit (30r/m→30r/s), vite --force, nav slash fix, allowedHosts: true |
| v11.8.2 | Vite allowedHosts patch, stale dep cache fix, internal health check URLs |
| v11.8.1 | click_events relationship fix, startup race fix, Vite HMR NGINX routing fix |
| v11.8.0 | Redis click queue, async worker, cleanup worker, analytics, NGINX proxy, named volumes |
| v11.7.9 | Branded custom domains, DNS verification, domain-aware short links |
| v11.7.8 | DB migration fixes |
| v11.7.x | Admin stats, reports, file manager, profile views, page SEO |

---

## 📄 License

MIT — do whatever you want with it.

---

*Built with FastAPI · React · PostgreSQL · Redis · Docker*
