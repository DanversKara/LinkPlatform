Pre-release v11.7.9.sh i not fully tested it - backup older version before testing.

# 🔗 LinkPlatform

**LinkPlatform** is a full-stack, Docker-powered alternative to commercial tools like Bitly and Linktree. Shorten links, track clicks, build beautiful bio profile pages, and manage everything from a clean admin dashboard — all running on your own infrastructure.

---

## ✨ Features

### 🔗 Link Shortening
- Short URLs at `/s/CODE` with base62 codes
- Custom short codes
- Click tracking per link
- Toggle links active/inactive
- Landing page mode (`/l/CODE`) — preview page before redirect
- QR code generation built in
- Landing page themes (default, light, dark)

### 🎨 Bio Profile Pages (`/@slug`)
- Link-in-bio style profile pages
- 12 built-in seasonal themes (May Flowers, Halloween, Christmas, etc.)
- Custom HTML/CSS theme override
- Tab system — organize links into sections by type (links, social, contact, text, video, gallery)
- Per-tab background images, opacity, text color, and style (solid/glass/frost/transparent)
- Social icon row with custom icons
- Profile photo with shape (circle/rounded/square) and effect (pulse/glow/rainbow)
- Header image with half/full/cover banner modes
- Daily status bubble on profile photo
- @slug display styles (vertical, horizontal, hidden)
- Password-protected profiles
- Sensitive content + age restriction gates
- Cookie consent popup
- Verified badge, share button, branding removal

### 🌐 Custom Domains
- Users can point their own domain to their profile
- Admin grants per-user custom domain access
- DNS A-record verification built in
- Root redirect + custom 404 redirect per domain
- Short links work on custom domains (`yourdomain.com/s/CODE`)

### 🛡️ Security
- JWT authentication with refresh tokens
- Two-factor authentication (TOTP) with backup codes
- Password reset via email
- Rate limiting (SlowAPI + NGINX zones)
- NGINX security headers (X-Frame-Options, X-Content-Type-Options, CSP, etc.)
- Profile password protection
- User ban, suspend, and role system (user / moderator / admin)
- Docker network isolation

### 👑 Admin Dashboard
- User management (ban, suspend, impersonate, delete)
- Per-user custom domain access toggle
- All links overview
- Platform statistics (users, clicks, profile views, messages, reports)
- Profile reports — review, dismiss, or delete
- File upload manager
- Site settings (name, tagline, footer, emoji)
- Navigation manager (add/edit/reorder/hide nav items, including external URLs)
- Pages manager (custom HTML pages at `/p/slug` with SEO metadata)
- Email template editor
- SMTP configuration + test email

### 📬 Messaging
- User-to-user messaging by @slug
- Guest contact form
- Inbox, sent, compose tabs
- Unread count badge in navbar
- Mark as read / delete

### ⚙️ Infrastructure (Blueprint Edition)
- Upgrade-safe installer (preserves database and uploads on re-run)
- Auto-installs Docker on Debian/Ubuntu if missing
- NGINX reverse proxy with security headers and rate limiting zones
- Health checks on all Docker services
- Named volume for uploads (survives container rebuilds)
- Structured logging with rotation
- `backup.sh` — one-command database backup (keeps 10 newest)
- `linkplatform` CLI for managing your instance

---

## 🚀 Quick Install

```bash
bash v11_7_9_blueprint.sh
```

That's it. The script will:
1. Check for Docker (and install it on Debian/Ubuntu if missing)
2. Detect any existing installation and offer to upgrade safely
3. Generate a secure `SECRET_KEY` automatically
4. Build and start all containers
5. Seed the admin account and default site data
6. Install the `linkplatform` CLI tool

---

## 🐳 Services

| Service    | Description                              | Port    |
|------------|------------------------------------------|---------|
| `nginx`    | Reverse proxy + security headers         | 80      |
| `frontend` | React dashboard (Vite dev server)        | 3000    |
| `backend`  | FastAPI API + redirect engine            | 8000    |
| `db`       | PostgreSQL 15                            | (internal) |

All services run on an isolated Docker bridge network. The database is not exposed to the host.

---

## 🛠️ CLI Reference

After install, manage your instance with the `linkplatform` command:

```bash
linkplatform start       # Start all services
linkplatform stop        # Stop all services
linkplatform restart     # Restart all services
linkplatform logs        # Tail backend logs
linkplatform logs nginx  # Tail nginx logs
linkplatform status      # Show container status
linkplatform backup      # Backup PostgreSQL database
linkplatform update      # Rebuild containers with new code
linkplatform shell       # Open a backend bash shell
linkplatform db          # Open a psql shell
```

---

## 🔧 Configuration

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

After install, site settings (name, tagline, SMTP, etc.) are editable live from the **Admin → Settings** panel without restarting.

---

## 📦 Database Backups

```bash
# Manual backup
linkplatform backup

# Or directly
./backup.sh
```

Backups are saved to `~/link-platform-backups/db_YYYYMMDD_HHMMSS.sql`. The script automatically prunes to keep the 10 most recent backups.

---

## 🔑 Default Admin Login

| Field    | Value                |
|----------|----------------------|
| Email    | `admin@admin.admin`  |
| Password | `admin`              |

**Change this immediately after first login** via Admin → Users or My Account.

---

## 📡 API

The full interactive API docs are available at:

```
http://your-server:8000/docs
```

Authentication uses Bearer tokens. Get a token:

```bash
curl -X POST http://your-server:8000/api/auth/login \
  -d "username=admin@admin.admin&password=admin"
```

Key endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/login` | Login, get JWT |
| `POST` | `/api/auth/register` | Register new user |
| `GET`  | `/api/links` | List your links |
| `POST` | `/api/links` | Create a short link |
| `GET`  | `/s/{code}` | Redirect (click tracked) |
| `GET`  | `/l/{code}` | Landing page redirect |
| `GET`  | `/@{slug}` | Public bio profile page |
| `GET`  | `/api/admin/stats` | Platform statistics (admin) |

---

## 🗂️ Project Structure

```
link-platform/
├── backend/
│   └── app/
│       ├── routers/          # auth, links, profile, admin, messages, public...
│       ├── services/         # business logic (scaffolded)
│       ├── workers/          # async workers (scaffolded)
│       ├── templates/        # Jinja2 HTML (public profiles, landing pages)
│       ├── uploads/          # user-uploaded files (persisted via Docker volume)
│       ├── models.py         # SQLAlchemy models
│       ├── schemas.py        # Pydantic schemas
│       ├── auth.py           # JWT + password utilities
│       ├── config.py         # Settings via pydantic-settings
│       ├── database.py       # DB engine + session
│       ├── email_utils.py    # SMTP + template rendering
│       └── main.py           # FastAPI app, migrations, seeding
├── frontend/
│   └── src/
│       ├── pages/            # React pages (Dashboard, BioProfile, Admin...)
│       ├── components/       # Navbar, Toast, LinkCard, EmptyState
│       ├── context/          # AuthContext, ThemeContext
│       ├── styles/           # theme.css (light/dark)
│       ├── api.js            # Axios instance with auto token refresh
│       └── config.js         # API URL, theme presets, tab types
├── nginx/
│   └── nginx.conf            # Reverse proxy + security headers + rate limiting
├── docker-compose.yml
├── .env                      # Project-level env (auto-generated)
├── backup.sh                 # Database backup script
└── linkplatform              # CLI management tool
```

---

## 🎨 Themes

LinkPlatform ships with 14 built-in themes plus a custom CSS mode:

| Theme | Season |
|-------|--------|
| 🌺 May Flowers | Default |
| ❄️ Winter Frost | January |
| 💖 Valentine's Love | February |
| 🍀 St. Patrick's Day | March |
| 🐰 Easter | April |
| 🌈 Summer Pride | June |
| 🇺🇸 4th of July | July |
| 🌅 Summer Heat | August |
| 🔧 Labor Day | September |
| 🎃 Halloween | October |
| 🦃 Thanksgiving | November |
| 🎄 Christmas | December |
| 🎉 New Year's | Special |
| ✏️ Custom | Write your own CSS |

Users select a theme from the Bio Profile editor. Each theme includes colors, particle effects (petals, snow, hearts, bats, confetti, fireflies, leaves, stars, bunnies), and a custom CSS block.

---

## 🔒 Security Notes

- Change the default admin password immediately after install
- The `SECRET_KEY` is auto-generated with `openssl rand -hex 32` during install
- SMTP credentials are stored in the database and editable from the admin panel — not hardcoded
- The database container is not exposed to the host network
- NGINX rate limiting: 30 req/min on API routes, 60 req/min on redirect routes
- SlowAPI enforces 200 req/min globally in the FastAPI layer
- User uploads are validated (images only, 10MB max)

---

## 🖥️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI, SQLAlchemy, PostgreSQL, Uvicorn |
| Frontend | React 18, Vite, React Router, Axios |
| Auth | JWT (python-jose), bcrypt, pyotp (2FA) |
| Templates | Jinja2 (public bio pages) |
| Proxy | NGINX |
| Containers | Docker, Docker Compose |
| Email | SMTP (configurable), Jinja2 templates |

---

## 📄 License

Self-hosted. No proprietary code copied. Build it, run it, keep your data.
