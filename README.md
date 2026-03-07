# 🔗 LinkPlatform

> **Shorten, track, and manage your links. Create beautiful bio profiles.**

A self-hosted, full-stack link management platform with custom bio profile pages, URL shortening, click analytics, team messaging, 2FA, and a fully themeable public profile system inspired by Kara's Page design.

---

## ✨ Features

### 🔗 Link Management
- Create short links with custom slugs
- Click tracking & analytics
- Landing page builder per link (with custom title, body, image, and theme)
- QR code generation for every link
- Enable / disable links instantly

### 🎨 Bio Profile Pages
- Public profile at `/@yourslug` — visits work without logging in
- **14 selectable monthly themes** extracted from the Kara Danvers page design (May Flowers default)
- Vertical `@slug` badge floating left of your avatar
- Daily status thought-bubble to the right of your avatar
- Glowing conic-gradient avatar ring
- Ambient background glow + circuit/binary-rain tech animations
- Particle effects per theme (petals 🌺, snow ❄️, hearts 💖, bats 🦇, confetti 🎉, fireflies, leaves, stars, bunnies…)
- Profile tabs with link cards, text blocks, social cards, contact info, video embeds, gallery
- Custom HTML/CSS theme override
- Redirect mode (send visitors to an external URL instead)
- Show/hide social icon row
- Profile photo styles: circle, pulse ring, glow, rainbow border, rounded square, square
- Report profile button

### 💬 Messaging
- User-to-user inbox/outbox
- Guest contact form on public profile
- Reply threading
- Accept / decline messages toggle per user

### 🔐 Security
- JWT access + refresh token auth
- Full 2FA (TOTP) with backup codes
- Password reset via email token
- Admin ban / suspend / impersonate users
- Role system: user → moderator → admin

### 🛠️ Admin Panel
- User management (ban, suspend, change role, delete, impersonate)
- All links view + delete
- Site config (name, tagline, emoji, footer)
- Custom navigation manager
- Page/CMS manager (create custom pages like `/p/contact`)
- Email template editor
- SMTP settings (editable at runtime, no restart needed)
- Profile report review queue

---

## 🗓️ Monthly Themes

Users pick a theme from the Bio Profile editor. No auto-rotation. May Flowers is the default.

| # | Theme | Colors | Effect |
|---|-------|--------|--------|
| Jan | ❄️ Winter Frost | Blue · Teal · Purple | Snow |
| Feb | 💖 Valentine's Love | Red · Pink · Blush | Hearts |
| Mar | 🍀 St. Patrick's Day | Green · Gold | Fireflies |
| Apr | 🐰 Easter | Purple · Pink · Gold | Bunnies |
| May | 🌺 May Flowers *(DEFAULT)* | Pink · Purple · Teal | Petals |
| Jun | 🌈 Summer Pride | Red · Orange · Blue | Fireflies |
| Jul | 🇺🇸 4th of July | Red · Blue · Gold | Stars |
| Aug | 🌅 Summer Heat | Orange · Red · Gold | Fireflies |
| Sep | 🔧 Labor Day | Amber · Steel Blue | Leaves |
| Oct | 🎃 Halloween | Purple · Gold · Red | Bats |
| Nov | 🦃 Thanksgiving | Orange · Brown · Green | Leaves |
| Dec | 🎄 Christmas | Red · Green · Gold | Snow |
| — | 🎉 New Year's | Blue · Purple · Teal | Confetti |
| — | ✏️ Custom | Write your own CSS | — |

---

## 🚀 Quick Start

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) + Docker Compose
- `openssl` (pre-installed on most systems)

### Install & Run

```bash
# Download the install script
curl -O https://your-server/v11.7.2.sh
# or copy v11.7.2.sh to your machine, then:

chmod +x v11.7.2.sh
bash v11.7.2.sh
```

That's it. The script will:
1. Check prerequisites
2. Scaffold the entire project under `~/link-platform/`
3. Generate a random `SECRET_KEY`
4. Build and start all Docker containers
5. Seed the admin user, default nav, pages, and email templates

### Default Credentials

| Field | Value |
|-------|-------|
| URL | `http://localhost:3000` |
| Admin email | `admin@admin.admin` |
| Admin password | `admin` |
| API docs | `http://localhost:8000/docs` |
| Profile preview | `http://localhost:3000/@admin` |

> ⚠️ **Change the admin password immediately after first login.**

---

## ⚙️ Configuration

Edit the variables at the top of `v11.7.2.sh` before running:

```bash
SITE_NAME="LinkPlatform"
SITE_EMOJI="🔗"
SITE_TAGLINE="Shorten, track, and manage your links."
SITE_FOOTER="© 2026 LinkPlatform. All rights reserved."
SITE_VERSION="11.7.2"

BACKEND_PORT=8000
FRONTEND_PORT=3000

ADMIN_EMAIL="admin@admin.admin"
ADMIN_PASSWORD="admin"
DEFAULT_THEME_COLOR="#e91e8c"   # May Flowers pink

SMTP_HOST="localhost"
SMTP_PORT="25"
SMTP_USER=""
SMTP_PASSWORD=""
SMTP_USE_TLS="false"
```

SMTP can also be configured at runtime via **Admin → SMTP Settings** without restarting.

---

## 🐳 Docker Commands

```bash
cd ~/link-platform

# View logs
docker compose logs -f backend
docker compose logs -f frontend

# Restart all services
docker compose restart

# Stop everything
docker compose down

# Full reset (destroys database)
docker compose down -v && bash v11.7.2.sh
```

---

## 🏗️ Architecture

```
~/link-platform/
├── backend/               # FastAPI (Python 3.11)
│   ├── app/
│   │   ├── routers/       # auth, profile, links, admin, messages, public…
│   │   ├── templates/     # Jinja2 HTML (public profile, landing pages)
│   │   ├── uploads/       # User-uploaded files (served as /uploads/*)
│   │   ├── main.py        # FastAPI app, migrations, seeding
│   │   ├── models.py      # SQLAlchemy models
│   │   ├── schemas.py     # Pydantic schemas
│   │   ├── auth.py        # JWT + password hashing
│   │   ├── config.py      # Pydantic settings
│   │   └── email_utils.py # SMTP email helpers
│   ├── Dockerfile
│   ├── requirements.txt
│   └── .env
├── frontend/              # React 18 + Vite
│   ├── src/
│   │   ├── pages/         # Dashboard, BioProfile, Admin, Messages…
│   │   ├── components/    # Navbar, Toast
│   │   ├── context/       # AuthContext, ThemeContext
│   │   ├── config.js      # THEME_PRESETS, constants
│   │   └── api.js         # Axios instance
│   ├── Dockerfile
│   └── vite.config.js
└── docker-compose.yml
```

**Stack:**
- **Backend:** FastAPI · SQLAlchemy · PostgreSQL · python-jose · passlib · pyotp · Jinja2
- **Frontend:** React 18 · React Router v6 · Axios · Vite
- **Database:** PostgreSQL 15 (Alpine)
- **Auth:** JWT (access + refresh tokens) · TOTP 2FA · bcrypt

---

## 📸 Profile Page Design

The public profile at `/@slug` is a server-rendered Jinja2 HTML page (no React dependency). It matches the Kara Danvers page aesthetic:

- Dark glassmorphism card
- Conic-gradient avatar glow ring
- `@slug` vertical badge (left) + status thought-bubble (right)
- Ambient radial glow background
- Moving circuit lines + binary rain in header
- Section cards with hover slide effect
- Particle effects tied to the selected theme
- SHARE and REPORT action buttons at the bottom
- Fully responsive (single column on mobile)

---

## 🔒 Security Notes

- The `SECRET_KEY` is auto-generated with `openssl rand -hex 32` on every fresh install
- Passwords are hashed with bcrypt
- JWT tokens have configurable expiry (default: 30 min access, 7 day refresh)
- 2FA uses TOTP (RFC 6238 compliant, works with any authenticator app)
- Admin actions (ban, impersonate) are role-gated at the API level
- File uploads are stored server-side under `/uploads/`, served as static files

---

## 📝 License

MIT — do whatever you want, just don't remove the footer credit 🙏

---

*Built with ❤️ — LinkPlatform v11.7.2*
