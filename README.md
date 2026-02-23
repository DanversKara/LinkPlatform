# 🔗 LinkPlatform v11.6.0
**Shorten URLs · QR Codes · Bio Profiles · Custom Pages · Docker · WSL**

A self-hosted, all-in-one link management platform. One script creates everything — the database, backend API, and frontend — all running in Docker.

> **🎉 What's New in v11.6.0?**
> *   **✅ SMTP Settings UI:** Configure email server directly from Admin Panel (no more editing config files).
> *   **✅ Auto Backup & Restore:** Database is automatically backed up before upgrades and restored afterwards.
> *   **✅ Full 2FA Implementation:** Two-Factor Authentication is now fully functional (setup, verify, disable).
> *   **✅ Message Privacy:** Users can toggle "Accept Messages" in My Account.
> *   **✅ Email Templates:** Manage system email templates (Password Reset, etc.) via Admin UI.

---

## ✨ Features

| Feature | Description |
| :--- | :--- |
| **⚡ Short Links** | Create short links at `/s/code` — clean, trackable, fast |
| **🛑 Landing Pages** | Add a preview page at `/l/code` before the redirect |
| **📱 QR Codes** | Every link gets a scannable QR code |
| **🎨 Bio Profiles** | Fully customizable public profile at `/@username` |
| **📑 Profile Tabs** | Links, Social, Contact, Text, Video, Gallery tab types |
| **🎭 Tab Styles** | Per-tab style: Solid, Glass, Frost, or Transparent |
| **🖼️ Image Uploads** | Upload profile photos, header images, tab backgrounds |
| **💬 Messaging** | Internal inbox, sent, and compose system with privacy controls |
| **📄 Custom Pages** | Create HTML pages at `/p/slug` — auto-listed in navigation |
| **🧭 Nav Manager** | Admin controls what appears in the navigation bar |
| **👑 Admin Panel** | User management, link management, site settings, impersonation |
| **📨 SMTP UI** | Configure outgoing email server via Admin Dashboard |
| **📧 Email Templates** | Edit system emails (Password Reset, etc.) via Admin Dashboard |
| **🔐 2FA** | Full Two-Factor Authentication support (TOTP + Backup Codes) |
| **🌙 Dark Mode** | Full light/dark theme toggle |
| **🔒 JWT Auth** | Access + refresh tokens with automatic renewal |
| **🐳 Docker** | Fully containerized — Postgres, FastAPI, React, all in one command |

---

## 🚀 Quick Install (WSL)

### Step 1 — Open your WSL terminal
```bash
wsl.exe
```
Or open Windows Terminal → click the dropdown → select your Linux distro (Ubuntu, Debian, etc.)

### Step 2 — Make sure Docker is running
LinkPlatform requires Docker Desktop with WSL integration enabled.
1.  Open **Docker Desktop** on Windows.
2.  Go to **Settings → Resources → WSL Integration**.
3.  Enable your distro (e.g., Ubuntu).
4.  Click **Apply & Restart**.

Verify Docker works inside WSL:
```bash
docker --version
docker compose version
```

### Step 3 — Download the install script
**Option A — Download directly (Recommended):**
```bash
wget https://github.com/DanversKara/LinkPlatform/releases/download/v11.6.0/install.sh
```

**Option B — Clone the repo:**
```bash
git clone https://github.com/DanversKara/LinkPlatform.git
cd LinkPlatform
```

**Option C — Copy-paste manually:**
```bash
nano install.sh
# Paste the script contents, then press Ctrl+X → Y → Enter to save
```

### Step 4 — Make it executable and run
```bash
chmod +x install.sh
./install.sh
```

**That's it.** The script will:
1.  ✅ Check that Docker and openssl are installed.
2.  📦 **Auto-Backup:** If an old installation exists, it backs up the database to `~/link-platform-backups/`.
3.  🗑️ Clean previous installation at `~/link-platform`.
4.  📁 Create the full project directory structure.
5.  ⚙️ Write all backend Python files (FastAPI + SQLAlchemy).
6.  🎨 Write all frontend React files (Vite + React).
7.  🐳 Write `docker-compose.yml`.
8.  🚀 Build and start all Docker containers.
9.  🌱 Seed the database with admin account and default navigation.
10. 🔄 **Auto-Restore:** Restores your database from the backup if found.
11. ✅ Run health checks and print the URLs.

### Step 5 — Open the app

| Service | URL |
| :--- | :--- |
| 🌐 **Frontend** | `http://localhost:3000` |
| ⚙️ **Backend API** | `http://localhost:8000` |
| 📖 **API Docs** | `http://localhost:8000/docs` |

**Default admin login:**
*   **Email:** `admin@admin.admin`
*   **Password:** `admin`

> ⚠️ **Security:** Change the admin password after first login via **My Account**.

---

## 🔧 Configuration

At the top of `install.sh` you can customize everything before running:

```bash
SITE_NAME="LinkPlatform"        # Your site name
SITE_EMOJI="🔗"                 # Emoji shown in the nav bar
SITE_TAGLINE="Shorten, track…"  # Homepage tagline
SITE_FOOTER="© 2026 … "          # Footer text
SITE_VERSION="11.6.0"           # Current version
BACKEND_PORT=8000               # Backend port
FRONTEND_PORT=3000              # Frontend port
ADMIN_EMAIL="admin@admin.admin" # Admin account email
ADMIN_PASSWORD="admin"          # Admin account password
DEFAULT_THEME_COLOR="#6366f1"   # Default profile theme color
# SMTP Defaults (Editable via Admin UI later)
SMTP_HOST="localhost"
SMTP_PORT="25"
SMTP_USER=""
SMTP_PASSWORD=""
SMTP_USE_TLS="false"
```

---

## 🗂️ How URLs Work

LinkPlatform uses distinct URL prefixes so you can always tell what kind of link it is:

| Prefix | Example | What it does |
| :--- | :--- | :--- |
| `/s/code` | `localhost:8000/s/mylink` | **Short link** — redirects directly to destination |
| `/l/code` | `localhost:8000/l/mylink` | **Landing page** — shows a preview page first |
| `/p/slug` | `localhost:3000/p/about` | **Custom page** — renders your HTML page |
| `/@slug` | `localhost:8000/@username` | **Bio profile** — public profile page |

---

## 📋 Using the App

### Creating a Short Link
1.  Log in → click **Create** in the nav bar.
2.  Enter the destination URL.
3.  Optionally enter a custom code (e.g., `mylink`).
4.  Toggle **Landing Page** if you want a preview before redirect.
5.  Click **🚀 Create**.
6.  Your link will appear on the Dashboard with its full URL, click count, and a QR code button.

### Setting Up Your Bio Profile
1.  Go to **Bio Profile** in the nav bar.
2.  Set a **custom slug** (e.g., `@johndoe`) — your profile URL will be `/@johndoe`.
3.  Upload a profile photo and header image.
4.  Add **tabs**: Links, Social icons, Contact info, Text blocks, Video embeds, or Gallery.
5.  Choose a **Tab Style** per tab — Solid, Glass, Frost, or Transparent.
6.  Customize colors, background image, and custom CSS.

> **Tip:** Glass, Frost, and Transparent styles look best when you set a **Page Background Image** in the Bio Profile editor.

### Configuring SMTP (Email)
1.  Log in as **Admin**.
2.  Go to **Admin → SMTP**.
3.  Enter your SMTP Host, Port, Username, Password, and TLS settings.
4.  Click **Send Test** to verify configuration.
5.  Click **Save Settings**.
    *   *Note: Settings are stored securely in the database.*

### Managing Email Templates
1.  Go to **Admin → Email Templates**.
2.  Edit system emails (e.g., Password Reset) using HTML or Text.
3.  Use variables like `{name}`, `{reset_link}`, `{site_name}`.
4.  Send test emails directly from the manager.

### Two-Factor Authentication (2FA)
1.  Go to **2FA** in the nav bar.
2.  Click **Enable 2FA**.
3.  Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.).
4.  Enter the 6-digit code to verify.
5.  **Save your Backup Codes** in a safe place.

### Message Privacy
1.  Go to **My Account**.
2.  Toggle **Accept messages from other users**.
3.  If unchecked, only admins can send you messages.

---

## 🛠️ Docker Commands

Run these from inside your WSL terminal:

```bash
# View live backend logs
docker compose -f ~/link-platform/docker-compose.yml logs -f backend

# View live frontend logs
docker compose -f ~/link-platform/docker-compose.yml logs -f frontend

# Restart all containers
docker compose -f ~/link-platform/docker-compose.yml restart

# Stop all containers
docker compose -f ~/link-platform/docker-compose.yml down
```

Or `cd` into the project first:
```bash
cd ~/link-platform
docker compose logs -f backend
docker compose restart
```

### 🔄 Upgrading & Backups
**v11.6.0 automates backups!** When you run `./install.sh`:
1.  It detects existing data.
2.  It backs up your database to `~/link-platform-backups/backup-YYYYMMDD-HHMMSS.sql`.
3.  It reinstalls the system.
4.  It restores your data automatically.

**⚠️ Full reset (wipe database + rebuild everything):**
```bash
docker compose -f ~/link-platform/docker-compose.yml down -v
bash ~/install.sh
```
> **Warning:** This removes the `~/link-platform` directory and the database volume. Your backups remain safe in `~/link-platform-backups/`.

---

## 🏗️ Architecture

```text
link-platform/
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI app, router includes
│   │   ├── models.py         # SQLAlchemy database models
│   │   ├── schemas.py        # Pydantic request/response schemas
│   │   ├── auth.py           # JWT auth, password hashing
│   │   ├── config.py         # Environment settings
│   │   ├── database.py       # Postgres connection
│   │   ├── email_utils.py    # SMTP & templating utilities (DB based)
│   │   ├── routers/
│   │   │   ├── auth.py       # /api/auth login, 2FA, refresh
│   │   │   ├── users.py      # /api/users CRUD
│   │   │   ├── links.py      # /api links & redirects
│   │   │   ├── profile.py    # /api profile public data
│   │   │   ├── admin.py      # /api admin stats & SMTP
│   │   │   └── messages.py   # /api messages
│   │   ├── templates/        # Jinja2 HTML templates
│   │   └── uploads/          # Uploaded images
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/            # React page components (JSX)
│   │   ├── components/       # Reusable UI components
│   │   ├── styles/           # CSS & theme variables
│   │   ├── context/          # React context providers
│   │   ├── api/              # Axios API clients
│   │   ├── App.jsx           # Main React entry
│   │   └── main.jsx          # DOM render
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
└── docker-compose.yml        # Postgres 15 + FastAPI + React Vite
```

**Stack:**
*   **Database:** PostgreSQL 15
*   **Backend:** Python 3.11, FastAPI, SQLAlchemy, Passlib/bcrypt, python-jose
*   **Frontend:** React 18, Vite, React Router 6, Axios
*   **Auth:** JWT access tokens (30 min) + refresh tokens (7 days)
*   **Containers:** Docker Compose with hot-reload in development

---

## 🗄️ Database Schema

| Table | Purpose |
| :--- | :--- |
| `users` | Accounts, bio data, profile settings, 2FA fields, message preferences |
| `links` | Short links with landing page data |
| `profile_tabs` | Bio profile tab sections (with style + bg_url) |
| `profile_links` | Links inside bio tabs |
| `social_icons` | Social media icons on profiles |
| `messages` | Internal messaging system |
| `profile_reports` | Reports submitted on public profiles |
| `site_config` | Key-value site settings (name, tagline, SMTP, etc.) |
| `nav_items` | Navigation bar items |
| `pages` | Custom HTML pages |
| `email_templates` | Stored email templates for system emails |

---

## ❓ Troubleshooting

**Backend isn't starting**
```bash
cd ~/link-platform
docker compose logs backend
```
*Common causes: port 8000 already in use, Docker not running.*

**Frontend shows blank page**
```bash
docker compose logs frontend
```
*Common cause: `npm install` still running — wait 30 seconds and refresh.*

**"Login failed" error**
*   Make sure you're using the correct email and password.
*   Emails are case-insensitive — `ADMIN@admin.admin` = `admin@admin.admin`.
*   Check backend is running: `curl http://localhost:8000/`.
*   If you upgraded, ensure the database restore completed successfully.

**Port conflicts**
Edit the top of `install.sh` and change `BACKEND_PORT` or `FRONTEND_PORT` before running.

**Restoring from Backup Manually**
If auto-restore fails, backups are located in `~/link-platform-backups/`.
```bash
# Example restore command
cat ~/link-platform-backups/backup-20240101-120000.sql | docker exec -i $(docker ps -qf "name=db") psql -U user -d linkplatform
```

---

## 🔒 Security Notes

*   **Change Default Password:** Change the admin password immediately after install.
*   **SECRET_KEY:** The `SECRET_KEY` in `backend/.env` is used to sign JWT tokens. It is auto-generated on install.
*   **CORS:** Set to `allow_origins=["*"]` by default — restrict this in production via Nginx Proxy.
*   **SMTP Credentials:** Stored in the database (`site_config` table) encrypted by database permissions.
*   **File Uploads:** Stored in `backend/app/uploads/` — consider a CDN for production.

---

## 📦 Requirements

| Requirement | Notes |
| :--- | :--- |
| **Windows 10/11 with WSL2** | Ubuntu 20.04+ recommended |
| **Docker Desktop** | With WSL2 integration enabled |
| **2GB RAM free** | For all three containers |
| **Ports 3000 + 8000** | Must be free (configurable in script) |

---

## 📝 License

**MIT** — do whatever you want with it.

Built with **FastAPI · React · PostgreSQL · Docker**

---

## 🔗 Nginx Proxy Manager

If you're running a bunch of services on different ports, **Nginx Proxy Manager** is honestly hard to beat.

**Official site:** https://nginxproxymanager.com/

**Why it's so good (especially for homelabs):**
*   🔁 Easy reverse proxy setup (no manual nginx.conf editing)
*   🔒 Built-in Let's Encrypt SSL with auto-renew
*   🌐 Clean web UI instead of CLI configs
*   🎯 Simple host → IP:port mapping
*   👥 Basic access control & authentication
*   📦 Works great with Docker setups

If you're juggling stuff like:
*   `app1` on port 3000
*   `app2` on port 8080
*   `api` on port 5000

It makes everything accessible via:
*   `app1.yourdomain.com`
*   `app2.yourdomain.com`
*   `api.yourdomain.com`

---

## 📸 Screenshots

[🖼️ **Open Interactive Gallery**](https://rawcdn.githack.com/DanversKara/LinkPlatform/6055b9b08117ce036cb0f44a79bc3c6f9fb226dc/images/gallery-html/gallery.html)
*Click thumbnails for fullscreen lightbox with keyboard navigation and smooth animations*
