
<b>ISSUES TAB:</b>
Please report all bugs, glitches, exploits, or other issues here. We may not respond immediately, so thank you for your patience.
Before creating a new ticket, check if the issue has already been reported. If it has, add your details to the existing report instead of creating a new one. Keeping the same issue in one ticket helps us track it more easily and fix it faster.

# 🔗 LinkPlatform

> **Shorten URLs · QR Codes · Bio Profiles · Custom Pages · Docker · WSL**

A self-hosted, all-in-one link management platform. One script creates everything — the database, backend API, and frontend — all running in Docker.

---

## ✨ Features

| Feature | Description |
|---|---|
| ⚡ **Short Links** | Create short links at `/s/code` — clean, trackable, fast |
| 🛑 **Landing Pages** | Add a preview page at `/l/code` before the redirect |
| 📱 **QR Codes** | Every link gets a scannable QR code |
| 🎨 **Bio Profiles** | Fully customizable public profile at `/@username` |
| 📑 **Profile Tabs** | Links, Social, Contact, Text, Video, Gallery tab types |
| 🎭 **Tab Styles** | Per-tab style: Solid, Glass, Frost, or Transparent |
| 🖼️ **Image Uploads** | Upload profile photos, header images, tab backgrounds |
| 💬 **Messaging** | Internal inbox, sent, and compose system |
| 📄 **Custom Pages** | Create HTML pages at `/p/slug` — auto-listed in navigation |
| 🧭 **Nav Manager** | Admin controls what appears in the navigation bar |
| 👑 **Admin Panel** | User management, link management, site settings, impersonation |
| 🌙 **Dark Mode** | Full light/dark theme toggle |
| 🔒 **JWT Auth** | Access + refresh tokens with automatic renewal |
| 🐳 **Docker** | Fully containerized — Postgres, FastAPI, React, all in one command |

---

## 🚀 Quick Install (WSL)

### Step 1 — Open your WSL terminal

```bash
wsl.exe
```

> Or open **Windows Terminal** → click the dropdown → select your Linux distro (Ubuntu, Debian, etc.)

---

### Step 2 — Make sure Docker is running

LinkPlatform requires **Docker Desktop** with WSL integration enabled.

1. Open **Docker Desktop** on Windows
2. Go to **Settings → Resources → WSL Integration**
3. Enable your distro (e.g. Ubuntu)
4. Click **Apply & Restart**

Verify Docker works inside WSL:
```bash
docker --version
docker compose version
```

---

### Step 3 — Download the setup script

**Option A — Download from GitHub Releases (recommended):**
```bash
wget https://github.com/DanversKara/LinkPlatform/releases/download/v10.4/setup.sh
```

**Option B — Clone the repo:**
```bash
git clone https://github.com/DanversKara/LinkPlatform.git
cd LinkPlatform
```

**Option C — Copy-paste manually:**
```bash
nano setup.sh
# Paste the script contents, then press Ctrl+X → Y → Enter to save
```

---

### Step 4 — Make it executable and run

```bash
chmod +x setup.sh
./setup.sh
```

That's it. The script will:
1. ✅ Check that Docker and openssl are installed
2. 🗑️ Clean any previous installation at `~/link-platform`
3. 📁 Create the full project directory structure
4. ⚙️ Write all backend Python files (FastAPI + SQLAlchemy)
5. 🎨 Write all frontend React files (Vite + React Router)
6. 🐳 Write `docker-compose.yml`
7. 🚀 Build and start all Docker containers
8. 🌱 Seed the database with admin account and default navigation
9. ✅ Run health checks and print the URLs

---

### Step 5 — Open the app

| Service | URL |
|---|---|
| 🌐 Frontend | http://localhost:3000 |
| ⚙️ Backend API | http://localhost:8000 |
| 📖 API Docs | http://localhost:8000/docs |

**Default admin login:**
```
Email:    admin@admin.admin
Password: admin
```

> ⚠️ Change the admin password after first login via **My Account**.

---

## 🔧 Configuration

At the top of `setup.sh` you can customize everything before running:

```bash
SITE_NAME="LinkPlatform"        # Your site name
SITE_EMOJI="🔗"                 # Emoji shown in the nav bar
SITE_TAGLINE="Shorten, track…"  # Homepage tagline
SITE_FOOTER="© 2025 …"          # Footer text
BACKEND_PORT=8000               # Backend port
FRONTEND_PORT=3000              # Frontend port
ADMIN_EMAIL="admin@admin.admin" # Admin account email
ADMIN_PASSWORD="admin"          # Admin account password
DEFAULT_THEME_COLOR="#6366f1"   # Default profile theme color
```

---

## 🗂️ How URLs Work

LinkPlatform uses distinct URL prefixes so you can always tell what kind of link it is:

| Prefix | Example | What it does |
|---|---|---|
| `/s/code` | `localhost:8000/s/mylink` | **Short link** — redirects directly to destination |
| `/l/code` | `localhost:8000/l/mylink` | **Landing page** — shows a preview page first |
| `/p/slug` | `localhost:3000/p/about` | **Custom page** — renders your HTML page |
| `/@slug` | `localhost:8000/@username` | **Bio profile** — public profile page |

---

## 📋 Using the App

### Creating a Short Link
1. Log in → click **Create** in the nav bar
2. Enter the destination URL
3. Optionally enter a custom code (e.g. `mylink`)
4. Toggle **Landing Page** if you want a preview before redirect
5. Click **🚀 Create**

Your link will appear on the **Dashboard** with its full URL, click count, and a QR code button.

### Setting Up Your Bio Profile
1. Go to **Bio Profile** in the nav bar
2. Set a custom slug (e.g. `@johndoe`) — your profile URL will be `/@johndoe`
3. Upload a profile photo and header image
4. Add tabs: Links, Social icons, Contact info, Text blocks, Video embeds, or Gallery
5. Choose a **Tab Style** per tab — Solid, Glass, Frost, or Transparent
6. Customize colors, background image, and custom CSS

### Tab Styles
Each profile tab has its own style setting, chosen in the Bio Profile editor:

| Style | Look |
|---|---|
| ⬜ **Solid** | Clean white background — the default |
| 🪟 **Glass** | Frosted glass with blur and transparency |
| ❄️ **Frost** | Heavier blur with a 60% white overlay |
| ◻️ **Transparent** | Fully see-through — great over background images |

> **Tip:** Glass, Frost, and Transparent styles look best when you set a **Page Background Image** in the Bio Profile editor.

### Creating a Custom Page
1. Go to **Admin → Pages** in the nav bar
2. Enter a title and slug (e.g. `about`)
3. Write HTML content in the editor
4. Click **Create** — the page is live at `/p/about`
5. A nav item for this page is **automatically added** to Navigation Manager

### Managing Navigation
1. Go to **Admin → Navigation** in the nav bar
2. See all nav items including auto-generated page links
3. Toggle, reorder, or delete any non-system items
4. System items (Dashboard, Bio Profile, etc.) cannot be deleted but can be disabled

---

## 🛠️ Docker Commands

Run these from inside your WSL terminal in any directory:

```bash
# View live backend logs
docker compose -f ~/link-platform/docker-compose.yml logs -f backend

# View live frontend logs
docker compose -f ~/link-platform/docker-compose.yml logs -f frontend

# Restart all containers
docker compose -f ~/link-platform/docker-compose.yml restart

# Stop all containers
docker compose -f ~/link-platform/docker-compose.yml down

# Full reset (wipe database + rebuild everything)
docker compose -f ~/link-platform/docker-compose.yml down -v && bash setup.sh
```

Or `cd` into the project first:
```bash
cd ~/link-platform
docker compose logs -f backend
docker compose restart
docker compose down -v && bash ~/setup.sh  # full reset
```

---

## 🏗️ Architecture

```
link-platform/
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI app, /s/ and /l/ routes
│   │   ├── models.py         # SQLAlchemy database models
│   │   ├── schemas.py        # Pydantic request/response schemas
│   │   ├── auth.py           # JWT auth, password hashing, normalize_email
│   │   ├── config.py         # Environment settings
│   │   ├── database.py       # Postgres connection
│   │   ├── routers/
│   │   │   ├── auth.py       # /api/auth/register, login, refresh
│   │   │   ├── profile.py    # /api/profile/me, bio, tabs, icons
│   │   │   ├── links.py      # /api/links CRUD
│   │   │   ├── messages.py   # /api/messages inbox/sent/compose
│   │   │   ├── admin.py      # /api/admin users/links/settings
│   │   │   ├── admin_nav.py  # /api/admin/nav
│   │   │   ├── admin_pages.py # /api/admin/pages (auto-syncs nav)
│   │   │   ├── public.py     # /@slug bio profiles, report endpoint
│   │   │   ├── public_nav.py # /api/public/nav
│   │   │   └── public_pages.py # /p/{slug} custom pages
│   │   ├── templates/
│   │   │   ├── public_profile.html  # Bio profile Jinja2 template
│   │   │   ├── landing.html         # Landing page template
│   │   │   └── page.html            # Custom page template
│   │   └── uploads/          # Uploaded images (volume-mounted)
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Home.jsx, Login.jsx, Signup.jsx
│   │   │   ├── Dashboard.jsx, Create.jsx, EditLink.jsx
│   │   │   ├── BioProfile.jsx, MyAccount.jsx
│   │   │   ├── Messages.jsx, CustomPage.jsx
│   │   │   └── Admin.jsx, AdminNav.jsx, AdminPages.jsx
│   │   ├── components/
│   │   │   ├── Navbar.jsx    # Dynamic nav from API
│   │   │   ├── LinkCard.jsx  # Shows /s/ or /l/ badge
│   │   │   ├── Toast.jsx
│   │   │   └── EmptyState.jsx
│   │   ├── config.js         # shortUrl(), landingUrl(), linkUrl(), TAB_STYLES
│   │   ├── api.js            # Axios with auto token refresh
│   │   └── styles/theme.css  # CSS variables, dark mode
│   ├── Dockerfile
│   └── package.json
└── docker-compose.yml        # Postgres 15 + FastAPI + React Vite
```

**Stack:**
- **Database:** PostgreSQL 15
- **Backend:** Python 3.11, FastAPI, SQLAlchemy, Passlib/bcrypt, python-jose
- **Frontend:** React 18, Vite, React Router 6, Axios, qrcode.react
- **Auth:** JWT access tokens (30 min) + refresh tokens (7 days)
- **Containers:** Docker Compose with hot-reload in development

---

## 🗄️ Database Schema

| Table | Purpose |
|---|---|
| `users` | Accounts, bio data, profile settings |
| `links` | Short links with landing page data |
| `profile_tabs` | Bio profile tab sections (with style + bg_url) |
| `profile_links` | Links inside bio tabs |
| `social_icons` | Social media icons on profiles |
| `messages` | Internal messaging system |
| `profile_reports` | Reports submitted on public profiles |
| `site_config` | Key-value site settings (name, tagline, etc.) |
| `nav_items` | Navigation bar items |
| `pages` | Custom HTML pages |

---

## ❓ Troubleshooting

### Backend isn't starting
```bash
cd ~/link-platform
docker compose logs backend
```
Common causes: port 8000 already in use, Docker not running.

### Frontend shows blank page
```bash
docker compose logs frontend
```
Common cause: npm install still running — wait 30 seconds and refresh.

### "Login failed" error
- Make sure you're using the correct email and password
- Emails are **case-insensitive** — `ADMIN@admin.admin` = `admin@admin.admin`
- Check backend is running: `curl http://localhost:8000/`

### Tab styles showing as plain white
This was a bug fixed in v10.4. If you're on v10.3, re-run with the new setup script or apply the patch:
```bash
wget https://github.com/DanversKara/LinkPlatform/releases/download/v10.4/setup.sh
```

### Full reset (wipe everything and start fresh)
```bash
cd ~/link-platform
docker compose down -v  # removes containers AND database
bash ~/setup.sh         # rebuild from scratch
```

### Port conflicts
Edit the top of `setup.sh` and change `BACKEND_PORT` or `FRONTEND_PORT` before running.

---

## 🔒 Security Notes

- Change the default admin password immediately after install
- The `SECRET_KEY` in `backend/.env` is used to sign JWT tokens — change it for production
- CORS is set to `allow_origins=["*"]` — restrict this in production
- File uploads are stored in `backend/app/uploads/` — consider a CDN for production

---

## 📦 Requirements

| Requirement | Notes |
|---|---|
| Windows 10/11 with WSL2 | Ubuntu 20.04+ recommended |
| Docker Desktop | With WSL2 integration enabled |
| 2GB RAM free | For all three containers |
| Ports 3000 + 8000 | Must be free |

---

## 📝 License

MIT — do whatever you want with it.

---

*Built with FastAPI · React · PostgreSQL · Docker*

---

<b>Future Plans</b></p>
<p>Emails - send emails for reset accounts, signups, messages, etc</p>
<p>2FA APP and Backup codes</p>
<p>Cloudflare Captcha</p>
<p>Mobile / Desktop / Tablet Universal Layout aka Responsive Design</p>
<p>Plans for a Mobile App for Android and iOS (much later down the road)</p>
<p>Auto Backup and Restore Database for each update. When you run a new install, it will backup the database then restore it, so you dont lose profile, user, link, pages, data. RIGHT NOW YOU NEED TO BACK UP ALL DATABASE BEFORE YOU INSTALL ANY NEW RELEASES</p>

---

## 📸 Screenshots

<style>
.screenshot-gallery {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 15px;
  margin: 20px 0;
}

.screenshot-thumbnail {
  cursor: pointer;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(0,0,0,0.1);
  transition: transform 0.2s, box-shadow 0.2s;
  aspect-ratio: 16/9;
}

.screenshot-thumbnail:hover {
  transform: translateY(-4px);
  box-shadow: 0 4px 16px rgba(0,0,0,0.2);
}

.screenshot-thumbnail img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  display: block;
}

/* Modal/Lightbox Styles */
.screenshot-modal {
  display: none;
  position: fixed;
  z-index: 1000;
  left: 0;
  top: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0,0,0,0.9);
  animation: fadeIn 0.3s;
}

.screenshot-modal.active {
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 20px;
}

.screenshot-modal img {
  max-width: 90%;
  max-height: 90%;
  object-fit: contain;
  border-radius: 8px;
  box-shadow: 0 4px 32px rgba(0,0,0,0.5);
}

.screenshot-modal-close {
  position: absolute;
  top: 20px;
  right: 40px;
  color: white;
  font-size: 40px;
  font-weight: bold;
  cursor: pointer;
  z-index: 1001;
  transition: color 0.2s;
}

.screenshot-modal-close:hover {
  color: #6366f1;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}
</style>

<div class="screenshot-gallery">
  <div class="screenshot-thumbnail" onclick="openModal(this)">
    <img src="https://raw.githubusercontent.com/DanversKara/LinkPlatform/refs/heads/main/10.4/0.png" alt="Screenshot 1">
  </div>
  <div class="screenshot-thumbnail" onclick="openModal(this)">
    <img src="https://raw.githubusercontent.com/DanversKara/LinkPlatform/refs/heads/main/10.4/1.png" alt="Screenshot 2">
  </div>
  <div class="screenshot-thumbnail" onclick="openModal(this)">
    <img src="https://raw.githubusercontent.com/DanversKara/LinkPlatform/refs/heads/main/10.4/11.png" alt="Screenshot 3">
  </div>
  <div class="screenshot-thumbnail" onclick="openModal(this)">
    <img src="https://raw.githubusercontent.com/DanversKara/LinkPlatform/refs/heads/main/10.4/2.png" alt="Screenshot 4">
  </div>
  <div class="screenshot-thumbnail" onclick="openModal(this)">
    <img src="https://raw.githubusercontent.com/DanversKara/LinkPlatform/refs/heads/main/10.4/3.png" alt="Screenshot 5">
  </div>
  <div class="screenshot-thumbnail" onclick="openModal(this)">
    <img src="https://raw.githubusercontent.com/DanversKara/LinkPlatform/refs/heads/main/10.4/4.png" alt="Screenshot 6">
  </div>
  <div class="screenshot-thumbnail" onclick="openModal(this)">
    <img src="https://raw.githubusercontent.com/DanversKara/LinkPlatform/refs/heads/main/10.4/5.png" alt="Screenshot 7">
  </div>
  <div class="screenshot-thumbnail" onclick="openModal(this)">
    <img src="https://raw.githubusercontent.com/DanversKara/LinkPlatform/refs/heads/main/10.4/6.png" alt="Screenshot 8">
  </div>
  <div class="screenshot-thumbnail" onclick="openModal(this)">
    <img src="https://raw.githubusercontent.com/DanversKara/LinkPlatform/refs/heads/main/10.4/7.png" alt="Screenshot 9">
  </div>
  <div class="screenshot-thumbnail" onclick="openModal(this)">
    <img src="https://raw.githubusercontent.com/DanversKara/LinkPlatform/refs/heads/main/10.4/8.png" alt="Screenshot 10">
  </div>
  <div class="screenshot-thumbnail" onclick="openModal(this)">
    <img src="https://raw.githubusercontent.com/DanversKara/LinkPlatform/refs/heads/main/10.4/9.png" alt="Screenshot 11">
  </div>
</div>

<!-- Modal for enlarged images -->
<div id="screenshotModal" class="screenshot-modal" onclick="closeModal()">
  <span class="screenshot-modal-close">&times;</span>
  <img id="modalImage" src="" alt="Enlarged screenshot">
</div>

<script>
function openModal(element) {
  const modal = document.getElementById('screenshotModal');
  const modalImg = document.getElementById('modalImage');
  const img = element.querySelector('img');
  
  modalImg.src = img.src;
  modalImg.alt = img.alt;
  modal.classList.add('active');
  document.body.style.overflow = 'hidden';
}

function closeModal() {
  const modal = document.getElementById('screenshotModal');
  modal.classList.remove('active');
  document.body.style.overflow = 'auto';
}

// Close modal with Escape key
document.addEventListener('keydown', function(event) {
  if (event.key === 'Escape') {
    closeModal();
  }
});
</script>

---

If you’re running a bunch of services on different ports, Nginx Proxy Manager is honestly hard to beat.

🔗 Nginx Proxy Manager
Official site: https://nginxproxymanager.com/

Why it’s so good (especially for homelabs)

🔁 Easy reverse proxy setup (no manual nginx.conf editing)

🔒 Built-in Let’s Encrypt SSL with auto-renew

🌐 Clean web UI instead of CLI configs

🎯 Simple host → IP:port mapping

👥 Basic access control & authentication

📦 Works great with Docker setups

If you're juggling stuff like:

app1 on port 3000

app2 on port 8080

api on port 5000

random dev tools on weird ports

It makes everything accessible via:

app1.yourdomain.com
app2.yourdomain.com
api.yourdomain.com

instead of remembering ports.
