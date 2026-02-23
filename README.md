🔗 LinkPlatform v11.7.0
Shorten URLs · QR Codes · Bio Profiles · Custom Pages · Docker · WSL
A self-hosted, all-in-one link management platform. One script creates everything — the database, backend API, and frontend — all running in Docker.

🎉 What's New in v11.7.0?
✅ Fixed Missing Jinja2 Templates: Added `public_profile.html`, `landing.html`, and `page.html` – fixes profile rendering errors.
✅ Fixed Messages Page: Added missing `deleteMessage` function in `Messages.jsx` – fixes blank messages
Step 3 — Download the install script
Option A — Download directly (Recommended):
bash
1
wget https://github.com/DanversKara/LinkPlatform/releases/download/v11.7.0/install.sh
Option B — Clone the repo:
bash
12
git clone https://github.com/DanversKara/LinkPlatform.git
cd LinkPlatform
Option C — Copy-paste manually:
bash
12
nano install.sh
# Paste the script contents, then press Ctrl+X → Y → Enter to save
Step 4 — Make it executable and run
bash
12
chmod +x install.sh
./install.sh
That's it. The script will:
✅ Check that Docker and openssl are installed.
📦 Auto-Backup: If an old installation exists, it backs up the database to ~/link-platform-backups/.
🗑️ Clean previous installation at ~/link-platform.
📁 Create the full project directory structure.
⚙️ Write all backend Python files (FastAPI + SQLAlchemy).
🎨 Write all frontend React files (Vite + React).
🐳 Write docker-compose.yml.
🚀 Build and start all Docker containers.
🌱 Seed the database with admin account and default navigation.
🔄 Auto-Restore: Restores your database from the backup if found.
✅ Run health checks and print the URLs.
Step 5 — Open the app
| Service
|URL
|
| ---|---|
| 🌐 Frontend
|http://localhost:3000
|
| ⚙️ Backend API
|http://localhost:8000
|
| 📖 API Docs
|http://localhost:8000/docs
|
Default admin login:
Email:admin@admin.admin
Password:admin
⚠️ Security: Change the admin password after first login via My Account.
🔧 Configuration
At the top of install.sh you can customize everything before running:
bash
12345678910111213141516
SITE_NAME="LinkPlatform"        # Your site name
SITE_EMOJI="🔗"                 # Emoji shown in the nav bar
SITE_TAGLINE="Shorten, track…"  # Homepage tagline
SITE_FOOTER="© 2026 …  "          # Footer text
SITE_VERSION="11.7.0"           # Current version
BACKEND_PORT=8000               # Backend port
FRONTEND_PORT=3000              # Frontend port
ADMIN_EMAIL="admin@admin.admin" # Admin account email
ADMIN_PASSWORD="admin"          # Admin account password
DEFAULT_THEME_COLOR="#6366f1"   # D
🗂️ How URLs Work
LinkPlatform uses distinct URL prefixes so you can always tell what kind of link it is:
| Prefix
|Example
|What it does
|
| ---|---|---|
| /s/code
|localhost:8000/s/mylink
|Short link — redirects directly to destination
|
| /l/code
|localhost:8000/l/mylink
|Landing page — shows a preview page first
|
| /p/slug
|localhost:3000/p/about
|Custom page — renders your HTML page
|
| /@slug
|localhost:8000/@username
|Bio profile — public profile page
|
📋 Using the App
Creating a Short Link
Log in → click Create in the nav bar.
Enter the destination URL.
Optionally enter a custom code (e.g., mylink).
Toggle Landing Page if you want a preview before redirect.
Click 🚀 Create.
Your link will appear on the Dashboard with its full URL, click count, and a QR code button.
Setting Up Your Bio Profile
Go to Bio Profile in the nav bar.
Set a custom slug (e.g., @johndoe) — your profile URL will be /@johndoe.
Upload a profile photo and header image.
Add tabs: Links, Social icons, Contact info, Text blocks, Video embeds, or Gallery.
Choose a Tab Style per tab — Solid, Glass, Frost, or Transparent.
Customize colors, background image, and custom CSS.
Tip: Glass, Frost, and Transparent styles look best when you set a Page Background Image in the Bio Profile editor.
Configuring SMTP (Email)
Log in as Admin.
Go to Admin → SMTP.
Enter your SMTP Host, Port, Username, Password, and TLS settings.
Click Send Test to verify configuration.
Click Save Settings.
Note: Settings are stored securely in the database.
Managing Email Templates
Go to Admin → Email Templates.
Edit system emails (e.g., Password Reset) using HTML or Text.
Use variables like {name}, {reset_link}, {site_name}.
Send test emails directly from the manager.
Two-Factor Authentication (2FA)
Go to 2FA in the nav bar.
Click Enable 2FA.
Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.).
Enter the 6-digit code to verify.
Save your Backup Codes in a safe place.
Message Privacy
Go to My Account.
Toggle Accept messages from other users.
If unchecked, only admins can send you messages.
🛠️ Docker Commands
Run these from inside your WSL terminal:
bash
1234567891011
Or cd into the project first:
bash
123
🔄 Upgrading & Backups
v11.7.0 automates backups! When you run ./install.sh:
It detects existing data.
It backs up your database to ~/link-platform-backups/backup-YYYYMMDD-HHMMSS.sql.
It reinstalls the system.
It restores your data automatically.
⚠️ Full reset (wipe database + rebuild everything):
bash
12
Warning: This removes the ~/link-platform directory and the database volume. Your backups remain safe in ~/link-platform-backups/.
🏗️ Architecture
12345678910111213141516171819202122232425262728293031323334
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

Stack:
Database: PostgreSQL 15
Backend: Python 3.11, FastAPI, SQLAlchemy, Passlib/bcrypt, python-jose
Frontend: React 18, Vite, React Router 6, Axios
Auth: JWT access tokens (30 min) + refresh tokens (7 days)
Containers: Docker Compose with hot-reload in development
🗄️ Database Schema
| Table
|Purpose
|
| ---|---|
| users
|Accounts, bio data, profile settings, 2FA fields, message preferences
|
| links
|Short links with landing page data
|
| profile_tabs
|Bio profile tab sections (with style + bg_url)
|
| profile_links
|Links inside bio tabs
|
| social_icons
|Social media icons on profiles
|
| messages
|Internal messaging system
|
| profile_reports
|Reports submitted on public profiles
|
| site_config
|Key-value site settings (name, tagline, SMTP, etc.)
|
| nav_items
|Navigation bar items
|
| pages
|Custom HTML pages
|
| email_templates
|Stored email templates for system emails
|
❓ Troubleshooting
Backend isn't starting
bash
12
cd ~/link-platform
docker compose logs backend
Common causes: port 8000 already in use, Docker not running.
Frontend shows blank page
bash
1
Common cause: npm install still running — wait 30 seconds and refresh.
"Login failed" error
Make sure you're using the correct email and password.
Emails are case-insensitive — ADMIN@admin.admin = admin@admin.admin.
Check backend is running: curl http://localhost:8000/.
If you upgraded, ensure the database restore completed successfully.
Port conflicts
Edit the top of install.sh and change BACKEND_PORT or FRONTEND_PORT before running.
Restoring from Backup Manually
If auto-restore fails, backups are located in ~/link-platform-backups/.
bash
12
# Example restore command
cat ~/link-platform-backups/backup-20240101-120000.sql | docker exec -i $(docker ps -qf "name=db") psql -U user -d linkplatform
🔒 Security Notes
Change Default Password: Change the admin password immediately after install.
SECRET_KEY: The SECRET_KEY in backend/.env is used to sign JWT tokens. It is auto-generated on install.
CORS: Set to allow_origins=["*"] by default — restrict this in production via Nginx Proxy.
SMTP Credentials: Stored in the database (site_config table) encrypted by database permissions.
File Uploads: Stored in backend/app/uploads/ — consider a CDN for production.
📦 Requirements
| Requirement
|Notes
|
| ---|---|
| Windows 10/11 with WSL2
|Ubuntu 20.04+ recommended
|
| Docker Desktop
|With WSL2 integration enabled
|
| 2GB RAM free
|For all three containers
|
| Ports 3000 + 8000
|Must be free (configurable in script)
|
📝 License
MIT — do whatever you want with it.
Built with FastAPI · React · PostgreSQL · Docker
🔗 Nginx Proxy Manager
If you're running a bunch of services on different ports, Nginx Proxy Manager is honestly hard to beat.
Official site: https://nginxproxymanager.com/
Why it's so good (especially for homelabs):
🔁 Easy reverse proxy setup (no manual nginx.conf editing)
🔒 Built-in Let's Encrypt SSL with auto-renew
🌐 Clean web UI instead of CLI configs
🎯 Simple host → IP:port mapping
👥 Basic access control & authentication
📦 Works great with Docker setups
If you're juggling stuff like:
app1 on port 3000
app2 on port 8080
api on port 5000
It makes everything accessible via:
app1.yourdomain.com
app2.yourdomain.com
api.yourdomain.com
📸 Screenshots
🖼️ Open Interactive GalleryClick thumbnails for fullscreen lightbox with keyboard navigation and smooth animations
```
