# 🔗 LinkPlatform v11.6.0

Short Links · QR Codes · Bio Profiles · Custom Pages · Docker · WSL

A fully self-hosted, all-in-one link management platform.\
One script sets up everything --- database, backend API, and frontend
--- running in Docker.

------------------------------------------------------------------------

## 🚀 What's New in v11.6.0

-   ✅ SMTP Settings UI --- Configure email directly from the Admin
    Panel\
-   ✅ Automatic Backup & Restore --- Database safely backed up before
    upgrades\
-   ✅ Full 2FA Support --- Enable, verify, and disable Two-Factor
    Authentication\
-   ✅ Message Privacy Controls --- Users can toggle "Accept Messages"\
-   ✅ Email Template Manager --- Edit system emails from the Admin UI

------------------------------------------------------------------------

# ✨ Features

-   ⚡ Short Links (`/s/code`)
-   🛑 Landing Pages (`/l/code`)
-   📱 QR Codes for every link
-   🎨 Custom Bio Profiles (`/@username`)
-   📑 Profile Tabs (Links, Social, Contact, Text, Video, Gallery)
-   🎭 Tab Styles (Solid, Glass, Frost, Transparent)
-   🖼 Image Uploads
-   💬 Internal Messaging System
-   📄 Custom Pages (`/p/slug`)
-   👑 Admin Panel
-   📨 SMTP Configuration UI
-   📧 Editable Email Templates
-   🔐 2FA (TOTP + Backup Codes)
-   🌙 Dark Mode
-   🔒 JWT Authentication
-   🐳 Fully Dockerized

------------------------------------------------------------------------

# 🚀 Quick Install (WSL + Docker)

## 1️⃣ Open WSL

``` bash
wsl.exe
```

## 2️⃣ Verify Docker

``` bash
docker --version
docker compose version
```

## 3️⃣ Download Installer

``` bash
wget https://github.com/DanversKara/LinkPlatform/releases/download/v11.6.0/install.sh
```

## 4️⃣ Run Installer

``` bash
chmod +x install.sh
./install.sh
```

------------------------------------------------------------------------

## 🌐 Access

Frontend: http://localhost:3000\
Backend API: http://localhost:8000\
Docs: http://localhost:8000/docs

Default Admin: Email: admin@admin.admin\
Password: admin

⚠️ Change the password immediately.

------------------------------------------------------------------------

# 🐳 Docker Commands

``` bash
cd ~/link-platform
docker compose logs -f backend
docker compose logs -f frontend
docker compose restart
docker compose down
```

------------------------------------------------------------------------

# 🏗️ Stack

-   PostgreSQL 15\
-   FastAPI (Python 3.11)\
-   React 18 + Vite\
-   JWT Authentication\
-   Docker Compose

------------------------------------------------------------------------

# 📦 Requirements

-   Windows 10/11 with WSL2\
-   Docker Desktop with WSL integration\
-   2GB RAM available\
-   Ports 3000 & 8000 free

------------------------------------------------------------------------

# 📝 License

MIT License
