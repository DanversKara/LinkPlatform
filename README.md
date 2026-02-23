🔗 LinkPlatform v11.7.0
Shorten URLs · QR Codes · Bio Profiles · Custom Pages · Docker · WSL
A self-hosted, all-in-one link management platform. One script creates everything — the database, backend API, and frontend — all running in Docker.

🎉 What's New in v11.7.0?
✅ Fixed Missing Jinja2 Templates: Added `public_profile.html`, `landing.html`, and `page.html` – fixes profile rendering errors.
✅ Fixed Messages Page: Added missing `deleteMessage` function in `Messages.jsx` – fixes blank messages page and enables deletion.
✅ SMTP Settings UI: Configure email server directly from Admin Panel (no more editing config files).
✅ Test Email Button: Verify SMTP configuration directly from the Admin UI.
✅ Auto Backup & Restore: Database is automatically backed up before upgrades and restored afterwards.
✅ Full 2FA Implementation: Two-Factor Authentication is now fully functional (setup, verify, disable).
✅ Message Privacy: Users can toggle "Accept Messages" in My Account.
✅ Email Templates: Manage system email templates (Password Reset, etc.) via Admin UI.

✨ Features
| Feature
|Description
|
| ---|---|
| ⚡ Short Links
|Create short links at  /s/code  — clean, trackable, fast
|
| 🛑 Landing Pages
|Add a preview page at  /l/code  before the redirect
|
| 📱 QR Codes
|Every link gets a scannable QR code
|
| 🎨 Bio Profiles
|Fully customizable public profile at  /@username
|
| 📑 Profile Tabs
|Links, Social, Contact, Text, Video, Gallery tab types
|
| 🎭 Tab Styles
|Per-tab style: Solid, Glass, Frost, or Transparent
|
| 🖼️ Image Uploads
|Upload profile photos, header images, tab backgrounds
|
| 💬 Messaging
|Internal inbox, sent, and compose system with privacy controls
|
| 📄 Custom Pages
|Create HTML pages at  /p/slug  — auto-listed in navigation
|
| 🧭 Nav Manager
|Admin controls what appears in the navigation bar
|
| 👑 Admin Panel
|User management, link management, site settings, impersonation
|
| 📨 SMTP UI
|Configure outgoing email server via Admin Dashboard
|
| 📧 Email Templates
|Edit system emails (Password Reset, etc.) via Admin Dashboard
|
| 🔐 2FA
|Full Two-Factor Authentication support (TOTP + Backup Codes)
|
| 🌙 Dark Mode
|Full light/dark theme toggle
|
| 🔒 JWT Auth
|Access + refresh tokens with automatic renewal
|
| 🐳 Docker
|Fully containerized — Postgres, FastAPI, React, all in one command
|

🚀 Quick Install (WSL)
Step 1 — Open your WSL terminal
wsl.exe
Or open Windows Terminal → click the dropdown → select your Linux distro (Ubuntu, Debian, etc.)

Step 2 — Make sure Docker is running
LinkPlatform requires Docker Desktop with WSL integration enabled.
1. Open Docker Desktop on Windows.
2. Go to Settings → Resources → WSL Integration.
3. Enable your distro (e.g., Ubuntu).
4. Click Apply & Restart.

Verify Docker works inside WSL:
```bash
docker --version
docker compose version
