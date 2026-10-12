# LinkPlatform

## Docker setup

How to install, run, update, back up and troubleshoot LinkPlatform on a Linux Docker host (e.g. a Proxmox VM/LXC). Windows (Docker Desktop) is covered at the end.

Everything runs in **one container** (`app`). Data (database + uploads) lives in the Docker volume **`linkplatform_data`**. Settings live in **`.env`** next to `docker-compose.yml`.

---

### Requirements

- Docker Engine with the Compose plugin (`docker compose version` should work)
- `openssl` (for generating secrets)
- One free TCP port (default `8000`)

---

### 1. Get the files

Copy `linkplatform-v12.1.zip` to `/root/` on the Docker host (192.168.8.100), then:

```bash
mkdir -p /root/linkplatform
unzip -o /root/linkplatform-v12.1.zip -d /root/linkplatform
cd /root/linkplatform
ls docker-compose.yml Dockerfile .env.example   # all three must exist
```

---

### 2. Install

```bash
cd /root/linkplatform
chmod +x setup.sh
./setup.sh            # first install, or update keeping data
./setup.sh --fresh    # wipe everything and start over (asks you to type yes)
```

It asks for the admin email, port and optional domain, builds, waits until healthy, and prints the address, email and a generated password.

### 3. First steps in the app

1. Log in and set a new password.
2. **Bio** (top menu) → **Profile**: change your **Handle** from `admin` to your own (your page becomes `/@yourhandle`), add a photo and tagline, **Save**.
3. **Appearance**: pick **Seasonal** or **Meadow**, toggle the landscape / effects / page elements.
4. **Links**: add links, copy cards, info cards and notices; drag `⋮⋮` to reorder.
5. **Verified badge** (admins only): **Admin → Users → Verify** next to a user. Their page then shows a Verified pill and a check by their name. Click again to remove it.

Public page: `http://192.168.8.100:8000/@yourhandle` (or `https://DOMAIN/@yourhandle`).

---

### Using a domain

#### Behind a tunnel or your own reverse proxy (Cloudflare Tunnel, Nginx Proxy Manager, Traefik…)

1. Set `DOMAIN` during install (or edit `.env`: add the domain to `ALLOWED_HOSTS` and set `BASE_URL=https://your.domain`).
2. Point the tunnel/proxy at `http://192.168.8.100:8000`.
3. Restart: `docker compose up -d`.

With `BASE_URL` on `https://`, login cookies are HTTPS-only, so **log in through the domain**, not the raw IP. For LAN-only use over plain `http://`, leave `BASE_URL` empty (or set `SECURE_COOKIES=false`).

If your proxy runs on the same Docker host/LAN and you want real visitor IPs in stats, set `TRUST_PROXY=true`.

#### Built-in Caddy with automatic HTTPS

Only if ports 80/443 on this host are free and the domain's DNS points here. In `.env` set `DOMAIN=your.domain`, `BASE_URL=https://your.domain`, `APP_BIND=127.0.0.1`, `TRUST_PROXY=true`, then:

```bash
docker compose --profile edge up -d --build
```

When using Caddy, add `--profile edge` to every `docker compose` command below.

---

### Everyday commands

Run from `/root/linkplatform`:

```bash
docker compose ps                    # status
docker compose logs -f app           # live logs (Ctrl+C to quit)
docker compose logs --tail=50 app    # last 50 lines
docker compose restart app           # restart
docker compose down                  # stop (data is kept)
docker compose up -d                 # start
```

---

### Update

Keeps your data and `.env`:

```bash
cd /root/linkplatform
unzip -o /root/linkplatform-v12.1.zip -d /root/linkplatform -x .env
docker compose up -d --build
```

New database columns are added automatically on startup.

---

### Reset a password

```bash
cd /root/linkplatform
docker compose exec -T -e LP_EMAIL='you@example.com' -e LP_PW='NewPassword123!' app python -c "import os,sqlite3; from app.security import hash_password; c=sqlite3.connect('/data/app.db'); n=c.execute('update users set password_hash=?, must_change_password=1, is_active=1 where email=?', (hash_password(os.environ['LP_PW']), os.environ['LP_EMAIL'].strip().lower())).rowcount; c.commit(); print('updated', n)"
```

`updated 1` = done. `updated 0` = no account with that email; list accounts with:

```bash
docker compose exec -T app python -c "import sqlite3; c=sqlite3.connect('/data/app.db'); print(list(c.execute('select email, role, is_active from users')))"
```

### Make an account an admin

```bash
docker compose exec -T -e LP_EMAIL='you@example.com' app python -c "import os,sqlite3; c=sqlite3.connect('/data/app.db'); n=c.execute('update users set role=? where email=?', ('admin', os.environ['LP_EMAIL'].strip().lower())).rowcount; c.commit(); print('updated', n)"
```

---

### Backup & restore

Backup (writes a dated tarball to `/root/linkplatform/backups/`):

```bash
cd /root/linkplatform && mkdir -p backups
docker compose exec -T app python -c "import sqlite3; sqlite3.connect('/data/app.db').execute('PRAGMA wal_checkpoint(TRUNCATE)')"
docker run --rm -v linkplatform_data:/data:ro -v "$PWD/backups":/backup alpine \
  tar czf /backup/linkplatform-$(date +%F-%H%M).tar.gz -C /data .
```

Restore (replaces current data):

```bash
cd /root/linkplatform && docker compose stop app
docker run --rm -v linkplatform_data:/data -v "$PWD/backups":/backup alpine \
  sh -c 'rm -rf /data/* && tar xzf /backup/FILE.tar.gz -C /data && chown -R 10000:10000 /data'
docker compose start app
```

Also keep a copy of `.env` — the `SECRET_KEY` in it signs sessions.

---

### Uninstall

```bash
cd /root/linkplatform
docker compose --profile edge down -v --remove-orphans   # containers + data volume
docker image rm linkplatform:12
```

---

### Troubleshooting

| Symptom | Fix |
|---|---|
| `no configuration file provided: not found` | You're not in the project folder. `cd /root/linkplatform` (must contain `docker-compose.yml`). |
| `Invalid host header` | The address you used isn't in `ALLOWED_HOSTS` in `.env`. Add it (comma-separated, no port), then `docker compose up -d`. |
| "Invalid email or password" on a fresh install | The volume wasn't empty, so the old admin was kept. Use [Reset a password](#reset-a-password), or run `./setup.sh --fresh`. |
| Login succeeds but you bounce back to the login page | `BASE_URL` is `https://…` but you're on plain `http://`. Use the domain, or clear `BASE_URL` / set `SECURE_COOKIES=false`. |
| `port is already allocated` | Change `APP_PORT` in `.env`, then `docker compose up -d`. |
| `That handle is reserved` | Pick another handle — names like `admin`, `api`, `login`, `bio`, `settings` are reserved for new handles. |
| Container keeps restarting | `docker compose logs --tail=80 app` and check the last error. |
| Changes in `.env` ignored | Run `docker compose up -d` (not just `restart`) so the new env is loaded. |

---

## About

A modern, secure, single-container link shortener. FastAPI + server-rendered
Jinja UI, SQLite (WAL) with in-process click batching — no Postgres, no Redis,
no workers, no separate frontend build. One container does everything; an
optional Caddy sidecar adds automatic HTTPS when you configure a domain.

## Visual tour

`linkplatform-v12-tour/` is a click-through gallery of **every page** rendered
from a live demo instance (fictional data): landing, login, register, the
public bio page (desktop + a phone-frame mobile preview), dashboard in dark
**and** light theme, link list/create/stats, the bio editor, files, domains,
settings, API tokens, and all eight admin screens. The pages are real HTML —
open `index.html` in a browser, click around, flip the theme toggle, and watch
the bio header animation run.

Regenerate it after any UI change (needs the project venv):

```bash
/tmp/lp12venv/bin/python scripts/make_tour.py   # -> ~/workspace/your_files/linkplatform-v12-tour/
```

## Architecture

```
                ┌──────────────────────────────┐
                │  app  (linkplatform:12)       │
                │  FastAPI + Jinja UI          │
Internet ──?──▶ │  SQLite WAL in /data         │──▶ named volume linkplatform_data
                │  non-root user (uid 10000)    │
                └──────────────┬───────────────┘
                               │ (only with a domain)
                ┌──────────────▼───────────────┐
                │  caddy  (profile: edge)      │  :80/:443, auto-TLS,
                │  gzip + security headers     │  HSTS, nosniff, SAMEORIGIN
                └──────────────────────────────┘
```

**Resources:** ~1 container (~150–250 MB RAM idle). Compare with v11's
7 containers including a Vite dev server in production.

## Features

**Short links** — create, edit, disable, and delete links; per-link QR codes
(`/links/<id>/qr.png`); click stats with charts (referrers, countries,
devices, browsers); optional expiry dates and interstitial landing pages;
`POST /links/<id>/toggle` for quick enable/disable.

**Bio pages (`/@slug`)** — a full link-in-bio system, not a plain link list:

- Rich bio links with **sections** (e.g. "Social Media", "Projects"), each
  with a hand-drawn inline **SVG brand icon** (33 built in: YouTube, X,
  Facebook, Instagram, TikTok, GitHub, Mastodon, Bluesky, LinkedIn, Twitch,
  Discord, Telegram, WhatsApp, Signal, Reddit, Pinterest, plus generics —
  auto-detected from the URL domain, overridable per link), a short
  description, and up/down arrow reordering.
- Links in a **"Social Media"** section also render as v11-style mini icon
  buttons in a row under the header.
- **Avatar upload** with magic-byte validation; per-profile accent color that
  tints the whole page; `mailto:` links supported.
- Every public bio page gets the animated **tech header**: drifting grid,
  sweeping circuit lines, pulsing glow dots, falling binary/code-glyph rain,
  and a holographic scan sheen — accent-tinted, and static for visitors with
  `prefers-reduced-motion`.
- The bio editor (`/bio/edit`) manages the profile, avatar, and links in one
  place, with per-link edit and active/inactive toggles.

**v12.1 bio refresh (karas.page look)** — public pages now use the karas.page
design: an animated landscape (sky, sun, clouds, city, road, trees, birds,
wind-blown leaves), frosted-glass cards, a tech-animated header, 2–3 column
card grid, colour-coded brand icon tiles, Share/Report buttons, a theme badge
and the full accessibility toolbar (text size, readable font, spacing, link
highlight, contrast, colour themes, stop animations, large cursor, read
aloud). Themes: Meadow, **Seasonal** (holiday theme per month + special days,
with snow/hearts/bats/confetti… particles), Midnight, Sunset, Forest, Ocean,
Mono; optional custom accent colour. Items can be **links, copy-to-clipboard
cards, info cards, warning notices or notes**. Fonts (Outfit, JetBrains Mono,
Atkinson Hyperlegible, SIL OFL) are self-hosted so the strict CSP still holds.

The editor has Profile / Appearance / Links tabs, a **live phone preview** that
updates as you type, an unsaved-changes bar, a visual icon picker, quick
show/hide, and **drag-and-drop reordering** (also between sections; keyboard:
focus the grip and press ↑/↓). New columns (`bio_links.kind`,
`bio_links.color`, `users.bio_prefs`) are added automatically on startup.

**Files** — upload files (magic-byte validated, size-capped) and get public
`/uploads/...` URLs to share or attach to links.

**Custom domains** — attach your own domains to short links, with a DNS
verification flow and per-domain root / not-found fallback URLs. Admins
approve or reject domain requests.

**API** — token-based REST API at `/api/v1` with scopes (`links:read`,
`links:write`), paginated envelopes, per-token prefixes and revocation, and
interactive docs at `/api/docs`.

**Accounts** — registration (can be closed), login with rate limiting,
forced password change on first login, voluntary change requires the current
password, per-user settings and API tokens.

**Moderation** — public `/report` abuse form; admins triage reports, manage
users (activate/deactivate, roles, delete), and review an audit log of
admin actions.

**Theming** — dark mode by default with a one-click light/dark toggle, no
flash on load (a tiny pre-script sets the theme before first paint). Zero
inline scripts anywhere, so the strict `Content-Security-Policy`
(`script-src 'self'`) never silently breaks a feature.

## Security notes

- Passwords hashed with **argon2id** (`pwdlib`); no passlib/bcrypt legacy.
- Admin password is **randomly generated** per install and shown once.
- `SECRET_KEY` is random per install; changing it invalidates all sessions.
- `.env` is written mode `600` and backed up before any installer change.
- Host header validation (`ALLOWED_HOSTS`), CSRF protection, rate limits.
- `X-Forwarded-For` is only trusted from private/loopback peers, and only
  when `TRUST_PROXY=true` (set automatically with a domain). The **last**
  XFF entry is used (the one our proxy appended); earlier entries may be
  client-supplied. In domain mode the app's port binds to 127.0.0.1 so all
  public traffic must pass through Caddy.
- Container runs as **non-root** (uid 10000); image is `python:3.13-slim`
  with pinned dependencies and no build tools left behind.
- Caddy edge (domain mode) adds HSTS, `nosniff`, `SAMEORIGIN`, and strips
  the `Server` header.

