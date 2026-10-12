# LinkPlatform: Docker setup

How to install, run, update, back up and troubleshoot LinkPlatform on a Linux Docker host (e.g. a Proxmox VM/LXC). Windows (Docker Desktop) is covered at the end.

Everything runs in **one container** (`app`). Data (database + uploads) lives in the Docker volume **`linkplatform_data`**. Settings live in **`.env`** next to `docker-compose.yml`.

---

## Requirements

- Docker Engine with the Compose plugin (`docker compose version` should work)
- `openssl` (for generating secrets)
- One free TCP port (default `8000`)

---

## 1. Get the files

Copy the project to the server and unzip it so `docker-compose.yml` is directly inside the folder:

```bash
mkdir -p ~/linkplatform && cd ~/linkplatform
unzip -o /path/to/linkplatform-v12.1-bio-refresh.zip
ls docker-compose.yml Dockerfile .env.example   # all three must exist
```

---

## 2. Fresh install

> ⚠️ This **deletes all LinkPlatform data** (users, links, bio pages, uploads). Skip the first line if you are upgrading — see [Update](#update).

Edit the three values on the second line, then paste the whole block:

```bash
cd ~/linkplatform && docker compose --profile edge down -v --remove-orphans; docker volume rm -f linkplatform_data
EMAIL=you@example.com; PORT=8000; DOMAIN=
PW=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16); IPS=$(hostname -I | xargs | tr ' ' ',')
cp .env.example .env && sed -i \
  -e "s|^SECRET_KEY=.*|SECRET_KEY=$(openssl rand -hex 32)|" \
  -e "s|^ADMIN_EMAIL=.*|ADMIN_EMAIL=$EMAIL|" \
  -e "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=$PW|" \
  -e "s|^APP_PORT=.*|APP_PORT=$PORT|" \
  -e "s|^ALLOWED_HOSTS=.*|ALLOWED_HOSTS=localhost,127.0.0.1,$IPS${DOMAIN:+,$DOMAIN}|" \
  -e "s|^BASE_URL=.*|BASE_URL=${DOMAIN:+https://$DOMAIN}|" .env && chmod 600 .env
docker compose up -d --build
echo "LOGIN: http://$(hostname -I | awk '{print $1}'):$PORT   email: $EMAIL   password: $PW"
```

| Value | Meaning |
|---|---|
| `EMAIL` | Admin login email |
| `PORT` | Host port. Change it if something else already uses `8000` (e.g. `8010`) |
| `DOMAIN` | Public hostname if you'll reach it through a tunnel / reverse proxy (e.g. `links.example.com`). Leave empty for LAN-only |

**Save the password it prints** — it is only shown once. On first login you'll be asked to choose a new one.

Check it's up:

```bash
docker compose ps
curl -s http://127.0.0.1:8000/api/health     # {"ok":true,...}
```

> The admin account is created **only on the first start of an empty volume**. Changing `ADMIN_EMAIL` / `ADMIN_PASSWORD` in `.env` later does nothing — use [Reset a password](#reset-a-password) instead.

---

## 3. First steps in the app

1. Log in and set a new password.
2. **Bio** (top menu) → **Profile**: change your **Handle** from `admin` to your own (your page becomes `/@yourhandle`), add a photo and tagline, **Save**.
3. **Appearance**: pick **Seasonal** or **Meadow**, toggle the landscape / effects / page elements.
4. **Links**: add links, copy cards, info cards and notices; drag `⋮⋮` to reorder.

Public page: `http://SERVER:PORT/@yourhandle` (or `https://DOMAIN/@yourhandle`).

---

## Using a domain

### Behind a tunnel or your own reverse proxy (Cloudflare Tunnel, Nginx Proxy Manager, Traefik…)

1. Set `DOMAIN` during install (or edit `.env`: add the domain to `ALLOWED_HOSTS` and set `BASE_URL=https://your.domain`).
2. Point the tunnel/proxy at `http://SERVER_IP:PORT`.
3. Restart: `docker compose up -d`.

With `BASE_URL` on `https://`, login cookies are HTTPS-only, so **log in through the domain**, not the raw IP. For LAN-only use over plain `http://`, leave `BASE_URL` empty (or set `SECURE_COOKIES=false`).

If your proxy runs on the same Docker host/LAN and you want real visitor IPs in stats, set `TRUST_PROXY=true`.

### Built-in Caddy with automatic HTTPS

Only if ports 80/443 on this host are free and the domain's DNS points here. In `.env` set `DOMAIN=your.domain`, `BASE_URL=https://your.domain`, `APP_BIND=127.0.0.1`, `TRUST_PROXY=true`, then:

```bash
docker compose --profile edge up -d --build
```

When using Caddy, add `--profile edge` to every `docker compose` command below.

---

## Everyday commands

Run from `~/linkplatform`:

```bash
docker compose ps                    # status
docker compose logs -f app           # live logs (Ctrl+C to quit)
docker compose logs --tail=50 app    # last 50 lines
docker compose restart app           # restart
docker compose down                  # stop (data is kept)
docker compose up -d                 # start
```

---

## Update

Keeps your data and `.env`:

```bash
cd ~/linkplatform
unzip -o /path/to/new-version.zip -x .env      # don't overwrite your .env
docker compose up -d --build
```

New database columns are added automatically on startup.

---

## Reset a password

```bash
cd ~/linkplatform
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

## Backup & restore

Backup (writes a dated tarball to `~/linkplatform/backups/`):

```bash
cd ~/linkplatform && mkdir -p backups
docker compose exec -T app python -c "import sqlite3; sqlite3.connect('/data/app.db').execute('PRAGMA wal_checkpoint(TRUNCATE)')"
docker run --rm -v linkplatform_data:/data:ro -v "$PWD/backups":/backup alpine \
  tar czf /backup/linkplatform-$(date +%F-%H%M).tar.gz -C /data .
```

Restore (replaces current data):

```bash
cd ~/linkplatform && docker compose stop app
docker run --rm -v linkplatform_data:/data -v "$PWD/backups":/backup alpine \
  sh -c 'rm -rf /data/* && tar xzf /backup/FILE.tar.gz -C /data && chown -R 10000:10000 /data'
docker compose start app
```

Also keep a copy of `.env` — the `SECRET_KEY` in it signs sessions.

---

## Uninstall

```bash
cd ~/linkplatform
docker compose --profile edge down -v --remove-orphans   # containers + data volume
docker image rm linkplatform:12
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `no configuration file provided: not found` | You're not in the project folder. `cd ~/linkplatform` (must contain `docker-compose.yml`). |
| `Invalid host header` | The address you used isn't in `ALLOWED_HOSTS` in `.env`. Add it (comma-separated, no port), then `docker compose up -d`. |
| "Invalid email or password" on a fresh install | The volume wasn't empty, so the old admin was kept. Use [Reset a password](#reset-a-password), or rerun the [fresh install](#2-fresh-install) block (it deletes the volume first). |
| Login succeeds but you bounce back to the login page | `BASE_URL` is `https://…` but you're on plain `http://`. Use the domain, or clear `BASE_URL` / set `SECURE_COOKIES=false`. |
| `port is already allocated` | Change `APP_PORT` in `.env`, then `docker compose up -d`. |
| `That handle is reserved` | Pick another handle — names like `admin`, `api`, `login`, `bio`, `settings` are reserved for new handles. |
| Container keeps restarting | `docker compose logs --tail=80 app` and check the last error. |
| Changes in `.env` ignored | Run `docker compose up -d` (not just `restart`) so the new env is loaded. |

---

## Windows (Docker Desktop)

In PowerShell, inside the unzipped folder:

```powershell
Remove-Item .env -ErrorAction SilentlyContinue      # fresh install only
powershell -ExecutionPolicy Bypass -File .\Setup.ps1
```

It asks for domain, admin email and port, builds, and prints the admin password. Manage with the same `docker compose` commands as above.
