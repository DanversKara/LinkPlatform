#!/usr/bin/env bash
# LinkPlatform — Linux Docker setup.
#   ./setup.sh            first install, or update keeping data + .env
#   ./setup.sh --fresh    wipe data + .env and start over (asks to confirm)
set -euo pipefail
cd "$(dirname "$0")"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }
ask() {  # prompt goes to the terminal (stderr), answer is echoed for $(...)
  local v=""
  printf '%s [%s]: ' "$1" "$2" >&2
  if [ -r /dev/tty ] && { exec 3</dev/tty; } 2>/dev/null; then read -r v <&3 || true; exec 3<&-
  else read -r v || true; fi
  echo "${v:-$2}"
}

command -v docker >/dev/null || die "docker is not installed."
docker compose version >/dev/null 2>&1 || die "docker compose plugin is missing."
command -v openssl >/dev/null || die "openssl is not installed (apt install openssl)."
[ -f docker-compose.yml ] && [ -f .env.example ] || die "run this from the LinkPlatform folder."

if [ "${1:-}" = "--fresh" ]; then
  echo "This DELETES all LinkPlatform data (users, links, bio pages, uploads) and .env."
  [ "$(ask 'Type yes to continue' 'no')" = "yes" ] || die "cancelled."
  say "Removing old containers, data and .env"
  docker compose --profile edge down -v --remove-orphans || true
  docker volume rm -f linkplatform_data >/dev/null 2>&1 || true
  rm -f .env
fi

FRESH=0
if [ ! -f .env ]; then
  FRESH=1
  say "First-time configuration"
  while :; do
    EMAIL=$(ask "Admin email (your login)" "admin@example.com")
    [[ "$EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] && break
    echo "  That doesn't look like an email address — try again." >&2
  done
  while :; do
    PORT=$(ask "Port to open in the browser" "8000")
    [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] && break
    echo "  Port must be a number like 8000 — try again." >&2
  done
  DOMAIN=$(ask "Domain, e.g. links.example.com (press Enter for none)" "")
  DOMAIN=$(echo "$DOMAIN" | sed -E 's#^https?://##; s#/.*$##')
  [[ -z "$DOMAIN" || "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || { echo "  Ignoring invalid domain '$DOMAIN'." >&2; DOMAIN=""; }
  PW=$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 16)
  IPS=$(hostname -I 2>/dev/null | xargs | tr ' ' ',')
  HOSTS="localhost,127.0.0.1${IPS:+,$IPS}${DOMAIN:+,$DOMAIN}"
  cp .env.example .env
  sed -i \
    -e "s|^SECRET_KEY=.*|SECRET_KEY=$(openssl rand -hex 32)|" \
    -e "s|^ADMIN_EMAIL=.*|ADMIN_EMAIL=$EMAIL|" \
    -e "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=$PW|" \
    -e "s|^APP_PORT=.*|APP_PORT=$PORT|" \
    -e "s|^ALLOWED_HOSTS=.*|ALLOWED_HOSTS=$HOSTS|" \
    -e "s|^BASE_URL=.*|BASE_URL=${DOMAIN:+https://$DOMAIN}|" .env
  chmod 600 .env
else
  say "Existing .env found — keeping it and your data"
  PORT=$(grep -E '^APP_PORT=' .env | cut -d= -f2); PORT=${PORT:-8000}
  DOMAIN=$(grep -E '^BASE_URL=' .env | cut -d= -f2 | sed 's|^https\?://||')
fi

say "Building and starting (first run takes a minute or two)"
docker compose up -d --build

say "Waiting for the app to be healthy"
for _ in $(seq 1 90); do
  curl -fs "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fs "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 || {
  docker compose logs --tail=40 app; die "app did not become healthy."; }

if [ "$FRESH" = 1 ]; then
  # Guarantee the printed login works even if an old data volume survived.
  docker compose exec -T -e LP_EMAIL="$EMAIL" -e LP_PW="$PW" app python -c "import os,sqlite3; from app.security import hash_password; c=sqlite3.connect('/data/app.db'); c.execute('update users set email=?, password_hash=?, must_change_password=1, is_active=1 where id=(select min(id) from users where role=?)', (os.environ['LP_EMAIL'].strip().lower(), hash_password(os.environ['LP_PW']), 'admin')); c.commit()"
fi

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
echo
echo "======================================================================"
echo " LinkPlatform is running"
echo "   Open:     http://${IP:-SERVER-IP}:$PORT${DOMAIN:+   or   https://$DOMAIN}"
if [ "$FRESH" = 1 ]; then
  echo "   Email:    $EMAIL"
  echo "   Password: $PW   (shown once — you'll set a new one at first login)"
fi
echo "   Logs:     docker compose logs -f app"
echo "======================================================================"
