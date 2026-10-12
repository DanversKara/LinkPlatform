# LinkPlatform v12 -- Windows (Docker Desktop) setup.
# Right-click > "Run with PowerShell", or from PowerShell: .\Setup.ps1
# Re-running is safe: upgrades keep your existing .env and data.
$ErrorActionPreference = "Stop"
$LP_VERSION = "12.1.0"

function Step($msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }
function Die($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }
function Read-Default($prompt, $default) {
    $v = Read-Host "$prompt [$default]"
    if ([string]::IsNullOrWhiteSpace($v)) { $default } else { $v.Trim() }
}
function Random-Hex($bytes) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $b = New-Object byte[] $bytes
    $rng.GetBytes($b)
    -join ($b | ForEach-Object { $_.ToString("x2") })
}
function Random-Password($length) {
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $b = New-Object byte[] $length
    $rng.GetBytes($b)
    -join ($b | ForEach-Object { $chars[$_ % $chars.Length] })
}

Set-Location $PSScriptRoot
$LP_DIR = $PSScriptRoot

Step "Checking prerequisites (LinkPlatform v$LP_VERSION)"
try { docker info 2>&1 | Out-Null } catch { Die "docker daemon is not reachable. Start Docker Desktop and try again." }
if ($LASTEXITCODE -ne 0) { Die "docker daemon is not reachable. Start Docker Desktop and try again." }
try { docker compose version 2>&1 | Out-Null } catch { Die "docker compose is missing." }
Write-Host "Docker OK: $(docker --version)"

$fresh = -not (Test-Path "$LP_DIR\.env")
if ($fresh) {
    Step "First-time configuration"
    $DOMAIN = Read-Host "Public domain for auto-HTTPS (blank = local/LAN only)"
    $DOMAIN = $DOMAIN.Trim()
    $ADMIN_EMAIL = Read-Default "Admin email" "admin@example.com"
    $APP_PORT = Read-Default "Host port for the app" "8000"

    $SECRET_KEY = Random-Hex 32
    $ADMIN_PASSWORD = Random-Password 16

    $lanIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        Select-Object -ExpandProperty IPAddress)
    $ALLOWED_HOSTS = "localhost,127.0.0.1"
    if ($lanIps) { $ALLOWED_HOSTS += "," + ($lanIps -join ",") }
    if ($DOMAIN) { $ALLOWED_HOSTS += ",$DOMAIN" }

    if ($DOMAIN) { $TRUST_PROXY = "true";  $BASE_URL = "https://$DOMAIN"; $APP_BIND = "127.0.0.1" }
    else         { $TRUST_PROXY = "false"; $BASE_URL = "";               $APP_BIND = "0.0.0.0" }

    $envLines = Get-Content "$LP_DIR\.env.example"
    $subs = @{
        '^APP_PORT=.*'       = "APP_PORT=$APP_PORT"
        '^APP_BIND=.*'       = "APP_BIND=$APP_BIND"
        '^DOMAIN=.*'         = "DOMAIN=$DOMAIN"
        '^BASE_URL=.*'       = "BASE_URL=$BASE_URL"
        '^SECRET_KEY=.*'     = "SECRET_KEY=$SECRET_KEY"
        '^ALLOWED_HOSTS=.*'  = "ALLOWED_HOSTS=$ALLOWED_HOSTS"
        '^TRUST_PROXY=.*'    = "TRUST_PROXY=$TRUST_PROXY"
        '^ADMIN_EMAIL=.*'    = "ADMIN_EMAIL=$ADMIN_EMAIL"
        '^ADMIN_PASSWORD=.*' = "ADMIN_PASSWORD=$ADMIN_PASSWORD"
    }
    $out = foreach ($line in $envLines) {
        $done = $false
        foreach ($k in $subs.Keys) {
            if ($line -match $k) { $subs[$k]; $done = $true; break }
        }
        if (-not $done) { $line }
    }
    # UTF-8 without BOM so Linux tools read it cleanly
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines("$LP_DIR\.env", $out, $utf8)
    Write-Host ".env written."
} else {
    Step "Existing install detected -- keeping your .env and data"
    $DOMAIN = ""
    $envContent = Get-Content "$LP_DIR\.env" -Raw
    if ($envContent -match '(?m)^DOMAIN=(.+)\s*$') { $DOMAIN = $Matches[1].Trim() }
    $APP_PORT = "8000"
    if ($envContent -match '(?m)^APP_PORT=(.+)\s*$') { $APP_PORT = $Matches[1].Trim() }
}

$composeArgs = @()
if ($DOMAIN) { $composeArgs += "--profile"; $composeArgs += "edge" }

if ($fresh) {
    Step "Removing leftover LinkPlatform containers from earlier installs"
    $old = docker ps -a --filter "name=linkplatform" -q
    if ($old) { docker rm -f $old | Out-Null }
}

Step "Building and starting the app (a few minutes on first run)"
& docker compose @composeArgs up -d --build
if ($LASTEXITCODE -ne 0) { Die "docker compose failed." }

Step "Waiting for a healthy app (up to 120s)"
$ok = $false
for ($i = 0; $i -lt 120; $i++) {
    try {
        $r = Invoke-RestMethod "http://127.0.0.1:$APP_PORT/api/health" -TimeoutSec 3
        if ($r.ok -or $r.status -eq "ok") { $ok = $true; break }
    } catch { }
    Start-Sleep 1
}
if (-not $ok) {
    Write-Host "App did not become healthy in time. Last logs:" -ForegroundColor Red
    & docker compose @composeArgs logs --tail=50 app
    Die "startup failed -- see logs above."
}

if ($fresh) {
    # Make sure the printed login works even if an old data volume survived:
    # point the first admin account at this email/password.
    Step "Setting the admin login"
    $py = "import os,sqlite3; from app.security import hash_password; c=sqlite3.connect('/data/app.db'); " +
          "c.execute('update users set email=?, password_hash=?, must_change_password=1, is_active=1 where id=(select min(id) from users where role=?)', " +
          "(os.environ['LP_EMAIL'].strip().lower(), hash_password(os.environ['LP_PW']), 'admin')); c.commit(); print('admin login ready')"
    & docker compose @composeArgs exec -T -e "LP_EMAIL=$ADMIN_EMAIL" -e "LP_PW=$ADMIN_PASSWORD" app python -c $py
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host " LinkPlatform v$LP_VERSION is up!" -ForegroundColor Green
Write-Host "   Open:   http://localhost:$APP_PORT"
if ($fresh) {
    Write-Host "   Email:  $ADMIN_EMAIL"
    Write-Host "   Password: $ADMIN_PASSWORD  (change it after first login)"
    Write-Host ""
    Write-Host "   Save that password -- it is only shown here." -ForegroundColor Yellow
}
Write-Host "   Manage: docker compose logs -f app   |   docker compose down"
Write-Host "======================================================================"
