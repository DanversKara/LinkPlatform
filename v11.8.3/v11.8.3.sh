#!/bin/bash
set -e

# ╔══════════════════════════════════════════════════════════════════╗
# ║          ⚙️  SITE CONFIGURATION — Edit values here              ║
# ╚══════════════════════════════════════════════════════════════════╝

SITE_NAME="LinkPlatform"
SITE_EMOJI="🔗"
SITE_TAGLINE="Shorten, track, and manage your links. Create beautiful bio profiles."
SITE_FOOTER="© 2026 ${SITE_NAME}. All rights reserved."
SITE_VERSION="11.8.3"

BACKEND_PORT=8000
FRONTEND_PORT=3000

# ── DEPLOY DOMAIN (optional) ───────────────────────────────────────────────────
# Set this to your domain (e.g. "mylinks.com") so the app works via
# localhost, local IP *and* your domain from the very first deploy.
# Leave blank to use localhost-only mode.
DEPLOY_DOMAIN=""   # e.g. DEPLOY_DOMAIN="mylinks.com"
# ─────────────────────────────────────────────────────────────────────────────

# Public-facing URLs — auto-computed from DEPLOY_DOMAIN when set
if [ -n "$DEPLOY_DOMAIN" ]; then
  BACKEND_URL="http://${DEPLOY_DOMAIN}"
  FRONTEND_URL="http://${DEPLOY_DOMAIN}"
else
  BACKEND_URL="http://localhost:${BACKEND_PORT}"
  FRONTEND_URL="http://localhost:${FRONTEND_PORT}"
fi

# Internal URL always hits localhost (used for health checks; avoids DNS dependency)
INTERNAL_BACKEND_URL="http://localhost:${BACKEND_PORT}"

ADMIN_EMAIL="admin@admin.admin"
ADMIN_PASSWORD="admin"
DEFAULT_THEME_COLOR="#a78bfa"

# Default SMTP settings (will be stored in database and editable via admin UI)
SMTP_HOST="localhost"
SMTP_PORT="25"
SMTP_USER=""
SMTP_PASSWORD=""
SMTP_USE_TLS="false"

# 🔧 FIX: Export variables so docker-compose can read them
export BACKEND_PORT FRONTEND_PORT BACKEND_URL FRONTEND_URL INTERNAL_BACKEND_URL DEPLOY_DOMAIN
export SITE_NAME SITE_EMOJI SITE_TAGLINE SITE_FOOTER SITE_VERSION
export ADMIN_EMAIL ADMIN_PASSWORD DEFAULT_THEME_COLOR
export SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASSWORD SMTP_USE_TLS

# ════════════════════════════════════════════════════════════════════

echo "🎨 === ${SITE_NAME} — V${SITE_VERSION} ==="
echo "🔍 Checking prerequisites..."

# Auto-install Docker on Debian/Ubuntu if missing
if ! command -v docker >/dev/null 2>&1; then
  echo "⚠️  Docker not found."
  if command -v apt-get >/dev/null 2>&1; then
    echo "📦 Installing Docker via apt..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq docker.io docker-compose curl openssl
    sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER" 2>/dev/null || true
    echo "✅ Docker installed."
  else
    echo "❌ Please install Docker manually: https://docs.docker.com/get-docker/"
    exit 1
  fi
fi

MISSING=0
command -v docker >/dev/null 2>&1 || { echo "❌ Docker required"; MISSING=1; }

if command -v docker-compose >/dev/null 2>&1; then
  DOCKER_COMPOSE="docker-compose"
elif docker compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE="docker compose"
else
  echo "❌ docker-compose or docker compose required"
  MISSING=1
fi

command -v openssl >/dev/null 2>&1 || { echo "❌ openssl required"; MISSING=1; }

[ $MISSING -eq 1 ] && {
  echo "💡 Install Docker: https://docs.docker.com/get-docker/"
  exit 1
}

echo "✅ Prerequisites OK"

PROJECT_DIR="$HOME/link-platform"

# ============================================================================
# UPGRADE-SAFE DIRECTORY HANDLING
# ============================================================================
if [ -d "$PROJECT_DIR" ]; then
  echo ""
  echo "⚠️  Existing installation detected at $PROJECT_DIR"
  echo "   Code files will be OVERWRITTEN. Database and uploads are SAFE."
  read -p "   Continue? (y/n): " CONFIRM
  if [ "$CONFIRM" != "y" ] && [ "$CONFIRM" != "Y" ]; then
    echo "Installation cancelled."
    exit 0
  fi
  echo "📦 Stopping containers..."
  cd "$PROJECT_DIR" && ($DOCKER_COMPOSE stop 2>/dev/null || true) && cd ~
fi

mkdir -p "$PROJECT_DIR" && cd "$PROJECT_DIR"
mkdir -p backend/app/{routers,utils,templates,uploads,services,workers}
mkdir -p frontend/src/{pages,components,styles,context}
mkdir -p nginx

echo "📁 Project structure created"

# ============================================================================
# BACKEND
# ============================================================================
echo "⚙️  Creating backend files..."

# ---------- requirements.txt ----------
cat > backend/requirements.txt << 'EOF'
fastapi>=0.109.0,<0.110.0
uvicorn[standard]==0.24.0
sqlalchemy==2.0.23
psycopg2-binary==2.9.9
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
python-multipart==0.0.6
qrcode[pil]==7.4.2
python-dotenv==1.0.0
pydantic-settings>=2.0.0,<3.0.0
pydantic>=2.0.0,<3.0.0
jinja2==3.1.2
bcrypt==4.0.1
aiofiles==23.2.1
pyotp==2.8.0
redis==5.0.1
slowapi==0.1.9
user-agents==2.2.0
EOF

# ---------- Dockerfile ----------
cat > backend/Dockerfile << 'EOF'
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p uploads
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--log-level", "info"]
EOF

# ---------- .env (initial, will be overridden by DB settings later) ----------
cat > backend/.env << EOF
DATABASE_URL=postgresql://user:pass@db:5432/linkplatform
SECRET_KEY=changeme
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
BASE_URL=${BACKEND_URL}
FRONTEND_URL=${FRONTEND_URL}
SITE_NAME=${SITE_NAME}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_USER=${SMTP_USER}
SMTP_PASSWORD=${SMTP_PASSWORD}
SMTP_USE_TLS=${SMTP_USE_TLS}
DEFAULT_THEME_COLOR=${DEFAULT_THEME_COLOR}
REDIS_URL=redis://redis:6379/0
CLICK_RETENTION_DAYS=90
EOF

# ---------- config.py ----------
cat > backend/app/config.py << 'EOF'
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    BASE_URL: str = "http://localhost:8000"
    FRONTEND_URL: str = "http://localhost:3000"
    SITE_NAME: str = "LinkPlatform"
    ADMIN_EMAIL: str = "admin@admin.admin"
    ADMIN_PASSWORD: str = "admin"
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 25
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = False
    SITE_TAGLINE: str = "Shorten, track, and manage your links. Create beautiful bio profiles."
    SITE_FOOTER: str = "© 2026 LinkPlatform. All rights reserved."
    SITE_EMOJI: str = "🔗"
    SITE_VERSION: str = "11.8.2"
    DEFAULT_THEME_COLOR: str = "#a78bfa"
    REDIS_URL: str = "redis://redis:6379/0"
    CLICK_RETENTION_DAYS: int = 90

    class Config:
        env_file = ".env"

settings = Settings()
EOF

# ---------- database.py ----------
cat > backend/app/database.py << 'EOF'
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .config import settings
engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
EOF

# ---------- models.py ----------
cat > backend/app/models.py << 'EOF'
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, func
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_banned = Column(Boolean, default=False)
    is_suspended = Column(Boolean, default=False)
    role = Column(String, default="user")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    custom_slug = Column(String, unique=True, index=True, nullable=True)
    profile_photo_url = Column(String, nullable=True)
    header_image_url = Column(String, nullable=True)
    bio_description = Column(Text, default="")
    header_text = Column(String, nullable=True)
    sub_header_text = Column(String, nullable=True)
    theme_color = Column(String, default="#a78bfa")
    profile_redirect_url = Column(String, nullable=True)
    is_redirect_enabled = Column(Boolean, default=False)
    show_social_icons = Column(Boolean, default=True)
    page_bg_url = Column(String, nullable=True)
    header_style = Column(String, default="solid")
    theme_html = Column(Text, nullable=True)
    daily_status = Column(Text, nullable=True)
    status_updated_at = Column(DateTime(timezone=True), nullable=True)
    profile_layout = Column(String, default="center")
    profile_photo_style = Column(String, default="circle")
    slug_style = Column(String, default="vertical-rotate")
    header_image_size = Column(String, default="half")
    header_bg_opacity = Column(String, default="0.45")
    is_verified = Column(Boolean, default=False)
    is_sensitive = Column(Boolean, default=False)
    age_restriction = Column(Boolean, default=False)
    cookie_popup = Column(Boolean, default=False)
    show_share_icon = Column(Boolean, default=True)
    remove_branding = Column(Boolean, default=False)
    profile_password = Column(String, nullable=True)
    display_avatar = Column(Boolean, default=True)
    avatar_style = Column(String, default="none")
    can_use_custom_domain = Column(Boolean, default=False)
    profile_views = Column(Integer, default=0)
    twofa_enabled = Column(Boolean, default=False)
    twofa_secret = Column(String, nullable=True)
    twofa_backup_codes = Column(Text, nullable=True)
    twofa_last_reset_at = Column(DateTime(timezone=True), nullable=True)
    reset_password_token = Column(String, nullable=True, index=True)
    reset_password_expires = Column(DateTime(timezone=True), nullable=True)
    accept_messages = Column(Boolean, default=True)
    links = relationship("Link", back_populates="user")
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.recipient_id", back_populates="recipient")
    profile_tabs = relationship("ProfileTab", back_populates="user", cascade="all, delete-orphan")
    social_icons = relationship("SocialIcon", back_populates="user", cascade="all, delete-orphan")
    profile_reports = relationship("ProfileReport", back_populates="reported_user", cascade="all, delete-orphan")

class Link(Base):
    __tablename__ = "links"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    original_url = Column(Text, nullable=False)
    short_code = Column(String, unique=True, index=True, nullable=False)
    title = Column(String)
    is_active = Column(Boolean, default=True)
    clicks = Column(Integer, default=0)
    landing_page_enabled = Column(Boolean, default=False)
    landing_page_title = Column(String, nullable=True)
    landing_page_body = Column(Text, nullable=True)
    landing_page_image = Column(String, nullable=True)
    landing_page_theme = Column(String, default="default")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", back_populates="links")
    click_events = relationship("Click", back_populates="link", cascade="all, delete-orphan")

class Click(Base):
    __tablename__ = "clicks"
    id = Column(Integer, primary_key=True, index=True)
    link_id = Column(Integer, ForeignKey("links.id", ondelete="SET NULL"), nullable=True)
    ip = Column(String, nullable=True)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    device = Column(String, nullable=True)
    browser = Column(String, nullable=True)
    os = Column(String, nullable=True)
    referer = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    link = relationship("Link", back_populates="click_events")

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    guest_name = Column(String, nullable=True)
    guest_email = Column(String, nullable=True)
    subject = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    reply_to_id = Column(Integer, ForeignKey("messages.id"), nullable=True)
    status = Column(String, default="unread")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")

class ProfileTab(Base):
    __tablename__ = "profile_tabs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String, nullable=False)
    slug = Column(String, nullable=False)
    display_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    tab_type = Column(String, default="links")
    tab_style = Column(String, default="solid")
    bg_url = Column(String, nullable=True)
    text_content = Column(Text, nullable=True)
    tab_bg_opacity = Column(String, default="0.85")
    tab_text_color = Column(String, nullable=True)
    user = relationship("User", back_populates="profile_tabs")
    links = relationship("ProfileLink", back_populates="tab", cascade="all, delete-orphan")

class ProfileLink(Base):
    __tablename__ = "profile_links"
    id = Column(Integer, primary_key=True, index=True)
    tab_id = Column(Integer, ForeignKey("profile_tabs.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    url = Column(String, nullable=False)
    thumbnail_url = Column(String, nullable=True)
    display_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    link_type = Column(String, default="url")
    tab = relationship("ProfileTab", back_populates="links")

class SocialIcon(Base):
    __tablename__ = "social_icons"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    platform = Column(String, nullable=False)
    url = Column(String, nullable=False)
    icon_url = Column(String, nullable=True)
    display_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    user = relationship("User", back_populates="social_icons")

class ProfileReport(Base):
    __tablename__ = "profile_reports"
    id = Column(Integer, primary_key=True, index=True)
    reporter_email = Column(String, nullable=True)
    reporter_ip = Column(String, nullable=True)
    reported_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reason = Column(String, nullable=False)
    details = Column(Text, nullable=True)
    status = Column(String, default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    reported_user = relationship("User", back_populates="profile_reports")

class CustomDomain(Base):
    __tablename__ = "custom_domains"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    domain = Column(String, unique=True, index=True, nullable=False)
    root_redirect = Column(String, nullable=True)
    not_found_redirect = Column(String, nullable=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    user = relationship("User", backref="custom_domain")

class SiteConfig(Base):
    __tablename__ = "site_config"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, nullable=False)
    value = Column(Text, nullable=True)

class NavItem(Base):
    __tablename__ = "nav_items"
    id = Column(Integer, primary_key=True, index=True)
    label = Column(String, nullable=False)
    path = Column(String, nullable=False)
    icon = Column(String, nullable=True)
    auth_required = Column(Boolean, default=False)
    admin_only = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True)
    order = Column(Integer, default=0)
    is_system = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Page(Base):
    __tablename__ = "pages"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    slug = Column(String, unique=True, index=True, nullable=False)
    content = Column(Text, nullable=False)
    published = Column(Boolean, default=True)
    meta_title = Column(String, nullable=True)
    meta_description = Column(Text, nullable=True)
    category = Column(String, nullable=True)
    language = Column(String, default="en")
    menu_visible = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class EmailTemplate(Base):
    __tablename__ = "email_templates"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, unique=True, index=True, nullable=False)
    subject = Column(String, nullable=False)
    body_html = Column(Text, nullable=True)
    body_text = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True)
    for_admin = Column(Boolean, default=False)
EOF

# ---------- schemas.py ----------
cat > backend/app/schemas.py << 'EOF'
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    email: str

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    is_banned: Optional[bool] = None
    is_suspended: Optional[bool] = None
    custom_slug: Optional[str] = None
    profile_photo_url: Optional[str] = None
    header_image_url: Optional[str] = None
    bio_description: Optional[str] = None
    header_text: Optional[str] = None
    sub_header_text: Optional[str] = None
    theme_color: Optional[str] = None
    profile_redirect_url: Optional[str] = None
    is_redirect_enabled: Optional[bool] = None
    show_social_icons: Optional[bool] = None
    page_bg_url: Optional[str] = None
    header_style: Optional[str] = None
    theme_html: Optional[str] = None
    daily_status: Optional[str] = None
    profile_layout: Optional[str] = None
    profile_photo_style: Optional[str] = None
    accept_messages: Optional[bool] = None
    slug_style: Optional[str] = None
    header_image_size: Optional[str] = None
    header_bg_opacity: Optional[str] = None
    is_verified: Optional[bool] = None
    is_sensitive: Optional[bool] = None
    age_restriction: Optional[bool] = None
    cookie_popup: Optional[bool] = None
    show_share_icon: Optional[bool] = None
    remove_branding: Optional[bool] = None
    profile_password: Optional[str] = None
    display_avatar: Optional[bool] = None
    avatar_style: Optional[str] = None
    can_use_custom_domain: Optional[bool] = None

class UserOut(UserBase):
    id: int
    is_active: bool
    is_banned: Optional[bool] = None
    is_suspended: Optional[bool] = None
    role: str = "user"
    created_at: datetime
    custom_slug: Optional[str] = None
    profile_photo_url: Optional[str] = None
    daily_status: Optional[str] = None
    status_updated_at: Optional[datetime] = None
    accept_messages: bool = True
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800
    requires_2fa: bool = False
    temp_token: Optional[str] = None

class TokenRefresh(BaseModel):
    refresh_token: str

class Verify2FA(BaseModel):
    code: str
    temp_token: Optional[str] = None

class Disable2FA(BaseModel):
    password: str

class ForgotPassword(BaseModel):
    email: str

class ResetPassword(BaseModel):
    token: str
    new_password: str

class LinkBase(BaseModel):
    original_url: str
    short_code: Optional[str] = None
    title: Optional[str] = None
    landing_page_enabled: Optional[bool] = False
    landing_page_title: Optional[str] = None
    landing_page_body: Optional[str] = None
    landing_page_image: Optional[str] = None
    landing_page_theme: Optional[str] = "default"

class LinkCreate(LinkBase):
    pass

class LinkUpdate(BaseModel):
    original_url: Optional[str] = None
    short_code: Optional[str] = None
    title: Optional[str] = None
    is_active: Optional[bool] = None
    landing_page_enabled: Optional[bool] = None
    landing_page_title: Optional[str] = None
    landing_page_body: Optional[str] = None
    landing_page_image: Optional[str] = None
    landing_page_theme: Optional[str] = None

class LinkOut(LinkBase):
    id: int
    user_id: Optional[int]
    is_active: bool
    clicks: int
    created_at: datetime
    class Config:
        from_attributes = True

class MessageBase(BaseModel):
    subject: str
    content: str
    recipient_id: Optional[int] = None
    recipient_slug: Optional[str] = None
    reply_to_id: Optional[int] = None
    guest_name: Optional[str] = None
    guest_email: Optional[str] = None

class MessageCreate(MessageBase):
    pass

class MessageOut(MessageBase):
    id: int
    sender_id: Optional[int] = None
    status: str
    created_at: datetime
    sender_email: Optional[str] = None
    recipient_email: Optional[str] = None
    guest_name: Optional[str] = None
    guest_email: Optional[str] = None
    class Config:
        from_attributes = True

class SocialIconBase(BaseModel):
    platform: str
    url: str
    icon_url: Optional[str] = None
    display_order: Optional[int] = None

class SocialIconCreate(SocialIconBase):
    pass

class SocialIconOut(SocialIconBase):
    id: int
    user_id: int
    is_active: bool
    class Config:
        from_attributes = True

class ProfileLinkCreate(BaseModel):
    title: str
    description: Optional[str] = None
    url: str
    thumbnail_url: Optional[str] = None
    display_order: Optional[int] = 0
    link_type: Optional[str] = "url"

class ProfileLinkUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    thumbnail_url: Optional[str] = None
    display_order: Optional[int] = None
    is_active: Optional[bool] = None
    link_type: Optional[str] = None

class ProfileLinkOut(BaseModel):
    id: int
    tab_id: int
    title: str
    description: Optional[str] = None
    url: str
    thumbnail_url: Optional[str] = None
    display_order: int
    is_active: bool
    link_type: str = "url"
    class Config:
        from_attributes = True

class ProfileTabCreate(BaseModel):
    title: str
    slug: Optional[str] = None
    tab_type: Optional[str] = "links"
    tab_style: Optional[str] = "solid"
    display_order: Optional[int] = 0
    bg_url: Optional[str] = None
    text_content: Optional[str] = None
    tab_bg_opacity: Optional[str] = "0.85"
    tab_text_color: Optional[str] = None

class ProfileTabUpdate(BaseModel):
    title: Optional[str] = None
    slug: Optional[str] = None
    tab_type: Optional[str] = None
    tab_style: Optional[str] = None
    display_order: Optional[int] = None
    is_active: Optional[bool] = None
    bg_url: Optional[str] = None
    text_content: Optional[str] = None
    tab_bg_opacity: Optional[str] = None
    tab_text_color: Optional[str] = None

class ProfileTabOut(BaseModel):
    id: int
    user_id: int
    title: str
    slug: str
    tab_type: str
    tab_style: str
    display_order: int
    is_active: bool
    bg_url: Optional[str] = None
    text_content: Optional[str] = None
    tab_bg_opacity: str = "0.85"
    tab_text_color: Optional[str] = None
    created_at: datetime
    links: List[ProfileLinkOut] = []
    class Config:
        from_attributes = True

class PublicProfileOut(BaseModel):
    id: int
    email: str
    custom_slug: Optional[str]
    profile_photo_url: Optional[str]
    header_image_url: Optional[str]
    bio_description: str
    header_text: Optional[str] = None
    sub_header_text: Optional[str] = None
    theme_color: str
    profile_redirect_url: Optional[str]
    is_redirect_enabled: bool
    show_social_icons: bool
    page_bg_url: Optional[str] = None
    header_style: str = "solid"
    theme_html: Optional[str] = None
    daily_status: Optional[str] = None
    status_updated_at: Optional[datetime] = None
    profile_layout: str = "center"
    profile_photo_style: str = "circle"
    slug_style: str = "vertical-rotate"
    header_image_size: str = "half"
    header_bg_opacity: str = "0.45"
    is_verified: bool = False
    is_sensitive: bool = False
    age_restriction: bool = False
    cookie_popup: bool = False
    show_share_icon: bool = True
    remove_branding: bool = False
    profile_password: Optional[str] = None
    display_avatar: bool = True
    avatar_style: str = "none"
    profile_views: int = 0
    can_use_custom_domain: bool = False
    tabs: List[ProfileTabOut] = []
    social_icons: List[SocialIconOut] = []
    class Config:
        from_attributes = True

class AdminStats(BaseModel):
    total_users: int
    total_links: int
    total_clicks: int
    total_profile_views: int
    total_messages: int
    total_reports: int
    pending_reports: int

class AdminReportOut(BaseModel):
    id: int
    reporter_email: Optional[str] = None
    reporter_ip: Optional[str] = None
    reported_user_id: int
    reason: str
    details: Optional[str] = None
    status: str
    created_at: datetime
    reported_slug: Optional[str] = None
    reported_email: Optional[str] = None
    class Config:
        from_attributes = True

class AdminReportUpdate(BaseModel):
    status: str  # pending, reviewed, dismissed

class SiteConfigOut(BaseModel):
    key: str
    value: Optional[str] = None

class SiteConfigUpdate(BaseModel):
    value: str

class SMTPSettings(BaseModel):
    host: str
    port: int
    user: str
    password: str
    use_tls: bool

class TestEmail(BaseModel):
    to_email: str

class NavItemBase(BaseModel):
    label: str
    path: str
    icon: Optional[str] = None
    auth_required: bool = False
    admin_only: bool = False
    enabled: bool = True
    order: int = 0

class NavItemCreate(NavItemBase):
    pass

class NavItemUpdate(BaseModel):
    label: Optional[str] = None
    path: Optional[str] = None
    icon: Optional[str] = None
    auth_required: Optional[bool] = None
    admin_only: Optional[bool] = None
    enabled: Optional[bool] = None
    order: Optional[int] = None

class NavItemOut(NavItemBase):
    id: int
    is_system: bool
    created_at: datetime
    class Config:
        from_attributes = True

class PageBase(BaseModel):
    title: str
    slug: str
    content: str
    published: bool = True
    meta_title: Optional[str] = None
    meta_description: Optional[str] = None
    category: Optional[str] = None
    language: Optional[str] = "en"
    menu_visible: Optional[bool] = True

class PageCreate(PageBase):
    pass

class PageUpdate(BaseModel):
    title: Optional[str] = None
    slug: Optional[str] = None
    content: Optional[str] = None
    published: Optional[bool] = None
    meta_title: Optional[str] = None
    meta_description: Optional[str] = None
    category: Optional[str] = None
    language: Optional[str] = None
    menu_visible: Optional[bool] = None

class PageOut(PageBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    class Config:
        from_attributes = True

class ProfileReportCreate(BaseModel):
    slug: str
    reason: str
    details: Optional[str] = None
    reporter_email: Optional[str] = None

class ContactForm(BaseModel):
    name: str
    email: str
    subject: str
    message: str

class CustomDomainCreate(BaseModel):
    domain: str
    root_redirect: Optional[str] = None
    not_found_redirect: Optional[str] = None

class CustomDomainUpdate(BaseModel):
    root_redirect: Optional[str] = None
    not_found_redirect: Optional[str] = None

class CustomDomainOut(BaseModel):
    id: int
    user_id: int
    domain: str
    root_redirect: Optional[str] = None
    not_found_redirect: Optional[str] = None
    is_verified: bool
    created_at: datetime
    class Config:
        from_attributes = True

class AdminDomainOut(CustomDomainOut):
    user_email: Optional[str] = None
    user_slug: Optional[str] = None

class UserListOut(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool
    is_banned: bool
    is_suspended: bool
    custom_slug: Optional[str]
    profile_photo_url: Optional[str]
    accept_messages: bool = True
    can_use_custom_domain: bool = False
    class Config:
        from_attributes = True

class TwoFAStatus(BaseModel):
    enabled: bool
    has_backup_codes: bool
    last_reset_at: Optional[datetime] = None

class TwoFASetup(BaseModel):
    generate_backup_codes: bool = True

class TwoFAReset(BaseModel):
    confirm: bool = True

class EmailTemplateBase(BaseModel):
    key: str
    subject: str
    body_html: Optional[str] = None
    body_text: Optional[str] = None
    enabled: bool = True
    for_admin: bool = False

class EmailTemplateCreate(EmailTemplateBase):
    pass

class EmailTemplateUpdate(BaseModel):
    subject: Optional[str] = None
    body_html: Optional[str] = None
    body_text: Optional[str] = None
    enabled: Optional[bool] = None

class EmailTemplateOut(EmailTemplateBase):
    id: int
    class Config:
        from_attributes = True

class SendTestEmail(BaseModel):
    to_email: str
    template_key: str
    context: dict = {}

class ClickOut(BaseModel):
    id: int
    link_id: Optional[int] = None
    ip: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    device: Optional[str] = None
    browser: Optional[str] = None
    os: Optional[str] = None
    referer: Optional[str] = None
    created_at: datetime
    class Config:
        from_attributes = True

class LinkStatsOut(BaseModel):
    link_id: int
    short_code: str
    title: Optional[str] = None
    original_url: str
    total_clicks: int
    unique_ips: int
    top_countries: List[dict] = []
    top_referers: List[dict] = []
    top_devices: List[dict] = []
    clicks_by_day: List[dict] = []

class PlatformStatsOut(BaseModel):
    total_clicks_today: int
    total_clicks_week: int
    total_clicks_all: int
    top_links: List[dict] = []
EOF

# ---------- auth.py ----------
cat > backend/app/auth.py << 'EOF'
from datetime import datetime, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from . import models
from .database import get_db
from .config import settings
import secrets

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def get_password_hash(pw): return pwd_context.hash(pw)
def normalize_email(email: str) -> str:
    return email.strip().lower()

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_temp_token(data: dict, expires_delta: timedelta = timedelta(minutes=5)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire, "type": "temp"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_token(token: str, expected_type: str = "access"):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != expected_type: return None
        return payload
    except JWTError:
        return None

def generate_reset_token(length=32):
    return secrets.token_urlsafe(length)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_token(token, "access")
    if not payload: raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    email = payload.get("sub")
    if not email: raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token", headers={"WWW-Authenticate": "Bearer"})
    user = db.query(models.User).filter(models.User.email == normalize_email(email)).first()
    if not user or user.is_banned:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or banned", headers={"WWW-Authenticate": "Bearer"})
    return user

async def get_current_active_user(current_user=Depends(get_current_user)):
    if not current_user.is_active or current_user.is_suspended:
        raise HTTPException(status_code=400, detail="Inactive or suspended user")
    return current_user

async def get_current_admin_user(current_user=Depends(get_current_active_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

async def get_current_moderator_user(current_user=Depends(get_current_active_user)):
    if current_user.role not in ["admin", "moderator"]:
        raise HTTPException(status_code=403, detail="Moderator or admin privileges required")
    return current_user
EOF

# ---------- email_utils.py ----------
cat > backend/app/email_utils.py << 'EOF'
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy.orm import Session

from .models import EmailTemplate, SiteConfig
from .config import settings

def get_site_setting(db: Session, key: str, default: str = "") -> str:
    cfg = db.query(SiteConfig).filter(SiteConfig.key == key).first()
    return cfg.value if cfg and cfg.value is not None else default

def get_smtp_settings(db: Session):
    """Retrieve SMTP settings from database, falling back to env."""
    return {
        "host": get_site_setting(db, "smtp_host", settings.SMTP_HOST),
        "port": int(get_site_setting(db, "smtp_port", str(settings.SMTP_PORT))),
        "user": get_site_setting(db, "smtp_user", settings.SMTP_USER),
        "password": get_site_setting(db, "smtp_password", settings.SMTP_PASSWORD),
        "use_tls": get_site_setting(db, "smtp_use_tls", str(settings.SMTP_USE_TLS)).lower() == "true",
    }

def render_email(db: Session, key: str, context: dict) -> tuple[str, str, str]:
    tpl = db.query(models.EmailTemplate).filter(models.EmailTemplate.key == key, models.EmailTemplate.enabled == True).first()
    if not tpl:
        subject = context.get("subject", key)
        text = context.get("text", "")
        return subject, text, text
    subject = tpl.subject.format(**context)
    body_text = (tpl.body_text or "").format(**context)
    body_html = (tpl.body_html or "").format(**context)
    if not body_html:
        body_html = f"<pre>{body_text}</pre>"
    return subject, body_text, body_html

def send_email_raw(to_email: str, subject: str, text: str, html: str | None, smtp: dict):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.ADMIN_EMAIL
    msg["To"] = to_email
    part1 = MIMEText(text, "plain")
    msg.attach(part1)
    if html:
        part2 = MIMEText(html, "html")
        msg.attach(part2)
    try:
        if smtp["user"] and smtp["password"]:
            server = smtplib.SMTP(smtp["host"], smtp["port"])
            if smtp["use_tls"]:
                server.starttls()
            server.login(smtp["user"], smtp["password"])
        else:
            server = smtplib.SMTP(smtp["host"], smtp["port"])
        server.sendmail(settings.ADMIN_EMAIL, [to_email], msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Email send error: {e}")
        raise

def send_templated_email(db: Session, key: str, to_email: str, context: dict):
    smtp = get_smtp_settings(db)
    subject, text, html = render_email(db, key, context)
    send_email_raw(to_email, subject, text, html, smtp)
EOF


# ============================================================================
# SERVICES LAYER
# ============================================================================
echo "🔧 Creating services layer..."
touch backend/app/services/__init__.py
touch backend/app/workers/__init__.py

cat > backend/app/services/redis_client.py << 'REOF'
import redis
import os
import json

_client = None

def get_redis():
    global _client
    if _client is None:
        redis_url = os.environ.get("REDIS_URL", "redis://redis:6379/0")
        try:
            _client = redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=2)
            _client.ping()
        except Exception as e:
            print(f"Redis unavailable: {e} — direct DB writes used")
            _client = None
    return _client

def push_click_event(event: dict) -> bool:
    r = get_redis()
    if r is None:
        return False
    try:
        r.lpush("click_queue", json.dumps(event))
        return True
    except Exception as e:
        print(f"Redis push failed: {e}")
        return False

def pop_click_event():
    r = get_redis()
    if r is None:
        return None
    try:
        result = r.brpop("click_queue", timeout=5)
        if result:
            return json.loads(result[1])
    except Exception as e:
        print(f"Redis pop failed: {e}")
    return None

def cache_set(key: str, value: str, ttl: int = 300):
    r = get_redis()
    if r:
        try:
            r.setex(key, ttl, value)
        except Exception:
            pass

def cache_get(key: str):
    r = get_redis()
    if r:
        try:
            return r.get(key)
        except Exception:
            pass
    return None
REOF

cat > backend/app/services/analytics_service.py << 'AEOF'
from sqlalchemy.orm import Session
from sqlalchemy import func
from .. import models
from datetime import datetime, timedelta, timezone

class AnalyticsService:

    @staticmethod
    def record_click(db: Session, link_id: int, event: dict):
        click = models.Click(
            link_id=link_id,
            ip=event.get("ip"),
            country=event.get("country"),
            city=event.get("city"),
            device=event.get("device"),
            browser=event.get("browser"),
            os=event.get("os"),
            referer=event.get("referer"),
        )
        db.add(click)
        db.query(models.Link).filter(models.Link.id == link_id).update(
            {models.Link.clicks: models.Link.clicks + 1}
        )
        db.commit()

    @staticmethod
    def get_link_stats(db: Session, link_id: int) -> dict:
        link = db.query(models.Link).filter(models.Link.id == link_id).first()
        if not link:
            return {}
        clicks_q = db.query(models.Click).filter(models.Click.link_id == link_id)
        unique_ips = clicks_q.with_entities(
            func.count(func.distinct(models.Click.ip))
        ).scalar() or 0
        countries = (
            db.query(models.Click.country, func.count(models.Click.id).label("cnt"))
            .filter(models.Click.link_id == link_id, models.Click.country.isnot(None))
            .group_by(models.Click.country)
            .order_by(func.count(models.Click.id).desc()).limit(5).all()
        )
        referers = (
            db.query(models.Click.referer, func.count(models.Click.id).label("cnt"))
            .filter(models.Click.link_id == link_id, models.Click.referer.isnot(None))
            .group_by(models.Click.referer)
            .order_by(func.count(models.Click.id).desc()).limit(5).all()
        )
        devices = (
            db.query(models.Click.device, func.count(models.Click.id).label("cnt"))
            .filter(models.Click.link_id == link_id, models.Click.device.isnot(None))
            .group_by(models.Click.device)
            .order_by(func.count(models.Click.id).desc()).limit(5).all()
        )
        fourteen_ago = datetime.now(timezone.utc) - timedelta(days=14)
        by_day = (
            db.query(
                func.date(models.Click.created_at).label("day"),
                func.count(models.Click.id).label("cnt")
            )
            .filter(models.Click.link_id == link_id, models.Click.created_at >= fourteen_ago)
            .group_by(func.date(models.Click.created_at))
            .order_by(func.date(models.Click.created_at)).all()
        )
        return {
            "link_id": link.id,
            "short_code": link.short_code,
            "title": link.title,
            "original_url": link.original_url,
            "total_clicks": link.clicks,
            "unique_ips": unique_ips,
            "top_countries": [{"country": r.country, "count": r.cnt} for r in countries],
            "top_referers": [{"referer": r.referer, "count": r.cnt} for r in referers],
            "top_devices": [{"device": r.device, "count": r.cnt} for r in devices],
            "clicks_by_day": [{"day": str(r.day), "count": r.cnt} for r in by_day],
        }

    @staticmethod
    def get_platform_stats(db: Session) -> dict:
        now = datetime.now(timezone.utc)
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_ago = now - timedelta(days=7)
        total_all = db.query(func.count(models.Click.id)).scalar() or 0
        total_today = db.query(func.count(models.Click.id)).filter(
            models.Click.created_at >= today).scalar() or 0
        total_week = db.query(func.count(models.Click.id)).filter(
            models.Click.created_at >= week_ago).scalar() or 0
        top_links = (
            db.query(models.Link.short_code, models.Link.title,
                     models.Link.clicks, models.Link.original_url)
            .order_by(models.Link.clicks.desc()).limit(10).all()
        )
        return {
            "total_clicks_today": total_today,
            "total_clicks_week": total_week,
            "total_clicks_all": total_all,
            "top_links": [
                {"short_code": r.short_code, "title": r.title,
                 "clicks": r.clicks, "original_url": r.original_url}
                for r in top_links
            ],
        }
AEOF

cat > backend/app/services/redirect_service.py << 'RREOF'
from sqlalchemy.orm import Session
from .. import models
from .redis_client import push_click_event
from .analytics_service import AnalyticsService

class RedirectService:

    @staticmethod
    def resolve_link(db: Session, short_code: str):
        return db.query(models.Link).filter(
            models.Link.short_code == short_code,
            models.Link.is_active == True
        ).first()

    @staticmethod
    def record_click(db: Session, link: models.Link, request_info: dict):
        event = {
            "link_id": link.id,
            "ip": request_info.get("ip"),
            "referer": request_info.get("referer"),
            "user_agent": request_info.get("user_agent"),
            "country": request_info.get("country"),
            "city": request_info.get("city"),
            "device": request_info.get("device"),
            "browser": request_info.get("browser"),
            "os": request_info.get("os"),
        }
        queued = push_click_event(event)
        if not queued:
            AnalyticsService.record_click(db, link.id, event)
        else:
            link.clicks += 1
            db.commit()
RREOF

# ============================================================================
# WORKERS
# ============================================================================
echo "⚙️  Creating workers..."

cat > backend/app/workers/click_processor.py << 'WEOF'
"""Click Queue Worker — reads from Redis and writes to PostgreSQL."""
import sys, time, logging, os
sys.path.insert(0, "/app")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [click-worker] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("click_worker")

def parse_ua(ua_string):
    if not ua_string:
        return {}
    try:
        from user_agents import parse
        ua = parse(ua_string)
        device = "mobile" if ua.is_mobile else ("tablet" if ua.is_tablet else "desktop")
        return {"device": device, "browser": ua.browser.family, "os": ua.os.family}
    except Exception:
        return {}

def main():
    from app.database import SessionLocal
    from app.services.redis_client import pop_click_event
    from app.services.analytics_service import AnalyticsService

    logger.info("Click worker started — listening on Redis queue...")
    errors = 0
    while True:
        db = None
        try:
            event = pop_click_event()
            if event is None:
                continue
            ua_info = parse_ua(event.get("user_agent"))
            enriched = {
                "ip": event.get("ip"),
                "referer": event.get("referer"),
                "country": event.get("country"),
                "city": event.get("city"),
                "device": ua_info.get("device") or event.get("device"),
                "browser": ua_info.get("browser") or event.get("browser"),
                "os": ua_info.get("os") or event.get("os"),
            }
            db = SessionLocal()
            AnalyticsService.record_click(db, event["link_id"], enriched)
            errors = 0
        except Exception as e:
            errors += 1
            logger.error(f"Worker error: {e}")
            if errors > 10:
                time.sleep(30); errors = 0
            else:
                time.sleep(2)
        finally:
            if db:
                db.close()

if __name__ == "__main__":
    main()
WEOF

cat > backend/app/workers/cleanup_worker.py << 'CLEOF'
"""Cleanup Worker — prunes old click data hourly."""
import sys, time, logging, os
sys.path.insert(0, "/app")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [cleanup] %(levelname)s %(message)s")
logger = logging.getLogger("cleanup_worker")

RETENTION = int(os.environ.get("CLICK_RETENTION_DAYS", "90"))

def run():
    from app.database import SessionLocal
    from app import models
    from datetime import datetime, timedelta, timezone
    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION)
        n = db.query(models.Click).filter(models.Click.created_at < cutoff).delete()
        db.commit()
        if n:
            logger.info(f"Pruned {n} click records older than {RETENTION} days")
    except Exception as e:
        logger.error(f"Cleanup error: {e}"); db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    logger.info("Cleanup worker started (hourly)")
    while True:
        run()
        time.sleep(3600)
CLEOF

# ============================================================================
# ANALYTICS ROUTER
# ============================================================================
echo "📊 Creating analytics router..."

cat > backend/app/routers/analytics.py << 'ANEOF'
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import schemas, models, auth
from ..database import get_db
from ..services.analytics_service import AnalyticsService

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

@router.get("/links/{link_id}")
def get_link_stats(link_id: int, db: Session = Depends(get_db),
                   current_user=Depends(auth.get_current_active_user)):
    link = db.query(models.Link).filter(
        models.Link.id == link_id, models.Link.user_id == current_user.id
    ).first()
    if not link:
        raise HTTPException(404, "Link not found")
    return AnalyticsService.get_link_stats(db, link_id)

@router.get("/platform")
def get_platform_stats(db: Session = Depends(get_db),
                       admin=Depends(auth.get_current_admin_user)):
    return AnalyticsService.get_platform_stats(db)
ANEOF


# ---------- routers/auth.py ----------
cat > backend/app/routers/auth.py << 'EOF'
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from .. import schemas, models
from ..database import get_db
from ..auth import (
    verify_password, get_password_hash,
    create_access_token, create_refresh_token, decode_token,
    normalize_email, create_temp_token, generate_reset_token
)
from ..config import settings
from ..email_utils import send_templated_email
import pyotp

router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/register", response_model=schemas.UserOut)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    email = normalize_email(user.email)
    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(400, "Email already registered")
    new_user = models.User(
        email=email,
        password_hash=get_password_hash(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post("/login", response_model=schemas.Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email = normalize_email(form.username)
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(401, "Incorrect email or password")
    if not user.is_active:
        raise HTTPException(400, "Account is inactive")
    if user.is_banned:
        raise HTTPException(403, "Account is banned")
    if user.is_suspended:
        raise HTTPException(403, "Account is suspended")

    if user.twofa_enabled:
        temp_token = create_temp_token({"sub": user.email, "role": user.role})
        return {
            "access_token": "",
            "refresh_token": "",
            "token_type": "bearer",
            "expires_in": 300,
            "requires_2fa": True,
            "temp_token": temp_token
        }

    access_token = create_access_token({"sub": user.email, "role": user.role})
    refresh_token = create_refresh_token({"sub": user.email, "role": user.role})
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "requires_2fa": False
    }

@router.post("/verify-2fa", response_model=schemas.Token)
def verify_2fa(data: schemas.Verify2FA, db: Session = Depends(get_db)):
    if not data.temp_token:
        raise HTTPException(400, "Missing temp token")
    payload = decode_token(data.temp_token, "temp")
    if not payload:
        raise HTTPException(401, "Invalid or expired temp token")
    email = payload.get("sub")
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.twofa_enabled:
        raise HTTPException(400, "2FA not enabled")

    totp = pyotp.TOTP(user.twofa_secret)
    if totp.verify(data.code):
        access_token = create_access_token({"sub": user.email, "role": user.role})
        refresh_token = create_refresh_token({"sub": user.email, "role": user.role})
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "requires_2fa": False
        }
    else:
        if user.twofa_backup_codes:
            codes = user.twofa_backup_codes.split("\n")
            if data.code in codes:
                codes.remove(data.code)
                user.twofa_backup_codes = "\n".join(codes) if codes else None
                db.commit()
                access_token = create_access_token({"sub": user.email, "role": user.role})
                refresh_token = create_refresh_token({"sub": user.email, "role": user.role})
                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": "bearer",
                    "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                    "requires_2fa": False
                }
        raise HTTPException(400, "Invalid code")

@router.post("/refresh", response_model=schemas.Token)
def refresh_token(body: schemas.TokenRefresh, db: Session = Depends(get_db)):
    payload = decode_token(body.refresh_token, "refresh")
    if not payload:
        raise HTTPException(401, "Invalid or expired refresh token")
    email = normalize_email(payload.get("sub", ""))
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.is_active or user.is_banned or user.is_suspended:
        raise HTTPException(401, "User not found or inactive")
    access_token = create_access_token({"sub": user.email, "role": user.role})
    new_refresh = create_refresh_token({"sub": user.email, "role": user.role})
    return {
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "requires_2fa": False
    }

@router.post("/forgot-password")
def forgot_password(data: schemas.ForgotPassword, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    email = normalize_email(data.email)
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return {"ok": True, "message": "If that email exists, a reset link has been sent."}
    
    token = generate_reset_token()
    user.reset_password_token = token
    user.reset_password_expires = datetime.utcnow() + timedelta(hours=1)
    db.commit()
    
    reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    context = {
        "name": user.email.split('@')[0],
        "reset_link": reset_link,
        "site_name": settings.SITE_NAME
    }
    background_tasks.add_task(send_templated_email, db, "password_reset", user.email, context)
    
    return {"ok": True, "message": "If that email exists, a reset link has been sent."}

@router.post("/reset-password")
def reset_password(data: schemas.ResetPassword, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(
        models.User.reset_password_token == data.token,
        models.User.reset_password_expires > datetime.utcnow()
    ).first()
    if not user:
        raise HTTPException(400, "Invalid or expired reset token")
    
    user.password_hash = get_password_hash(data.new_password)
    user.reset_password_token = None
    user.reset_password_expires = None
    db.commit()
    
    return {"ok": True, "message": "Password updated successfully"}
EOF

# ---------- routers/profile.py ----------
cat > backend/app/routers/profile.py << 'PROFILE_EOF'
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Optional
import os, uuid, re
from datetime import datetime, timezone
from .. import schemas, models, auth
from ..database import get_db
from ..config import settings
from ..auth import normalize_email
from pydantic import BaseModel

router = APIRouter(prefix="/api/profile", tags=["profile"])
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "uploads")

class IconUpdate(BaseModel):
    icon_url: Optional[str] = None
    url: Optional[str] = None

@router.get("/me", response_model=schemas.UserOut)
def get_profile(current_user=Depends(auth.get_current_active_user)):
    return current_user

@router.put("/me", response_model=schemas.UserOut)
def update_profile(update: schemas.UserUpdate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    if update.email is not None:
        new_email = normalize_email(update.email)
        if new_email != current_user.email:
            existing = db.query(models.User).filter(models.User.email == new_email).first()
            if existing:
                raise HTTPException(400, "Email already registered")
            current_user.email = new_email
    if update.password is not None:
        current_user.password_hash = auth.get_password_hash(update.password)
    if update.accept_messages is not None:
        current_user.accept_messages = update.accept_messages
    db.commit()
    db.refresh(current_user)
    return current_user

@router.get("/me/bio", response_model=schemas.PublicProfileOut)
def get_bio_profile(current_user=Depends(auth.get_current_active_user)):
    return current_user

@router.put("/me/bio", response_model=schemas.PublicProfileOut)
def update_bio_profile(profile: dict, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    fields = [
        'custom_slug','profile_photo_url','header_image_url','bio_description','theme_color',
        'profile_redirect_url','is_redirect_enabled','show_social_icons','header_text','sub_header_text',
        'page_bg_url','header_style','theme_html','daily_status',
        'profile_layout','profile_photo_style',
        'slug_style','header_image_size','header_bg_opacity',
        'is_verified','is_sensitive','age_restriction','cookie_popup',
        'show_share_icon','remove_branding','profile_password',
        'display_avatar','avatar_style'
    ]
    for field in fields:
        if field in profile and profile[field] is not None:
            setattr(current_user, field, profile[field])
    if 'daily_status' in profile:
        current_user.status_updated_at = datetime.now(timezone.utc)
    clear_fields = ['page_bg_url','header_image_url','profile_photo_url','theme_html','daily_status','profile_password']
    for field in clear_fields:
        if field in profile and profile[field] == '':
            setattr(current_user, field, None)
    if 'custom_slug' in profile and profile['custom_slug'] and profile['custom_slug'] != current_user.custom_slug:
        existing = db.query(models.User).filter(models.User.custom_slug == profile['custom_slug'], models.User.id != current_user.id).first()
        if existing:
            raise HTTPException(400, "Slug already taken")
    db.commit()
    db.refresh(current_user)
    return current_user

@router.post("/upload")
async def upload_file(file: UploadFile = File(...), current_user=Depends(auth.get_current_active_user)):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    if not file.content_type or not file.content_type.startswith('image/'):
        raise HTTPException(400, "Only image files allowed")
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(400, "File must be less than 10MB")
    ext = os.path.splitext(file.filename)[1] if file.filename else ".png"
    fname = f"{uuid.uuid4().hex}{ext}"
    with open(os.path.join(UPLOAD_DIR, fname), "wb") as f:
        f.write(content)
    return {"url": f"{settings.BASE_URL}/uploads/{fname}"}

@router.get("/me/bio/social-icons", response_model=List[schemas.SocialIconOut])
def list_social_icons(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    return db.query(models.SocialIcon).filter(models.SocialIcon.user_id == current_user.id).order_by(models.SocialIcon.display_order).all()

@router.post("/me/bio/social-icons", response_model=schemas.SocialIconOut)
def add_social_icon(icon: schemas.SocialIconCreate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    new_icon = models.SocialIcon(**icon.dict(), user_id=current_user.id)
    db.add(new_icon)
    db.commit()
    db.refresh(new_icon)
    return new_icon

@router.put("/me/bio/social-icons/{icon_id}", response_model=schemas.SocialIconOut)
def update_social_icon(icon_id: int, icon_data: IconUpdate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    icon = db.query(models.SocialIcon).filter(models.SocialIcon.id == icon_id, models.SocialIcon.user_id == current_user.id).first()
    if not icon:
        raise HTTPException(404, "Icon not found")
    if icon_data.icon_url is not None:
        icon.icon_url = icon_data.icon_url
    if icon_data.url is not None:
        icon.url = icon_data.url
    db.commit()
    db.refresh(icon)
    return icon

@router.delete("/me/bio/social-icons/{icon_id}")
def delete_social_icon(icon_id: int, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    icon = db.query(models.SocialIcon).filter(models.SocialIcon.id == icon_id, models.SocialIcon.user_id == current_user.id).first()
    if not icon:
        raise HTTPException(404, "Icon not found")
    db.delete(icon)
    db.commit()
    return {"ok": True}

@router.get("/me/bio/tabs", response_model=List[schemas.ProfileTabOut])
def list_tabs(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    tabs = db.query(models.ProfileTab).filter(models.ProfileTab.user_id == current_user.id).order_by(models.ProfileTab.display_order).all()
    for tab in tabs:
        tab.links = db.query(models.ProfileLink).filter(models.ProfileLink.tab_id == tab.id).order_by(models.ProfileLink.display_order).all()
    return tabs

@router.post("/me/bio/tabs", response_model=schemas.ProfileTabOut)
def create_tab(tab: schemas.ProfileTabCreate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    slug = tab.slug or re.sub(r'[^a-z0-9-]', '-', tab.title.lower())
    count = db.query(models.ProfileTab).filter(models.ProfileTab.user_id == current_user.id).count()
    new_tab = models.ProfileTab(
        user_id=current_user.id, title=tab.title, slug=slug,
        tab_type=tab.tab_type or "links", tab_style=tab.tab_style or "solid",
        display_order=count, bg_url=tab.bg_url, text_content=tab.text_content,
        tab_bg_opacity=tab.tab_bg_opacity or "0.85", tab_text_color=tab.tab_text_color
    )
    db.add(new_tab)
    db.commit()
    db.refresh(new_tab)
    new_tab.links = []
    return new_tab

@router.put("/me/bio/tabs/{tab_id}", response_model=schemas.ProfileTabOut)
def update_tab(tab_id: int, update: schemas.ProfileTabUpdate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    tab = db.query(models.ProfileTab).filter(models.ProfileTab.id == tab_id, models.ProfileTab.user_id == current_user.id).first()
    if not tab:
        raise HTTPException(404, "Tab not found")
    for field, val in update.dict(exclude_unset=True).items():
        setattr(tab, field, val)
    db.commit()
    db.refresh(tab)
    tab.links = db.query(models.ProfileLink).filter(models.ProfileLink.tab_id == tab.id).order_by(models.ProfileLink.display_order).all()
    return tab

@router.delete("/me/bio/tabs/{tab_id}")
def delete_tab(tab_id: int, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    tab = db.query(models.ProfileTab).filter(models.ProfileTab.id == tab_id, models.ProfileTab.user_id == current_user.id).first()
    if not tab:
        raise HTTPException(404, "Tab not found")
    db.delete(tab)
    db.commit()
    return {"ok": True}

@router.post("/me/bio/tabs/{tab_id}/links", response_model=schemas.ProfileLinkOut)
def add_tab_link(tab_id: int, link: schemas.ProfileLinkCreate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    tab = db.query(models.ProfileTab).filter(models.ProfileTab.id == tab_id, models.ProfileTab.user_id == current_user.id).first()
    if not tab:
        raise HTTPException(404, "Tab not found")
    count = db.query(models.ProfileLink).filter(models.ProfileLink.tab_id == tab_id).count()
    new_link = models.ProfileLink(tab_id=tab_id, title=link.title, description=link.description,
                                   url=link.url, thumbnail_url=link.thumbnail_url, display_order=count, link_type=link.link_type or "url")
    db.add(new_link)
    db.commit()
    db.refresh(new_link)
    return new_link

@router.put("/me/bio/tabs/{tab_id}/links/{link_id}", response_model=schemas.ProfileLinkOut)
def update_tab_link(tab_id: int, link_id: int, update: schemas.ProfileLinkUpdate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    tab = db.query(models.ProfileTab).filter(models.ProfileTab.id == tab_id, models.ProfileTab.user_id == current_user.id).first()
    if not tab:
        raise HTTPException(404, "Tab not found")
    link = db.query(models.ProfileLink).filter(models.ProfileLink.id == link_id, models.ProfileLink.tab_id == tab_id).first()
    if not link:
        raise HTTPException(404, "Link not found")
    for field, val in update.dict(exclude_unset=True).items():
        setattr(link, field, val)
    db.commit()
    db.refresh(link)
    return link

@router.delete("/me/bio/tabs/{tab_id}/links/{link_id}")
def delete_tab_link(tab_id: int, link_id: int, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    tab = db.query(models.ProfileTab).filter(models.ProfileTab.id == tab_id, models.ProfileTab.user_id == current_user.id).first()
    if not tab:
        raise HTTPException(404, "Tab not found")
    link = db.query(models.ProfileLink).filter(models.ProfileLink.id == link_id, models.ProfileLink.tab_id == tab_id).first()
    if not link:
        raise HTTPException(404, "Link not found")
    db.delete(link)
    db.commit()
    return {"ok": True}
PROFILE_EOF

# ---------- routers/links.py ----------
cat > backend/app/routers/links.py << 'LINKS_EOF'
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import schemas, models, auth
from ..database import get_db
import random, string

def gen_code(n=6): return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

router = APIRouter(prefix="/api/links", tags=["links"])

@router.post("/", response_model=schemas.LinkOut)
def create_link(link: schemas.LinkCreate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    code = link.short_code or gen_code()
    if db.query(models.Link).filter(models.Link.short_code == code).first():
        raise HTTPException(400, "Short code taken")
    new_link = models.Link(user_id=current_user.id, original_url=link.original_url, short_code=code,
                            title=link.title, landing_page_enabled=link.landing_page_enabled or False,
                            landing_page_title=link.landing_page_title, landing_page_body=link.landing_page_body,
                            landing_page_image=link.landing_page_image, landing_page_theme=link.landing_page_theme)
    db.add(new_link)
    db.commit()
    db.refresh(new_link)
    return new_link

@router.get("/", response_model=list[schemas.LinkOut])
def list_links(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    return db.query(models.Link).filter(models.Link.user_id == current_user.id).all()

@router.get("/{link_id}", response_model=schemas.LinkOut)
def get_link(link_id: int, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    link = db.query(models.Link).filter(models.Link.id == link_id, models.Link.user_id == current_user.id).first()
    if not link:
        raise HTTPException(404, "Link not found")
    return link

@router.put("/{link_id}", response_model=schemas.LinkOut)
def update_link(link_id: int, update: schemas.LinkUpdate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    link = db.query(models.Link).filter(models.Link.id == link_id, models.Link.user_id == current_user.id).first()
    if not link:
        raise HTTPException(404, "Link not found")
    if update.original_url is not None: link.original_url = update.original_url
    if update.short_code is not None:
        if db.query(models.Link).filter(models.Link.short_code == update.short_code, models.Link.id != link_id).first():
            raise HTTPException(400, "Short code taken")
        link.short_code = update.short_code
    if update.title is not None: link.title = update.title
    if update.is_active is not None: link.is_active = update.is_active
    if update.landing_page_enabled is not None: link.landing_page_enabled = update.landing_page_enabled
    if update.landing_page_title is not None: link.landing_page_title = update.landing_page_title
    if update.landing_page_body is not None: link.landing_page_body = update.landing_page_body
    if update.landing_page_image is not None: link.landing_page_image = update.landing_page_image
    if update.landing_page_theme is not None: link.landing_page_theme = update.landing_page_theme
    db.commit()
    db.refresh(link)
    return link

@router.delete("/{link_id}")
def delete_link(link_id: int, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    link = db.query(models.Link).filter(models.Link.id == link_id, models.Link.user_id == current_user.id).first()
    if not link:
        raise HTTPException(404, "Link not found")
    db.delete(link)
    db.commit()
    return {"ok": True}
LINKS_EOF

# ---------- routers/messages.py (v11.8.0 — fixed reply routing + guards) ----------
cat > backend/app/routers/messages.py << 'MESSAGES_EOF'
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import schemas, models, auth
from ..database import get_db

router = APIRouter(prefix="/api/messages", tags=["messages"])

def enrich(msg, db):
    sender = db.query(models.User).filter(models.User.id == msg.sender_id).first() if msg.sender_id else None
    recipient = db.query(models.User).filter(models.User.id == msg.recipient_id).first() if msg.recipient_id else None
    return {
        "id": msg.id,
        "sender_id": msg.sender_id,
        "recipient_id": msg.recipient_id,
        "subject": msg.subject,
        "content": msg.content,
        "status": msg.status,
        "created_at": msg.created_at,
        "reply_to_id": msg.reply_to_id,
        "sender_email": sender.email if sender else None,
        "recipient_email": recipient.email if recipient else None,
        "guest_name": msg.guest_name,
        "guest_email": msg.guest_email,
    }

@router.post("/", response_model=schemas.MessageOut)
def send_message(message: schemas.MessageCreate, db: Session = Depends(get_db),
                 current_user=Depends(auth.get_current_active_user)):
    recipient = None
    if message.recipient_id:
        recipient = db.query(models.User).filter(models.User.id == message.recipient_id).first()
    elif message.recipient_slug:
        slug = message.recipient_slug.lstrip("@").strip()
        recipient = db.query(models.User).filter(models.User.custom_slug == slug).first()
    if not recipient:
        raise HTTPException(404, "Recipient not found")
    if recipient.id == current_user.id and current_user.role != "admin":
        raise HTTPException(400, "Cannot send a message to yourself")
    # Allow: global messaging ON, OR sender is admin, OR recipient is admin
    allow_setting = db.query(models.SiteConfig).filter(models.SiteConfig.key == "allow_user_messaging").first()
    global_allow = allow_setting.value.lower() == "true" if allow_setting and allow_setting.value else False
    if not global_allow and current_user.role != "admin" and recipient.role != "admin":
        raise HTTPException(403, "Messaging is disabled. Only admin messages are accepted.")
    if not recipient.accept_messages and current_user.role != "admin":
        raise HTTPException(403, "This user does not accept messages")
    new_msg = models.Message(
        sender_id=current_user.id, recipient_id=recipient.id,
        subject=message.subject, content=message.content,
        reply_to_id=message.reply_to_id, status="unread",
        guest_name=message.guest_name, guest_email=message.guest_email,
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)
    return enrich(new_msg, db)

@router.get("/inbox", response_model=List[schemas.MessageOut])
def get_inbox(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    msgs = db.query(models.Message).filter(
        models.Message.recipient_id == current_user.id
    ).order_by(models.Message.created_at.desc()).all()
    return [enrich(m, db) for m in msgs]

@router.get("/sent", response_model=List[schemas.MessageOut])
def get_sent(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    msgs = db.query(models.Message).filter(
        models.Message.sender_id == current_user.id
    ).order_by(models.Message.created_at.desc()).all()
    return [enrich(m, db) for m in msgs]

@router.get("/unread-count")
def get_unread_count(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    count = db.query(models.Message).filter(
        models.Message.recipient_id == current_user.id,
        models.Message.status == "unread"
    ).count()
    return {"count": count}

@router.patch("/{message_id}/read")
def mark_read(message_id: int, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    msg = db.query(models.Message).filter(
        models.Message.id == message_id, models.Message.recipient_id == current_user.id
    ).first()
    if not msg:
        raise HTTPException(404, "Message not found")
    msg.status = "read"
    db.commit()
    return {"ok": True}

@router.patch("/inbox/read-all")
def mark_all_read(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    db.query(models.Message).filter(
        models.Message.recipient_id == current_user.id, models.Message.status == "unread"
    ).update({"status": "read"})
    db.commit()
    return {"ok": True}

@router.delete("/{message_id}")
def delete_message(message_id: int, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if not msg:
        raise HTTPException(404, "Message not found")
    if msg.sender_id != current_user.id and msg.recipient_id != current_user.id and current_user.role != "admin":
        raise HTTPException(403, "Not authorized to delete this message")
    db.delete(msg)
    db.commit()
    return {"ok": True}
MESSAGES_EOF

# ---------- routers/public.py ----------
# CORRECTED ORDER: API routes first, then catch-all profile route
# Also added FRONTEND_URL to template context and updated report link to point to frontend
cat > backend/app/routers/public.py << 'PUBLIC_EOF'
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session
from .. import models, schemas
from ..database import get_db
import os, re
from fastapi.templating import Jinja2Templates
from datetime import datetime, timezone
from ..config import settings

router = APIRouter(tags=["public"])

# ---------- Helper functions for templates ----------
def get_embed_url(url: str) -> str:
    yt = re.search(r'(?:youtube\.com/watch\?v=|youtu\.be/)([^&\s?]+)', url)
    if yt: return f'https://www.youtube.com/embed/{yt.group(1)}?rel=0'
    vm = re.search(r'vimeo\.com/(\d+)', url)
    if vm: return f'https://player.vimeo.com/video/{vm.group(1)}'
    return url

def is_video_file(url: str) -> bool:
    return any(url.lower().endswith(ext) for ext in ['.mp4', '.webm', '.ogg'])

def is_embed(url: str) -> bool:
    return bool(re.search(r'(?:youtube\.com/watch\?v=|youtu\.be/|vimeo\.com/\d+)', url))

# ---------- API routes (must be before the catch-all) ----------
@router.get("/api/public/config")
def get_public_config(db: Session = Depends(get_db)):
    return {c.key: c.value for c in db.query(models.SiteConfig).all()}

@router.post("/api/public/report-profile")
async def report_profile(report: schemas.ProfileReportCreate, request: Request, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.custom_slug == report.slug).first()
    if not user:
        raise HTTPException(404, "Profile not found")
    db_report = models.ProfileReport(
        reporter_email=report.reporter_email,
        reporter_ip=request.client.host if request.client else None,
        reported_user_id=user.id,
        reason=report.reason,
        details=report.details,
        status="pending"
    )
    db.add(db_report)
    admins = db.query(models.User).filter(models.User.role == "admin").all()
    for admin in admins:
        msg = models.Message(
            sender_id=admin.id,
            recipient_id=admin.id,
            subject=f"🚩 Profile reported: @{report.slug}",
            content=f"A profile was reported.\n\nReason: {report.reason}\nDetails: {report.details or 'None'}\nReporter email: {report.reporter_email or 'Anonymous'}\nReported user: {user.email} (@{user.custom_slug})",
            status="unread"
        )
        db.add(msg)
    db.commit()
    return {"ok": True}

@router.post("/api/public/contact")
async def contact_form(contact: schemas.ContactForm, request: Request, db: Session = Depends(get_db)):
    admins = db.query(models.User).filter(models.User.role == "admin").all()
    if not admins:
        raise HTTPException(500, "No admin users found")
    for admin in admins:
        msg = models.Message(
            sender_id=None,
            recipient_id=admin.id,
            guest_name=contact.name,
            guest_email=contact.email,
            subject=contact.subject,
            content=f"Name: {contact.name}\nEmail: {contact.email}\n\nMessage:\n{contact.message}",
            status="unread"
        )
        db.add(msg)
    db.commit()
    return {"ok": True, "message": "Your message has been sent. Thank you!"}

# ---------- Catch-all profile route (must be last) ----------
@router.get("/@{slug}", response_class=HTMLResponse)
async def get_public_profile(request: Request, slug: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.custom_slug == slug, models.User.is_active == True).first()
    if not user:
        raise HTTPException(404, "Profile not found")
    if user.is_redirect_enabled and user.profile_redirect_url:
        return RedirectResponse(url=user.profile_redirect_url, status_code=302)
    # Track profile view
    user.profile_views = (user.profile_views or 0) + 1
    db.commit()
    tabs = db.query(models.ProfileTab).filter(models.ProfileTab.user_id == user.id, models.ProfileTab.is_active == True).order_by(models.ProfileTab.display_order).all()
    for tab in tabs:
        tab.links = db.query(models.ProfileLink).filter(models.ProfileLink.tab_id == tab.id, models.ProfileLink.is_active == True).order_by(models.ProfileLink.display_order).all()
    social_icons = db.query(models.SocialIcon).filter(models.SocialIcon.user_id == user.id, models.SocialIcon.is_active == True).order_by(models.SocialIcon.display_order).all()
    site_config = {c.key: c.value for c in db.query(models.SiteConfig).all()}
    config = {
        "SITE_NAME": site_config.get("site_name", "LinkPlatform"),
        "SITE_EMOJI": site_config.get("site_emoji", "🔗"),
        "SITE_TAGLINE": site_config.get("site_tagline", ""),
        "SITE_FOOTER": site_config.get("site_footer", ""),
        "FRONTEND_URL": settings.FRONTEND_URL,
    }
    templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))
    templates.env.filters['embed_url'] = get_embed_url
    templates.env.filters['is_embed'] = is_embed
    templates.env.globals['is_video_file'] = is_video_file
    # Password protection gate — check cookie or POST param
    if user.profile_password:
        pw_cookie = request.cookies.get(f"pp_{slug}")
        if pw_cookie != user.profile_password:
            # Wrong/missing password — show gate (handled in template via flag)
            return templates.TemplateResponse("public_profile.html", {
                "request": request, "profile": user, "tabs": [], "social_icons": [],
                "config": config, "now": lambda: datetime.now(timezone.utc),
                "base_url": str(request.base_url), "gate": "password"
            })
    return templates.TemplateResponse("public_profile.html", {
        "request": request,
        "profile": user,
        "tabs": tabs,
        "social_icons": social_icons,
        "config": config,
        "now": lambda: datetime.now(timezone.utc),
        "base_url": str(request.base_url),
        "gate": None
    })

@router.post("/@{slug}/unlock", response_class=HTMLResponse)
async def unlock_profile(request: Request, slug: str, db: Session = Depends(get_db)):
    from fastapi.responses import Response
    import urllib.parse
    form = await request.form()
    entered = form.get("password", "")
    user = db.query(models.User).filter(models.User.custom_slug == slug, models.User.is_active == True).first()
    if not user or not user.profile_password:
        return RedirectResponse(url=f"/@{slug}", status_code=302)
    response = RedirectResponse(url=f"/@{slug}", status_code=302)
    if entered == user.profile_password:
        response.set_cookie(key=f"pp_{slug}", value=user.profile_password, max_age=86400, httponly=True, samesite="lax")
    return response
PUBLIC_EOF

# ---------- routers/users.py ----------
cat > backend/app/routers/users.py << 'USERS_EOF'
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import schemas, models, auth
from ..database import get_db

router = APIRouter(prefix="/api/users", tags=["users"])

# This endpoint is kept but returns empty to avoid exposing all users
@router.get("/", response_model=List[schemas.UserListOut])
def get_users(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    return []

@router.get("/me", response_model=schemas.UserOut)
def get_current_user(current_user=Depends(auth.get_current_active_user)):
    return current_user

@router.get("/by-slug/{slug}")
def get_user_by_slug(slug: str, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    user = db.query(models.User).filter(models.User.custom_slug == slug).first()
    if not user:
        raise HTTPException(404, "User not found")
    return {"id": user.id, "email": user.email, "custom_slug": user.custom_slug, "accept_messages": user.accept_messages}
USERS_EOF

# ---------- routers/admin.py ----------
cat > backend/app/routers/admin.py << 'ADMIN_EOF'
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List
from .. import schemas, models, auth
from ..database import get_db
from ..auth import create_access_token, create_refresh_token, get_password_hash, normalize_email
from ..email_utils import get_smtp_settings, send_email_raw, get_site_setting

router = APIRouter(prefix="/api/admin", tags=["admin"])

@router.get("/users", response_model=List[schemas.UserListOut])
def get_all_users(db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    return db.query(models.User).all()

@router.get("/users/{user_id}", response_model=schemas.UserOut)
def get_user(user_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    return user

@router.put("/users/{user_id}", response_model=schemas.UserOut)
def update_user(user_id: int, update: schemas.UserUpdate, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    for field, value in update.dict(exclude_unset=True).items():
        if field == "password" and value:
            setattr(user, "password_hash", get_password_hash(value))
        elif field == "email" and value:
            new_email = normalize_email(value)
            if new_email != user.email:
                existing = db.query(models.User).filter(models.User.email == new_email).first()
                if existing:
                    raise HTTPException(400, "Email already taken")
                setattr(user, field, new_email)
        else:
            setattr(user, field, value)
    db.commit()
    db.refresh(user)
    return user

@router.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Not found")
    if user.role == "admin":
        raise HTTPException(403, "Cannot delete admin")
    db.delete(user)
    db.commit()
    return {"ok": True}

@router.post("/users/{user_id}/ban")
def ban_user(user_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    if user.role == "admin":
        raise HTTPException(403, "Cannot ban admin")
    user.is_banned = True
    user.is_active = False
    db.commit()
    return {"ok": True}

@router.post("/users/{user_id}/unban")
def unban_user(user_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    user.is_banned = False
    user.is_active = True
    db.commit()
    return {"ok": True}

@router.post("/users/{user_id}/suspend")
def suspend_user(user_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    if user.role == "admin":
        raise HTTPException(403, "Cannot suspend admin")
    user.is_suspended = True
    db.commit()
    return {"ok": True}

@router.post("/users/{user_id}/unsuspend")
def unsuspend_user(user_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    user.is_suspended = False
    db.commit()
    return {"ok": True}

@router.post("/users/{user_id}/role")
def change_role(user_id: int, role: str, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    if role not in ["user", "moderator", "admin"]:
        raise HTTPException(400, "Invalid role")
    user.role = role
    db.commit()
    return {"ok": True}

@router.post("/users/{user_id}/impersonate", response_model=schemas.Token)
def impersonate(user_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Not found")
    if not user.is_active or user.is_banned or user.is_suspended:
        raise HTTPException(400, "User is not active")
    access_token = create_access_token({"sub": user.email, "role": user.role})
    refresh_token = create_refresh_token({"sub": user.email, "role": user.role})
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 1800,
        "requires_2fa": False
    }

@router.get("/links", response_model=List[schemas.LinkOut])
def get_all_links(db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    return db.query(models.Link).all()

@router.delete("/links/{link_id}")
def delete_link(link_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    link = db.query(models.Link).filter(models.Link.id == link_id).first()
    if not link:
        raise HTTPException(404, "Not found")
    db.delete(link)
    db.commit()
    return {"ok": True}

@router.get("/settings", response_model=List[schemas.SiteConfigOut])
def get_settings(db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    return db.query(models.SiteConfig).all()

@router.put("/settings/{key}")
def update_setting(key: str, body: schemas.SiteConfigUpdate, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    config = db.query(models.SiteConfig).filter(models.SiteConfig.key == key).first()
    if not config:
        config = models.SiteConfig(key=key, value=body.value)
        db.add(config)
    else:
        config.value = body.value
    db.commit()
    return {"ok": True, "key": key, "value": body.value}

# SMTP settings endpoints
@router.get("/smtp-settings", response_model=schemas.SMTPSettings)
def get_smtp_settings_route(db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    smtp = get_smtp_settings(db)
    return {
        "host": smtp["host"],
        "port": smtp["port"],
        "user": smtp["user"],
        "password": smtp["password"],
        "use_tls": smtp["use_tls"]
    }

@router.put("/smtp-settings")
def update_smtp_settings(settings: schemas.SMTPSettings, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    def set_config(key, value):
        config = db.query(models.SiteConfig).filter(models.SiteConfig.key == key).first()
        if config:
            config.value = str(value)
        else:
            db.add(models.SiteConfig(key=key, value=str(value)))
    set_config("smtp_host", settings.host)
    set_config("smtp_port", settings.port)
    set_config("smtp_user", settings.user)
    set_config("smtp_password", settings.password)
    set_config("smtp_use_tls", "true" if settings.use_tls else "false")
    db.commit()
    return {"ok": True}

@router.post("/test-email")
def send_test_email(test: schemas.TestEmail, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    smtp = get_smtp_settings(db)
    try:
        send_email_raw(test.to_email, "Test Email from LinkPlatform", "This is a test email to verify SMTP settings.", None, smtp)
        return {"ok": True, "message": "Test email sent"}
    except Exception as e:
        raise HTTPException(500, f"Failed to send email: {str(e)}")

@router.get("/stats", response_model=schemas.AdminStats)
def get_stats(db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    total_users = db.query(models.User).count()
    total_links = db.query(models.Link).count()
    total_clicks = db.query(func.sum(models.Link.clicks)).scalar() or 0
    total_profile_views = db.query(func.sum(models.User.profile_views)).scalar() or 0
    total_messages = db.query(models.Message).count()
    total_reports = db.query(models.ProfileReport).count()
    pending_reports = db.query(models.ProfileReport).filter(models.ProfileReport.status == "pending").count()
    return {
        "total_users": total_users,
        "total_links": total_links,
        "total_clicks": total_clicks,
        "total_profile_views": total_profile_views,
        "total_messages": total_messages,
        "total_reports": total_reports,
        "pending_reports": pending_reports,
    }

@router.get("/reports", response_model=List[schemas.AdminReportOut])
def get_reports(db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    reports = db.query(models.ProfileReport).order_by(models.ProfileReport.created_at.desc()).all()
    result = []
    for r in reports:
        item = schemas.AdminReportOut(
            id=r.id,
            reporter_email=r.reporter_email,
            reporter_ip=r.reporter_ip,
            reported_user_id=r.reported_user_id,
            reason=r.reason,
            details=r.details,
            status=r.status,
            created_at=r.created_at,
            reported_slug=r.reported_user.custom_slug if r.reported_user else None,
            reported_email=r.reported_user.email if r.reported_user else None,
        )
        result.append(item)
    return result

@router.put("/reports/{report_id}")
def update_report(report_id: int, update: schemas.AdminReportUpdate, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    report = db.query(models.ProfileReport).filter(models.ProfileReport.id == report_id).first()
    if not report:
        raise HTTPException(404, "Report not found")
    if update.status not in ["pending", "reviewed", "dismissed"]:
        raise HTTPException(400, "Invalid status")
    report.status = update.status
    db.commit()
    return {"ok": True}

@router.delete("/reports/{report_id}")
def delete_report(report_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    report = db.query(models.ProfileReport).filter(models.ProfileReport.id == report_id).first()
    if not report:
        raise HTTPException(404, "Report not found")
    db.delete(report)
    db.commit()
    return {"ok": True}

@router.get("/files")
def list_files(admin=Depends(auth.get_current_admin_user)):
    import os, glob
    upload_dir = os.path.join(os.path.dirname(__file__), "..", "uploads")
    if not os.path.isdir(upload_dir):
        return []
    files = []
    for path in sorted(glob.glob(os.path.join(upload_dir, "*")), key=os.path.getmtime, reverse=True):
        if os.path.isfile(path):
            fname = os.path.basename(path)
            files.append({
                "name": fname,
                "size": os.path.getsize(path),
                "url": f"/uploads/{fname}",
            })
    return files

@router.post("/files/upload")
async def admin_upload_file(file: UploadFile = File(...), admin=Depends(auth.get_current_admin_user)):
    import os, uuid
    upload_dir = os.path.join(os.path.dirname(__file__), "..", "uploads")
    os.makedirs(upload_dir, exist_ok=True)
    content = await file.read()
    if len(content) > 20 * 1024 * 1024:
        raise HTTPException(400, "File must be less than 20MB")
    ext = os.path.splitext(file.filename)[1] if file.filename else ".bin"
    fname = f"{uuid.uuid4().hex}{ext}"
    with open(os.path.join(upload_dir, fname), "wb") as f:
        f.write(content)
    return {"url": f"/uploads/{fname}", "name": fname}

@router.delete("/files/{filename}")
def admin_delete_file(filename: str, admin=Depends(auth.get_current_admin_user)):
    import os, re
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        raise HTTPException(400, "Invalid filename")
    upload_dir = os.path.join(os.path.dirname(__file__), "..", "uploads")
    path = os.path.join(upload_dir, filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "File not found")
    os.remove(path)
    return {"ok": True}
ADMIN_EOF

# ---------- routers/admin_nav.py ----------
cat > backend/app/routers/admin_nav.py << 'ADMIN_NAV_EOF'
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import schemas, models, auth
from ..database import get_db

router = APIRouter(prefix="/api/admin/nav", tags=["admin"])

@router.get("/", response_model=List[schemas.NavItemOut])
def get_all_nav_items(db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    return db.query(models.NavItem).order_by(models.NavItem.order).all()

@router.post("/", response_model=schemas.NavItemOut)
def create_nav_item(item: schemas.NavItemCreate, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    db_item = models.NavItem(**item.dict())
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return db_item

@router.put("/{item_id}", response_model=schemas.NavItemOut)
def update_nav_item(item_id: int, update: schemas.NavItemUpdate, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    item = db.query(models.NavItem).filter(models.NavItem.id == item_id).first()
    if not item:
        raise HTTPException(404, "Nav item not found")
    for field, value in update.dict(exclude_unset=True).items():
        setattr(item, field, value)
    db.commit()
    db.refresh(item)
    return item

@router.delete("/{item_id}")
def delete_nav_item(item_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    item = db.query(models.NavItem).filter(models.NavItem.id == item_id).first()
    if not item:
        raise HTTPException(404, "Nav item not found")
    if item.is_system:
        raise HTTPException(400, "Cannot delete system nav item")
    db.delete(item)
    db.commit()
    return {"ok": True}
ADMIN_NAV_EOF

# ---------- routers/admin_pages.py ----------
cat > backend/app/routers/admin_pages.py << 'ADMIN_PAGES_EOF'
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import schemas, models, auth
from ..database import get_db

router = APIRouter(prefix="/api/admin/pages", tags=["admin"])

def _sync_nav_for_page(db: Session, page: models.Page):
    path = f"/p/{page.slug}"
    existing = db.query(models.NavItem).filter(models.NavItem.path == path).first()
    show_in_menu = page.published and (page.menu_visible if page.menu_visible is not None else True)
    if existing:
        existing.label = page.title
        existing.enabled = show_in_menu
    else:
        max_order = db.query(models.NavItem).count()
        nav = models.NavItem(
            label=page.title,
            path=path,
            icon="📄",
            auth_required=False,
            admin_only=False,
            enabled=show_in_menu,
            order=max_order * 10 + 100,
            is_system=False,
        )
        db.add(nav)
    db.commit()

def _remove_nav_for_page(db: Session, slug: str):
    path = f"/p/{slug}"
    item = db.query(models.NavItem).filter(models.NavItem.path == path).first()
    if item:
        db.delete(item)
        db.commit()

@router.get("/", response_model=List[schemas.PageOut])
def get_all_pages(db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    return db.query(models.Page).order_by(models.Page.created_at.desc()).all()

@router.post("/", response_model=schemas.PageOut)
def create_page(page: schemas.PageCreate, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    existing = db.query(models.Page).filter(models.Page.slug == page.slug).first()
    if existing:
        raise HTTPException(400, "Slug already exists")
    db_page = models.Page(**page.dict())
    db.add(db_page)
    db.commit()
    db.refresh(db_page)
    _sync_nav_for_page(db, db_page)
    return db_page

@router.get("/{page_id}", response_model=schemas.PageOut)
def get_page(page_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    page = db.query(models.Page).filter(models.Page.id == page_id).first()
    if not page:
        raise HTTPException(404, "Page not found")
    return page

@router.put("/{page_id}", response_model=schemas.PageOut)
def update_page(page_id: int, update: schemas.PageUpdate, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    page = db.query(models.Page).filter(models.Page.id == page_id).first()
    if not page:
        raise HTTPException(404, "Page not found")
    old_slug = page.slug
    if update.slug is not None and update.slug != page.slug:
        existing = db.query(models.Page).filter(models.Page.slug == update.slug).first()
        if existing:
            raise HTTPException(400, "Slug already exists")
        _remove_nav_for_page(db, old_slug)
    for field, value in update.dict(exclude_unset=True).items():
        setattr(page, field, value)
    db.commit()
    db.refresh(page)
    _sync_nav_for_page(db, page)
    return page

@router.delete("/{page_id}")
def delete_page(page_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    page = db.query(models.Page).filter(models.Page.id == page_id).first()
    if not page:
        raise HTTPException(404, "Page not found")
    slug = page.slug
    db.delete(page)
    db.commit()
    _remove_nav_for_page(db, slug)
    return {"ok": True}
ADMIN_PAGES_EOF

# ---------- routers/public_pages.py ----------
cat > backend/app/routers/public_pages.py << 'PUBLIC_PAGES_EOF'
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from .. import models
from ..database import get_db
import os

router = APIRouter(tags=["public"])
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))

@router.get("/p/{slug}", response_class=HTMLResponse)
async def view_page(request: Request, slug: str, db: Session = Depends(get_db)):
    page = db.query(models.Page).filter(models.Page.slug == slug, models.Page.published == True).first()
    if not page:
        raise HTTPException(404, "Page not found")
    site_config = {c.key: c.value for c in db.query(models.SiteConfig).all()}
    config = {
        "SITE_NAME": site_config.get("site_name", "LinkPlatform"),
        "SITE_EMOJI": site_config.get("site_emoji", "🔗"),
    }
    return templates.TemplateResponse("page.html", {"request": request, "page": page, "config": config})

@router.get("/api/public/pages/{slug}")
def get_page_json(slug: str, db: Session = Depends(get_db)):
    page = db.query(models.Page).filter(models.Page.slug == slug, models.Page.published == True).first()
    if not page:
        raise HTTPException(404, "Page not found")
    return {"id": page.id, "title": page.title, "slug": page.slug, "content": page.content}
PUBLIC_PAGES_EOF

# ---------- routers/public_nav.py ----------
cat > backend/app/routers/public_nav.py << 'PUBLIC_NAV_EOF'
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from .. import schemas, models
from ..database import get_db

router = APIRouter(prefix="/api/public/nav", tags=["public"])

@router.get("/", response_model=List[schemas.NavItemOut])
def get_nav_items(db: Session = Depends(get_db)):
    return db.query(models.NavItem).filter(models.NavItem.enabled == True).order_by(models.NavItem.order).all()
PUBLIC_NAV_EOF

# ---------- routers/email_templates.py ----------
cat > backend/app/routers/email_templates.py << 'EMAILTMPL_EOF'
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from .. import schemas, models, auth
from ..database import get_db
from ..email_utils import send_templated_email

router = APIRouter(prefix="/api/admin/email-templates", tags=["admin"])

@router.get("/", response_model=List[schemas.EmailTemplateOut])
def list_templates(db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    return db.query(models.EmailTemplate).all()

@router.post("/", response_model=schemas.EmailTemplateOut)
def create_template(template: schemas.EmailTemplateCreate, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    existing = db.query(models.EmailTemplate).filter(models.EmailTemplate.key == template.key).first()
    if existing:
        raise HTTPException(400, "Template with this key already exists")
    db_tpl = models.EmailTemplate(**template.dict())
    db.add(db_tpl)
    db.commit()
    db.refresh(db_tpl)
    return db_tpl

@router.get("/{key}", response_model=schemas.EmailTemplateOut)
def get_template(key: str, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    tpl = db.query(models.EmailTemplate).filter(models.EmailTemplate.key == key).first()
    if not tpl:
        raise HTTPException(404, "Template not found")
    return tpl

@router.put("/{key}", response_model=schemas.EmailTemplateOut)
def update_template(key: str, update: schemas.EmailTemplateUpdate, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    tpl = db.query(models.EmailTemplate).filter(models.EmailTemplate.key == key).first()
    if not tpl:
        raise HTTPException(404, "Template not found")
    for field, val in update.dict(exclude_unset=True).items():
        setattr(tpl, field, val)
    db.commit()
    db.refresh(tpl)
    return tpl

@router.delete("/{key}")
def delete_template(key: str, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    tpl = db.query(models.EmailTemplate).filter(models.EmailTemplate.key == key).first()
    if not tpl:
        raise HTTPException(404, "Template not found")
    db.delete(tpl)
    db.commit()
    return {"ok": True}

@router.post("/test")
def send_test_email(data: schemas.SendTestEmail, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    try:
        send_templated_email(db, data.template_key, data.to_email, data.context)
        return {"ok": True, "message": "Test email sent"}
    except Exception as e:
        raise HTTPException(500, f"Failed to send email: {str(e)}")
EMAILTMPL_EOF

# ---------- routers/twofa.py ----------
cat > backend/app/routers/twofa.py << 'TWOFA_EOF'
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import pyotp
import secrets
from datetime import datetime, timezone

from .. import schemas, models, auth
from ..database import get_db
from ..config import settings

router = APIRouter(prefix="/api/auth/2fa", tags=["2fa"])

def generate_backup_codes(count=8):
    codes = []
    for _ in range(count):
        code = secrets.token_hex(5).upper()
        code = '-'.join([code[i:i+4] for i in range(0, len(code), 4)])
        codes.append(code)
    return codes

@router.get("/status", response_model=schemas.TwoFAStatus)
def get_2fa_status(current_user=Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    return {
        "enabled": user.twofa_enabled,
        "has_backup_codes": bool(user.twofa_backup_codes),
        "last_reset_at": user.twofa_last_reset_at
    }

@router.post("/setup")
def setup_2fa(setup: schemas.TwoFASetup, current_user=Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    if user.twofa_enabled:
        raise HTTPException(400, "2FA already enabled")
    secret = pyotp.random_base32()
    user.twofa_secret = secret
    if setup.generate_backup_codes:
        codes = generate_backup_codes()
        user.twofa_backup_codes = "\n".join(codes)
    else:
        user.twofa_backup_codes = None
    db.commit()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name=settings.SITE_NAME)
    return {
        "secret": secret,
        "provisioning_uri": provisioning_uri,
        "backup_codes": user.twofa_backup_codes.split("\n") if user.twofa_backup_codes else []
    }

@router.post("/verify")
def verify_2fa(data: schemas.Verify2FA, current_user=Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    if not user.twofa_secret:
        raise HTTPException(400, "2FA not set up")
    totp = pyotp.TOTP(user.twofa_secret)
    if totp.verify(data.code):
        if not user.twofa_enabled:
            user.twofa_enabled = True
            db.commit()
        return {"ok": True, "message": "2FA enabled successfully"}
    else:
        if user.twofa_backup_codes:
            codes = user.twofa_backup_codes.split("\n")
            if data.code in codes:
                codes.remove(data.code)
                user.twofa_backup_codes = "\n".join(codes) if codes else None
                if not user.twofa_enabled:
                    user.twofa_enabled = True
                db.commit()
                return {"ok": True, "message": "2FA enabled with backup code"}
        raise HTTPException(400, "Invalid code")

@router.post("/disable")
def disable_2fa(data: schemas.Disable2FA, current_user=Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    if not auth.verify_password(data.password, user.password_hash):
        raise HTTPException(400, "Invalid password")
    user.twofa_enabled = False
    user.twofa_secret = None
    user.twofa_backup_codes = None
    user.twofa_last_reset_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}

@router.post("/reset")
def reset_2fa(reset: schemas.TwoFAReset, current_user=Depends(auth.get_current_active_user), db: Session = Depends(get_db)):
    if not reset.confirm:
        raise HTTPException(400, "Confirmation required")
    user = db.query(models.User).filter(models.User.id == current_user.id).first()
    user.twofa_enabled = False
    user.twofa_secret = None
    user.twofa_backup_codes = None
    user.twofa_last_reset_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}
TWOFA_EOF

# ---------- routers/custom_domains.py ----------
cat > backend/app/routers/custom_domains.py << 'DOMAINS_EOF'
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List, Optional
import socket
import re

from .. import schemas, models, auth
from ..database import get_db

router = APIRouter(prefix="/api/domains", tags=["domains"])

def _clean_domain(raw: str) -> str:
    """Strip protocol/path and lowercase the domain."""
    d = raw.strip().lower()
    d = re.sub(r'^https?://', '', d)
    d = d.split('/')[0].split('?')[0]
    return d

def _verify_dns(domain: str, server_ip: str) -> bool:
    """Check if domain A record resolves to this server's IP."""
    try:
        resolved = socket.gethostbyname(domain)
        return resolved == server_ip
    except Exception:
        return False

# ── User endpoints ──────────────────────────────────────────────────────────

@router.get("/my", response_model=Optional[schemas.CustomDomainOut])
def get_my_domain(db: Session = Depends(get_db), current_user=Depends(auth.get_current_user)):
    if not current_user.can_use_custom_domain:
        raise HTTPException(403, "Custom domains not enabled for your account")
    return db.query(models.CustomDomain).filter(models.CustomDomain.user_id == current_user.id).first()

@router.post("/my", response_model=schemas.CustomDomainOut)
def set_my_domain(body: schemas.CustomDomainCreate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_user)):
    if not current_user.can_use_custom_domain:
        raise HTTPException(403, "Custom domains not enabled for your account. Ask an admin to grant access.")
    domain = _clean_domain(body.domain)
    if not domain or '.' not in domain:
        raise HTTPException(400, "Invalid domain name")
    # Check not already taken by someone else
    existing = db.query(models.CustomDomain).filter(models.CustomDomain.domain == domain).first()
    if existing and existing.user_id != current_user.id:
        raise HTTPException(400, "Domain already registered by another user")
    record = db.query(models.CustomDomain).filter(models.CustomDomain.user_id == current_user.id).first()
    if record:
        # Update existing
        record.domain = domain
        record.root_redirect = body.root_redirect
        record.not_found_redirect = body.not_found_redirect
        record.is_verified = False
    else:
        record = models.CustomDomain(
            user_id=current_user.id,
            domain=domain,
            root_redirect=body.root_redirect,
            not_found_redirect=body.not_found_redirect,
            is_verified=False,
        )
        db.add(record)
    db.commit()
    db.refresh(record)
    return record

@router.put("/my", response_model=schemas.CustomDomainOut)
def update_my_domain(body: schemas.CustomDomainUpdate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_user)):
    record = db.query(models.CustomDomain).filter(models.CustomDomain.user_id == current_user.id).first()
    if not record:
        raise HTTPException(404, "No domain configured")
    if body.root_redirect is not None:
        record.root_redirect = body.root_redirect
    if body.not_found_redirect is not None:
        record.not_found_redirect = body.not_found_redirect
    db.commit()
    db.refresh(record)
    return record

@router.delete("/my")
def delete_my_domain(db: Session = Depends(get_db), current_user=Depends(auth.get_current_user)):
    record = db.query(models.CustomDomain).filter(models.CustomDomain.user_id == current_user.id).first()
    if not record:
        raise HTTPException(404, "No domain configured")
    db.delete(record)
    db.commit()
    return {"ok": True}

@router.post("/my/verify", response_model=schemas.CustomDomainOut)
def verify_my_domain(request: Request, db: Session = Depends(get_db), current_user=Depends(auth.get_current_user)):
    record = db.query(models.CustomDomain).filter(models.CustomDomain.user_id == current_user.id).first()
    if not record:
        raise HTTPException(404, "No domain configured")
    # Get server IP to check against
    try:
        server_ip = socket.gethostbyname(request.headers.get("host", "localhost").split(":")[0])
    except Exception:
        server_ip = ""
    verified = _verify_dns(record.domain, server_ip)
    record.is_verified = verified
    db.commit()
    db.refresh(record)
    if not verified:
        fallback = "this server's IP"
        raise HTTPException(400, f"DNS not pointing to this server yet. Make sure your A record points to {server_ip or fallback}")
    return record

# ── Admin endpoints ──────────────────────────────────────────────────────────

@router.get("/admin/all")
def admin_list_domains(db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    records = db.query(models.CustomDomain).all()
    result = []
    for r in records:
        result.append({
            "id": r.id,
            "user_id": r.user_id,
            "domain": r.domain,
            "root_redirect": r.root_redirect,
            "not_found_redirect": r.not_found_redirect,
            "is_verified": r.is_verified,
            "created_at": r.created_at,
            "user_email": r.user.email if r.user else None,
            "user_slug": r.user.custom_slug if r.user else None,
            "can_use_custom_domain": r.user.can_use_custom_domain if r.user else False,
        })
    return result

@router.put("/admin/grant/{user_id}")
def admin_grant_domain(user_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    user.can_use_custom_domain = True
    db.commit()
    return {"ok": True, "user_id": user_id}

@router.put("/admin/revoke/{user_id}")
def admin_revoke_domain(user_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    user.can_use_custom_domain = False
    db.commit()
    return {"ok": True, "user_id": user_id}

@router.delete("/admin/domain/{domain_id}")
def admin_delete_domain(domain_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    record = db.query(models.CustomDomain).filter(models.CustomDomain.id == domain_id).first()
    if not record:
        raise HTTPException(404, "Domain not found")
    db.delete(record)
    db.commit()
    return {"ok": True}
DOMAINS_EOF

# ---------- Templates: public_profile.html (v11.7.2 — index.html design + @slug + status bubble) ----------
cat > backend/app/templates/public_profile.html << 'PROFILEHTML_EOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ profile.header_text or profile.custom_slug or 'Profile' }}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
{% if profile.theme_html %}{{ profile.theme_html | safe }}{% endif %}
<style>
/* ── Default: May Flowers theme — overridden by theme_html above ── */
:root {
  --primary:    {{ profile.theme_color or '#e91e8c' }};
  --secondary:  #9b59b6;
  --accent:     #1abc9c;
  --bg:         {% if profile.page_bg_url %}url({{ profile.page_bg_url }}) center/cover no-repeat fixed{% else %}#100618{% endif %};
  --text-color: #f8f9fa;
  --text-muted-color: #c070b0;
  /* these get overridden by theme_html if set */
  --card:       rgba(255,255,255,0.05);
  --card-hov:   rgba(255,255,255,0.10);
  --border:     rgba(255,255,255,0.10);
  --shadow:     rgba(0,0,0,0.6);
  --glass:      blur(18px);
  --r-sm:       10px;
  --r-md:       14px;
  --r-full:     9999px;
  --t:          0.27s ease;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
  font-family: 'Outfit', system-ui, sans-serif;
  background: var(--bg);
  color: var(--text-color);
  line-height: 1.6;
  min-height: 100vh;
  overflow-x: hidden;
  transition: background-color 0.9s ease, color 0.9s ease;
}
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #100618; }
::-webkit-scrollbar-thumb { background: var(--card-hov); border-radius: 3px; }

/* ── Particles ── */
.holiday-bg { position: fixed; inset: 0; pointer-events: none; z-index: 0; overflow: hidden; }
.petal-dot { position: absolute; width: 10px; height: 10px; border-radius: 50% 50% 50% 0; transform: rotate(-45deg); animation: petalFall linear infinite; }
@keyframes petalFall { 0%{transform:translateY(-60px) rotate(0deg);opacity:.8} 100%{transform:translateY(105vh) rotate(360deg);opacity:.2} }
.snow-dot { position: absolute; background: rgba(255,255,255,0.85); border-radius: 50%; animation: snowFall linear infinite; }
@keyframes snowFall { 0%{transform:translateY(-30px);opacity:0} 10%{opacity:.8} 90%{opacity:.8} 100%{transform:translateY(105vh);opacity:0} }
.heart-dot { position: absolute; color: #e84393; animation: heartRise linear infinite; }
@keyframes heartRise { 0%{transform:translateY(105vh);opacity:0} 10%{opacity:.9} 90%{opacity:.9} 100%{transform:translateY(-80px);opacity:0} }
.bat-dot { position: absolute; font-size: 20px; animation: batFly linear infinite; }
@keyframes batFly { 0%{transform:translateX(-100px);opacity:0} 5%{opacity:.7} 95%{opacity:.7} 100%{transform:translateX(calc(100vw + 100px));opacity:0} }
.confetti-dot { position: absolute; border-radius: 2px; animation: confettiFall linear infinite; }
@keyframes confettiFall { 0%{transform:translateY(-50px) rotate(0deg);opacity:.9} 100%{transform:translateY(105vh) rotate(720deg);opacity:.3} }
.firefly-dot { position: absolute; border-radius: 50%; width: 5px; height: 5px; animation: fireflyGlow ease-in-out infinite; }
@keyframes fireflyGlow { 0%,100%{transform:translate(0,0);opacity:.15;box-shadow:0 0 4px currentColor} 50%{transform:translate(18px,-22px);opacity:1;box-shadow:0 0 14px currentColor,0 0 28px currentColor} }
.leaf-dot { position: absolute; width: 14px; height: 14px; clip-path: polygon(50% 0%,0% 100%,100% 100%); animation: leafFall linear infinite; }
@keyframes leafFall { 0%{transform:translateY(-60px) rotate(0deg);opacity:.8} 100%{transform:translateY(105vh) rotate(720deg);opacity:.2} }
.star-dot { position: absolute; animation: starTwinkle ease-in-out infinite; }
@keyframes starTwinkle { 0%,100%{opacity:.15;transform:scale(.6)} 50%{opacity:1;transform:scale(1.3)} }
.bunny-dot { position: absolute; animation: bunnyHop ease-in-out infinite; }
@keyframes bunnyHop { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-18px)} }

/* ── BG Glow ── */
.bg-glow { position: fixed; top: -50%; left: -50%; width: 200%; height: 200%; pointer-events: none; z-index: 0; animation: glowSpin 35s linear infinite; }
@keyframes glowSpin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
.bg-grid { position: fixed; inset: 0; background-image: linear-gradient(rgba(255,255,255,0.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.018) 1px,transparent 1px); background-size: 56px 56px; pointer-events: none; z-index: 0; }

/* ── Main layout ── */
main { position: relative; z-index: 1; max-width: 780px; margin: 0 auto; padding: 0.6rem 0.7rem 1.2rem; display: flex; flex-direction: column; gap: 0.5rem; }

/* ── Tech layer ── */
.tech-layer { position: absolute; inset: 0; overflow: hidden; border-radius: var(--r-md); pointer-events: none; z-index: 0; }
.tech-grid-bg { position: absolute; width: 200%; height: 200%; background-image: linear-gradient(rgba(255,255,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px); background-size: 28px 28px; animation: gridDrift 22s linear infinite; opacity: .5; }
@keyframes gridDrift { 0%{transform:translate(0,0)} 100%{transform:translate(-28px,-28px)} }
.c-line { position: absolute; background: linear-gradient(90deg,transparent,var(--primary),transparent); height: 1.5px; animation: cFlow 3.2s linear infinite; opacity: 0; }
@keyframes cFlow { 0%{width:0%;left:0;opacity:0} 8%{opacity:.55} 92%{opacity:.55} 100%{width:100%;left:100%;opacity:0} }
.c-dot { position: absolute; width: 4px; height: 4px; background: var(--accent); border-radius: 50%; box-shadow: 0 0 7px var(--accent); animation: dotPulse 2.3s ease-in-out infinite; opacity: 0; }
@keyframes dotPulse { 0%,100%{transform:scale(1);opacity:.25} 50%{transform:scale(1.8);opacity:.85} }
.bin-rain { position: absolute; inset: 0; overflow: hidden; }
.bin-d { position: absolute; font-family:'JetBrains Mono',monospace; font-weight:700; font-size:10px; opacity:0; animation:binFall linear infinite; text-shadow:0 0 4px currentColor; }
@keyframes binFall { 0%{transform:translateY(-30px);opacity:0} 8%{opacity:.55} 90%{opacity:.55} 100%{transform:translateY(130px);opacity:0} }
.holo { position: absolute; inset: 0; background: linear-gradient(180deg,rgba(255,255,255,.1) 0%,transparent 18%,transparent 82%,rgba(255,255,255,.1) 100%); animation: holoScan 5s linear infinite; opacity: .12; }
@keyframes holoScan { 0%{transform:translateY(-100%)} 100%{transform:translateY(250%)} }

/* ── Hero ── */
.hero {
  position: relative; overflow: hidden; isolation: isolate;
  background: var(--card); backdrop-filter: var(--glass); -webkit-backdrop-filter: var(--glass);
  border: 1px solid var(--border); border-radius: var(--r-md);
  padding: 0.85rem 0.9rem 0.85rem;
  text-align: center; box-shadow: 0 8px 40px var(--shadow);
  animation: slideUp 0.65s ease-out;
  contain: layout;   /* prevent children escaping card bounds */
}
.hero::before {
  content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 90px;
  background: linear-gradient(135deg, var(--primary), var(--secondary));
  opacity: 0.1; z-index: 0; border-radius: var(--r-md) var(--r-md) 0 0;
}
.hero-banner {
  position: absolute; top: 0; left: 0; width: 100%;
  object-fit: cover; border-radius: var(--r-md) var(--r-md) 0 0;
  z-index: 1; pointer-events: none;
  /* height & opacity set inline via Jinja */
}
/* Half banner (default) — fades to transparent at bottom */
.hero-banner.size-half {
  height: 110px;
  opacity: var(--header-banner-opacity, 0.45);
  mask-image: linear-gradient(to bottom, rgba(0,0,0,0.85) 0%, rgba(0,0,0,0) 100%);
  -webkit-mask-image: linear-gradient(to bottom, rgba(0,0,0,0.85) 0%, rgba(0,0,0,0) 100%);
}
/* Full banner — taller, still fades slightly */
.hero-banner.size-full {
  height: 200px;
  opacity: var(--header-banner-opacity, 0.45);
  mask-image: linear-gradient(to bottom, rgba(0,0,0,0.9) 60%, rgba(0,0,0,0) 100%);
  -webkit-mask-image: linear-gradient(to bottom, rgba(0,0,0,0.9) 60%, rgba(0,0,0,0) 100%);
}
/* Cover — fills entire hero card as background image */
.hero.cover-mode {
  background-image: var(--cover-image-url);
  background-size: cover;
  background-position: center;
}
.hero.cover-mode::before {
  /* override the subtle gradient overlay for cover mode */
  opacity: 0 !important;
}
.hero-banner.size-cover { display: none; } /* handled by CSS background */
.hero.cover-mode .hero-content {
  background: rgba(0,0,0, var(--header-banner-opacity-inv, 0.35));
  border-radius: var(--r-sm);
  padding: 0.5rem;
}
.hero-content { position: relative; z-index: 2; }
.hero-inner-pad { position: relative; z-index: 2; padding-top: 0.2rem; }

/* ── Photo row: @slug LEFT, avatar CENTER, status bubble RIGHT ── */
.photo-row {
  display: flex; align-items: center; justify-content: center;
  gap: 0.75rem; margin-bottom: 0.6rem;
  flex-wrap: nowrap;          /* NEVER stack — keep 3-column row on all sizes */
}
.slug-vertical {
  writing-mode: vertical-rl; transform: rotate(180deg);
  font-size: 0.78rem; font-weight: 700; color: var(--primary);
  text-transform: uppercase; letter-spacing: 2px; white-space: nowrap;
  background: rgba(255,255,255,0.05); padding: 0.5rem 0.25rem;
  border-radius: 0.5rem; border: 1.5px solid var(--primary);
  line-height: 1.1; flex-shrink: 0; min-width: 0;
  animation: slugFloat 3s ease-in-out infinite;
  text-shadow: 0 0 10px var(--primary);
  overflow: hidden; max-height: 120px; /* clamp on very small screens */
  cursor: pointer; user-select: none;
}
/* Vertical straight (no rotation) */
.slug-vfixed {
  writing-mode: vertical-rl; transform: none;
  animation: slugFloatFixed 3s ease-in-out infinite;
}
@keyframes slugFloatFixed { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-4px)} }
/* Horizontal slug */
.slug-horizontal {
  writing-mode: horizontal-tb; transform: none;
  padding: 0.35rem 0.65rem; max-height: none; max-width: 120px;
  font-size: 0.75rem; letter-spacing: 1.5px;
  animation: slugFloatH 3s ease-in-out infinite;
  align-self: center;
}
@keyframes slugFloatH { 0%,100%{transform:translateX(0)} 50%{transform:translateX(-3px)} }
@keyframes slugFloat { 0%,100%{transform:rotate(180deg) translateY(0)} 50%{transform:rotate(180deg) translateY(-4px)} }

.avatar-wrap { position: relative; width: 74px; height: 74px; display: inline-block; flex-shrink: 0; flex-grow: 0; }
.avatar-ring {
  position: absolute; inset: -6px; border-radius: 50%; opacity: 0.8;
  background: conic-gradient(var(--primary), var(--secondary), var(--accent), var(--primary));
  filter: blur(9px); animation: ringPulse 3.2s ease-in-out infinite;
}
.avatar-ring.rainbow {
  background: conic-gradient(#ff0080, #ff8c00, #ffd700, #00ff80, #00cfff, #a855f7, #ff0080);
  animation: ringPulse 2s ease-in-out infinite, rainbowSpin 4s linear infinite;
  filter: blur(8px);
}
@keyframes rainbowSpin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
@keyframes ringPulse { 0%,100%{opacity:.5;transform:scale(1)} 50%{opacity:.9;transform:scale(1.07)} }
.avatar {
  position: relative; width: 74px; height: 74px;
  border-radius: {% if profile.profile_photo_style == 'circle' %}50%{% elif profile.profile_photo_style == 'rounded' %}20%{% else %}8px{% endif %};
  object-fit: cover; border: 3px solid var(--bg); z-index: 1; display: block;
}
.avatar.pulse { animation: avPulse 2s infinite; }
@keyframes avPulse { 0%{box-shadow:0 0 0 0 rgba(255,255,255,.3)} 70%{box-shadow:0 0 0 12px rgba(255,255,255,0)} 100%{box-shadow:0 0 0 0 rgba(255,255,255,0)} }
.avatar.glow { filter: drop-shadow(0 0 10px var(--primary)); }
.avatar-fallback { position: absolute; inset: 0; border-radius: 50%; background: linear-gradient(135deg, var(--primary), var(--secondary)); display: flex; align-items: center; justify-content: center; font-size: 2rem; color: #000; z-index: 0; }

/* ── Thought bubble ── */
.thought-bubble {
  position: relative; background: rgba(255,255,255,0.07);
  backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
  border-radius: 1rem 1rem 1rem 0.3rem;
  padding: 0.55rem 0.75rem; max-width: 180px; min-width: 0;
  color: var(--text-color); font-size: 0.78rem; font-weight: 500;
  border: 1.5px solid var(--primary);
  box-shadow: 0 4px 16px rgba(0,0,0,0.3), 0 0 12px rgba(0,0,0,0.1);
  flex-shrink: 1; flex-basis: 140px; line-height: 1.4;
  animation: bubblePop 0.4s ease-out;
  text-shadow: 0 0 8px var(--primary);
  word-break: break-word;
}
@keyframes bubblePop { from{opacity:0;transform:scale(.85)} to{opacity:1;transform:scale(1)} }
.thought-bubble::before {
  content: ''; position: absolute; left: -13px; top: 20px;
  width: 0; height: 0;
  border-top: 11px solid transparent; border-bottom: 11px solid transparent;
  border-right: 13px solid var(--primary);
}
.thought-bubble::after {
  content: ''; position: absolute; left: -9px; top: 22px;
  width: 0; height: 0;
  border-top: 9px solid transparent; border-bottom: 9px solid transparent;
  border-right: 11px solid rgba(20,10,30,0.85);
}

/* ── Hero text ── */
.hero h1 {
  font-size: clamp(1.3rem,4vw,2rem); font-weight: 700; margin-bottom: 0.15rem;
  letter-spacing: -0.01em;
  background: linear-gradient(135deg, var(--text-color) 40%, var(--primary));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
}
.tagline { color: var(--text-muted-color); font-size: 0.78rem; margin-bottom: 0.3rem; }
.bio-desc { color: var(--text-color); font-size: 0.85rem; margin-bottom: 0.65rem; line-height: 1.55; opacity: 0.85; }

/* ── Social icons row ── */
.social-row { display: flex; justify-content: center; flex-wrap: wrap; gap: 0.38rem; }
.s-link {
  display: flex; align-items: center; justify-content: center;
  width: 34px; height: 34px; background: rgba(255,255,255,0.04);
  backdrop-filter: blur(8px); border: 1px solid var(--border);
  border-radius: var(--r-sm); color: var(--text-muted-color);
  font-size: 0.9rem; text-decoration: none; transition: all var(--t);
}
.s-link:hover { background: var(--card-hov); color: var(--text-color); border-color: var(--primary); transform: translateY(-3px); box-shadow: 0 6px 22px rgba(0,0,0,.35); }
.s-link img { width: 18px; height: 18px; object-fit: contain; }

/* ── Sections ── */
.section {
  position: relative; overflow: hidden; isolation: isolate;
  backdrop-filter: var(--glass); -webkit-backdrop-filter: var(--glass);
  border: 1px solid var(--border); border-radius: var(--r-md);
  padding: 0.75rem 0.8rem;
  box-shadow: 0 4px 24px var(--shadow);
  animation: slideUp 0.6s ease-out both;
  /* background set inline per-tab via rgba() so opacity only affects the bg, not text */
}
.sec-title {
  font-size: 0.78rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: 0.06em; color: var(--text-muted-color);
  margin-bottom: 0.6rem; display: flex; align-items: center; gap: 0.4rem;
}
.sec-title i { color: var(--primary); }
.card-list { display: flex; flex-direction: column; gap: 0.3rem; }
.p-card {
  display: flex; align-items: center; gap: 0.65rem;
  background: var(--card); border: 1px solid var(--border);
  padding: 0.65rem 0.75rem; border-radius: var(--r-sm);
  text-decoration: none; color: var(--text-color);
  transition: all var(--t); position: relative; overflow: hidden; cursor: pointer;
}
.p-card::before { content:''; position:absolute; top:0; left:0; width:3px; height:100%; background:var(--primary); opacity:0; transition:opacity var(--t); }
.p-card:hover { background: rgba(255,255,255,0.055); transform: translateX(5px); border-color: rgba(255,255,255,.14); }
.p-card:hover::before { opacity: 1; }
.p-card .arr { margin-left: auto; color: var(--text-muted-color); font-size: 0.75rem; transition: transform .15s, color .15s; }
.p-card:hover .arr { transform: translateX(4px); color: var(--primary); }
.p-icon { width: 33px; height: 33px; flex-shrink: 0; display: flex; align-items: center; justify-content: center; border-radius: 8px; font-size: 1rem; }
.p-info { display: flex; flex-direction: column; gap: 0.04rem; }
.p-name { font-weight: 600; font-size: 0.82rem; color: var(--text-color); line-height: 1.2; }
.p-desc { font-size: 0.67rem; color: var(--text-muted-color); line-height: 1.2; }

/* ── Action row ── */
.action-row { display: flex; gap: 8px; margin: 4px 0; }
.action-row .p-card { flex: 1; justify-content: center; padding: 12px; }
.action-row .p-card::before { display: none; }
.action-row .p-card:hover { transform: translateY(-2px) translateX(0); }

/* ── Footer ── */
.footer {
  background: var(--card); backdrop-filter: var(--glass); -webkit-backdrop-filter: var(--glass);
  border: 1px solid var(--border); border-radius: var(--r-md);
  padding: 0.6rem 0.8rem; text-align: center;
  color: var(--text-muted-color); font-size: 0.68rem;
  box-shadow: 0 4px 24px var(--shadow);
  animation: slideUp 0.6s ease-out 0.35s both;
}
.footer a { color: var(--primary); text-decoration: none; font-weight: 500; }
.footer a:hover { color: var(--accent); }

/* ── Toast ── */
.toast { position: fixed; bottom: 22px; left: 50%; transform: translateX(-50%); background: var(--card); backdrop-filter: var(--glass); -webkit-backdrop-filter: var(--glass); color: var(--text-color); padding: 11px 24px; border-radius: var(--r-full); z-index: 1000; opacity: 0; transition: opacity 0.32s ease; font-size: 13.5px; border: 1px solid var(--border); box-shadow: 0 8px 36px var(--shadow); pointer-events: none; white-space: nowrap; }

@keyframes slideUp { from{opacity:0;transform:translateY(22px)} to{opacity:1;transform:translateY(0)} }
.section:nth-child(2){animation-delay:.07s}.section:nth-child(3){animation-delay:.14s}.section:nth-child(4){animation-delay:.21s}.section:nth-child(5){animation-delay:.28s}

@media (min-width: 580px) {
  main { padding: 0.6rem 1.4rem 1.2rem; }
  .card-list { flex-direction: row; flex-wrap: wrap; gap: 0.3rem; }
  .p-card { flex: 1 1 calc(50% - 0.15rem); flex-direction: column; text-align: center; padding: 0.6rem 0.45rem; }
  .p-card::before { width: 100%; height: 3px; top: auto; bottom: 0; left: 0; }
  .p-card:hover { transform: translateY(-4px) translateX(0); }
  .p-card .arr { display: none; }
  .p-icon { margin: 0 auto; }
  .p-info { align-items: center; margin-top: 0.28rem; }
}
@media (min-width: 768px) {
  main { padding: 0.6rem 2rem 1.2rem; }
  .p-card { flex: 1 1 calc(33.33% - 0.2rem); }
}
/* ── Mobile tweaks ── keep the 3-column row, just shrink components */
@media (max-width: 480px) {
  main { padding: 0.4rem 0.4rem 1rem; gap: 0.4rem; }
  .photo-row { gap: 0.4rem; }
  .slug-vertical { font-size: 0.65rem; letter-spacing: 1px; padding: 0.4rem 0.2rem; max-height: 90px; }
  .avatar-wrap { width: 62px; height: 62px; }
  .avatar { width: 62px; height: 62px; }
  .avatar-ring { inset: -4px; }
  .thought-bubble { font-size: 0.7rem; padding: 0.4rem 0.55rem; flex-basis: 110px; max-width: 130px; }
  .thought-bubble::before { border-right-width: 10px; left: -10px; }
  .thought-bubble::after  { border-right-width: 8px; left: -7px; }
  .hero { padding: 0.7rem 0.5rem 0.65rem; }
  .sec-title { font-size: 0.72rem; }
  .p-name { font-size: 0.78rem; }
}

/* ── Gate overlays (password / sensitive / age) ── */
.gate-overlay {
  position: fixed; inset: 0; z-index: 9999;
  display: flex; align-items: center; justify-content: center;
  background: rgba(10,4,24,0.97);
  backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px);
  padding: 1.5rem;
}
.gate-card {
  background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12);
  border-radius: 20px; padding: 2.5rem 2rem; max-width: 420px; width: 100%;
  text-align: center; box-shadow: 0 24px 80px rgba(0,0,0,0.7);
}
.gate-icon { font-size: 3rem; margin-bottom: 1rem; }
.gate-title { font-size: 1.4rem; font-weight: 700; color: #f8f9fa; margin-bottom: .5rem; }
.gate-desc { font-size: .875rem; color: rgba(255,255,255,0.6); margin-bottom: 1.75rem; line-height: 1.6; }
.gate-input { width: 100%; padding: .75rem 1rem; border-radius: 10px; border: 1px solid rgba(255,255,255,0.15); background: rgba(255,255,255,0.08); color: #f8f9fa; font-size: 1rem; margin-bottom: 1rem; outline: none; text-align: center; letter-spacing: .1em; }
.gate-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(167,139,250,.2); }
.gate-btn { width: 100%; padding: .85rem; border-radius: 10px; background: var(--primary); color: #fff; font-size: 1rem; font-weight: 600; border: none; cursor: pointer; transition: opacity .2s; }
.gate-btn:hover { opacity: .88; }
.gate-btn-ghost { background: transparent; border: 1px solid rgba(255,255,255,.2); color: rgba(255,255,255,.7); margin-top: .5rem; }
.gate-err { color: #ff6b6b; font-size: .82rem; margin-top: -.5rem; margin-bottom: .75rem; }

/* ── Verified badge ── */
.verified-badge { display: inline-flex; align-items: center; gap: .2rem; background: linear-gradient(135deg,#1d9bf0,#0d6efd); color: #fff; font-size: .65rem; font-weight: 700; padding: .15rem .4rem; border-radius: 9999px; vertical-align: middle; margin-left: .3rem; letter-spacing: .03em; }
.verified-badge svg { width: 10px; height: 10px; fill: #fff; }

/* ── Cookie banner ── */
.cookie-banner { position: fixed; bottom: 0; left: 0; right: 0; z-index: 800; background: rgba(20,10,35,0.97); backdrop-filter: blur(16px); border-top: 1px solid rgba(255,255,255,.1); padding: 1rem 1.5rem; display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
.cookie-banner p { flex: 1; font-size: .82rem; color: rgba(255,255,255,.75); min-width: 200px; margin: 0; }
.cookie-banner button { padding: .5rem 1.25rem; border-radius: 9999px; font-size: .82rem; font-weight: 600; cursor: pointer; border: none; }
.cookie-accept { background: var(--primary); color: #fff; }
.cookie-decline { background: transparent; border: 1px solid rgba(255,255,255,.25) !important; color: rgba(255,255,255,.6); }
</style>
</head>
<body>

{% if gate == 'password' %}
<div class="gate-overlay">
  <div class="gate-card">
    <div class="gate-icon">🔐</div>
    <div class="gate-title">Password Protected</div>
    <div class="gate-desc">This Bio Page is private. Enter the password to continue.</div>
    <form method="POST" action="/@{{ profile.custom_slug }}/unlock">
      <input class="gate-input" type="password" name="password" placeholder="Enter password" autofocus required />
      <button class="gate-btn" type="submit" style="margin-top:.5rem;">Unlock →</button>
    </form>
  </div>
</div>
{% else %}

{% if profile.is_sensitive %}
<div class="gate-overlay" id="sensitiveGate">
  <div class="gate-card">
    <div class="gate-icon">⚠️</div>
    <div class="gate-title">Sensitive Content</div>
    <div class="gate-desc">This Bio Page may contain content that some viewers find sensitive or not suitable for all audiences.</div>
    <button class="gate-btn" onclick="dismissSensitive()">I Understand, Continue</button>
    <br>
    <button class="gate-btn gate-btn-ghost" onclick="history.back()" style="margin-top:.5rem;">Go Back</button>
  </div>
</div>
{% endif %}

{% if profile.age_restriction %}
<div class="gate-overlay" id="ageGate"{% if profile.is_sensitive %} style="display:none;"{% endif %}>
  <div class="gate-card">
    <div class="gate-icon">🔞</div>
    <div class="gate-title">Age Verification Required</div>
    <div class="gate-desc">You must be 18 years of age or older to view this page. By continuing, you confirm that you meet this requirement.</div>
    <button class="gate-btn" onclick="confirmAge()">I Am 18 or Older</button>
    <br>
    <button class="gate-btn gate-btn-ghost" onclick="history.back()" style="margin-top:.5rem;">I Am Under 18</button>
  </div>
</div>
{% endif %}

{% if profile.cookie_popup %}
<div class="cookie-banner" id="cookieBanner">
  <p>🍪 This page uses cookies to enhance your experience. By continuing, you agree to our use of cookies.</p>
  <button class="cookie-accept" onclick="acceptCookies()">Accept</button>
  <button class="cookie-decline" onclick="acceptCookies()">Decline</button>
</div>
{% endif %}

{% endif %}{# end gate #}

<div class="holiday-bg" id="holidayBg"></div>
<div class="bg-glow" id="bgGlow"></div>
<div class="bg-grid"></div>

<main>
  <!-- ═══ HERO ═══ -->
  {% set his = profile.header_image_size or 'half' %}
  {% set hbo = profile.header_bg_opacity or '0.45' %}
  {% set ss  = profile.slug_style or 'vertical-rotate' %}
  <header class="hero{% if his == 'cover' %} cover-mode{% endif %}"
    {% if his == 'cover' and profile.header_image_url %}
    style="--cover-image-url:url('{{ profile.header_image_url }}');--header-banner-opacity-inv:{{ (1.0 - hbo|float)|round(2) }}"
    {% endif %}>
    {% if profile.header_image_url and his != 'cover' %}
    <img src="{{ profile.header_image_url }}" alt="" class="hero-banner size-{{ his }}"
         style="--header-banner-opacity:{{ hbo }}">
    {% endif %}
    <div class="tech-layer" id="heroLayer"></div>
    <div class="hero-content">

      <!-- Photo row: @slug LEFT · avatar CENTER · status bubble RIGHT -->
      <div class="photo-row">
        {% if profile.custom_slug and ss != 'hidden' %}
        <div class="slug-vertical {% if ss == 'horizontal' %}slug-horizontal{% elif ss == 'vertical-fixed' %}slug-vfixed{% endif %}"
             onclick="copySlug('@{{ profile.custom_slug }}')"
             title="Click to copy @{{ profile.custom_slug }}"
             style="cursor:pointer;">@{{ profile.custom_slug }}</div>
        {% elif ss == 'hidden' %}
        <div style="width:32px;flex-shrink:0;"></div>
        {% endif %}

        <div class="avatar-wrap"{% if not profile.display_avatar %} style="display:none;"{% endif %}>
          {# Effect ring — only shown when avatar_style is not 'none' #}
          {% set afx = profile.avatar_style if profile.avatar_style else 'none' %}
          {% if afx != 'none' %}<div class="avatar-ring{% if afx == 'rainbow' %} rainbow{% endif %}"></div>{% endif %}
          {% if profile.profile_photo_url %}
          <img src="{{ profile.profile_photo_url }}" alt="{{ profile.header_text or profile.custom_slug }}"
               class="avatar {{ profile.profile_photo_style }}{% if afx == 'pulse' %} pulse{% elif afx == 'glow' %} glow{% endif %}"
               onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">
          {% endif %}
          <div class="avatar-fallback" {% if profile.profile_photo_url %}style="display:none"{% endif %}>
            <i class="fas fa-user"></i>
          </div>
        </div>

        {% if profile.daily_status %}
        <div class="thought-bubble">{{ profile.daily_status }}</div>
        {% endif %}
      </div>

      {% if profile.header_text %}
      <h1>{{ profile.header_text }}{% if profile.is_verified %} <span class="verified-badge"><svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" stroke="#fff" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg> Verified</span>{% endif %}</h1>
      {% endif %}
      {% if profile.sub_header_text %}
      <p class="tagline">{{ profile.sub_header_text }}</p>
      {% endif %}
      {% if profile.bio_description %}
      <p class="bio-desc">{{ profile.bio_description }}</p>
      {% endif %}

      <!-- Social icons -->
      {% if profile.show_social_icons and social_icons %}
      <div class="social-row">
        {% for icon in social_icons %}
        <a href="{{ icon.url }}" target="_blank" rel="noopener" class="s-link" title="{{ icon.platform }}">
          {% if icon.icon_url %}
          <img src="{{ icon.icon_url if icon.icon_url.startswith('http') else base_url.rstrip('/') + icon.icon_url }}" alt="{{ icon.platform }}" style="width:18px;height:18px;object-fit:contain;border-radius:3px;">
          {% else %}
          <i class="fas fa-link"></i>
          {% endif %}
        </a>
        {% endfor %}
      </div>
      {% endif %}
    </div>
  </header>

  <!-- ═══ TABS AS SECTIONS ═══ -->
  {# icon and accent-color per tab type #}
  {% set TYPE_ICON  = {'links':'fas fa-link','social':'fas fa-share-alt','contact':'fas fa-envelope','text':'fas fa-align-left','video':'fas fa-play-circle','gallery':'fas fa-images'} %}
  {% set TYPE_LABEL = {'links':'fas fa-globe','social':'fas fa-share-nodes','contact':'fas fa-address-card','text':'fas fa-file-alt','video':'fas fa-video','gallery':'fas fa-photo-film'} %}
  {# rotating icon accent colors — cycles for each link card #}
  {% set ICON_COLORS = [
    ('rgba(255,0,0,.15)',     '#ff4444'),
    ('rgba(99,100,255,.15)',  '#6364ff'),
    ('rgba(0,183,241,.15)',   '#00b7f1'),
    ('rgba(52,168,83,.15)',   '#34a853'),
    ('rgba(155,89,182,.15)',  '#9b59b6'),
    ('rgba(255,153,0,.15)',   '#ff9900'),
    ('rgba(232,68,68,.15)',   '#e84444'),
    ('rgba(30,215,96,.15)',   '#1ed760'),
    ('rgba(0,128,255,.15)',   '#0a80ff'),
    ('rgba(241,196,15,.15)',  '#f1c40f'),
  ] %}

  {% for tab in tabs %}
  {% set op = tab.tab_bg_opacity if tab.tab_bg_opacity else '0.85' %}
  {% set ts = tab.tab_style if tab.tab_style else 'solid' %}
  {% set tc = tab.tab_text_color if tab.tab_text_color else '' %}
  {% if tab.bg_url %}
    {# === Has background image: opacity controls image visibility (like header), style applies overlay on top === #}
    {% if ts == 'glass' %}
      {% set overlay = 'rgba(0,0,0,' ~ (1.0 - op|float)|round(2) ~ ')' %}
      {% set extra_css = 'backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);' %}
    {% elif ts == 'frost' %}
      {% set overlay = 'rgba(255,255,255,' ~ (1.0 - op|float)|round(2) ~ ')' %}
      {% set extra_css = 'backdrop-filter:blur(24px) saturate(1.4);-webkit-backdrop-filter:blur(24px) saturate(1.4);' %}
    {% elif ts == 'transparent' %}
      {% set overlay = 'rgba(0,0,0,0)' %}
      {% set extra_css = '' %}
    {% else %}
      {# solid #}
      {% set overlay = 'rgba(0,0,0,' ~ (1.0 - op|float)|round(2) ~ ')' %}
      {% set extra_css = '' %}
    {% endif %}
  <section class="section"
    style="background-image:url({{ tab.bg_url if tab.bg_url.startswith('http') else base_url.rstrip('/') + tab.bg_url }});background-size:cover;background-position:center;{{ extra_css }}{% if tc %}color:{{ tc }};{% endif %}"
  ><div class="tab-img-overlay" style="position:absolute;inset:0;background:{{ overlay }};z-index:0;border-radius:inherit;"></div>
  {% else %}
    {# === No background image: style + opacity control the card background color === #}
    {% if ts == 'glass' %}
      {% set bg_css = 'background:rgba(255,255,255,' ~ (op|float * 0.12)|round(3) ~ ');backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);' %}
    {% elif ts == 'frost' %}
      {% set bg_css = 'background:rgba(255,255,255,' ~ (op|float * 0.22)|round(3) ~ ');backdrop-filter:blur(24px) saturate(1.4);-webkit-backdrop-filter:blur(24px) saturate(1.4);' %}
    {% elif ts == 'transparent' %}
      {% set bg_css = 'background:rgba(0,0,0,0);backdrop-filter:none;' %}
    {% else %}
      {# solid — scale the theme's card opacity by the user's chosen opacity #}
      {% set bg_css = 'background:color-mix(in srgb, var(--card) ' ~ (op|float * 100)|round|int ~ '%, transparent);' %}
    {% endif %}
  <section class="section"
    style="{{ bg_css }}{% if tc %}color:{{ tc }};{% endif %}"
  ><div style="display:none"></div>
  {% endif %}
    <div style="position:relative;z-index:1;">
    {# Section title with type icon #}
    <h2 class="sec-title" {% if tc %}style="color:{{ tc }};opacity:0.85;"{% endif %}>
      <i class="{{ TYPE_LABEL.get(tab.tab_type, 'fas fa-layer-group') }}"></i>
      {{ tab.title }}
    </h2>

    {# Optional text content shown above links #}
    {% if tab.text_content %}
    <p style="font-size:.82rem;color:{% if tc %}{{ tc }}{% else %}var(--text-muted-color){% endif %};margin-bottom:.65rem;line-height:1.5;">{{ tab.text_content }}</p>
    {% endif %}

    {# ── Link cards ── #}
    {% if tab.links %}
    <div class="card-list">
      {% for link in tab.links %}
      {% set ci = loop.index0 % 10 %}
      {% set ibg = ICON_COLORS[ci][0] %}
      {% set iclr = ICON_COLORS[ci][1] %}

      {# ── Video embed ── #}
      {% if link.link_type == 'embed' or link.url | is_embed %}
      <div class="p-card" style="flex-direction:column;padding:.75rem;">
        <div style="display:flex;align-items:center;gap:.65rem;width:100%;margin-bottom:.55rem;">
          <div class="p-icon" style="background:{{ ibg }};color:{{ iclr }}"><i class="fas fa-play-circle"></i></div>
          <div class="p-info">
            <span class="p-name">{{ link.title }}</span>
            {% if link.description %}<span class="p-desc">{{ link.description }}</span>{% endif %}
          </div>
        </div>
        <div style="width:100%;border-radius:8px;overflow:hidden;aspect-ratio:16/9;">
          <iframe src="{{ link.url | embed_url }}" frameborder="0" allowfullscreen style="width:100%;height:100%;border:none;"></iframe>
        </div>
      </div>

      {# ── Image link ── #}
      {% elif link.link_type == 'image' %}
      {% set imgurl = link.url if link.url.startswith('http') else base_url.rstrip('/') + link.url %}
      <a href="{{ imgurl }}" target="_blank" rel="noopener" class="p-card" style="flex-direction:column;padding:0;overflow:hidden;">
        <img src="{{ imgurl }}" alt="{{ link.title }}" style="width:100%;max-height:220px;object-fit:cover;border-radius:var(--r-sm);">
        {% if link.title or link.description %}
        <div style="padding:.55rem .75rem;width:100%;">
          {% if link.title %}<span class="p-name">{{ link.title }}</span>{% endif %}
          {% if link.description %}<span class="p-desc" style="display:block;margin-top:2px;">{{ link.description }}</span>{% endif %}
        </div>
        {% endif %}
      </a>

      {# ── Email link ── #}
      {% elif link.link_type == 'email' %}
      <a href="mailto:{{ link.url }}" class="p-card">
        <div class="p-icon" style="background:{{ ibg }};color:{{ iclr }};flex-shrink:0;">
          <i class="fas fa-envelope"></i>
        </div>
        <div class="p-info">
          <span class="p-name">{{ link.title }}</span>
          {% if link.description %}<span class="p-desc">{{ link.description }}</span>{% endif %}
          <span class="p-desc">{{ link.url }}</span>
        </div>
        <i class="fas fa-arrow-right arr"></i>
      </a>

      {# ── Phone link ── #}
      {% elif link.link_type == 'phone' %}
      <a href="tel:{{ link.url }}" class="p-card">
        <div class="p-icon" style="background:{{ ibg }};color:{{ iclr }};flex-shrink:0;">
          <i class="fas fa-phone"></i>
        </div>
        <div class="p-info">
          <span class="p-name">{{ link.title }}</span>
          {% if link.description %}<span class="p-desc">{{ link.description }}</span>{% endif %}
          <span class="p-desc">{{ link.url }}</span>
        </div>
        <i class="fas fa-arrow-right arr"></i>
      </a>

      {# ── Address click-to-copy ── #}
      {% elif link.link_type == 'address' %}
      <div class="p-card" onclick="copyAddress('{{ link.url }}', this)" style="cursor:pointer;">
        <div class="p-icon" style="background:{{ ibg }};color:{{ iclr }};flex-shrink:0;">
          <i class="fas fa-map-marker-alt"></i>
        </div>
        <div class="p-info">
          <span class="p-name">{{ link.title }}</span>
          {% if link.description %}<span class="p-desc">{{ link.description }}</span>{% endif %}
          <span class="p-desc">{{ link.url }}</span>
        </div>
        <i class="fas fa-copy arr"></i>
      </div>

      {# ── Regular link card ── #}
      {% else %}
      <a href="{{ link.url }}" target="_blank" rel="noopener" class="p-card">
        <div class="p-icon" style="background:{{ ibg }};color:{{ iclr }};flex-shrink:0;">
          {% if link.thumbnail_url %}
          {# Fix relative /uploads/ paths to absolute URL #}
          {% set thumb = link.thumbnail_url if link.thumbnail_url.startswith('http') else base_url.rstrip('/') + link.thumbnail_url %}
          <img src="{{ thumb }}" alt="" style="width:22px;height:22px;border-radius:4px;object-fit:cover;">
          {% else %}
          <i class="{{ TYPE_ICON.get(tab.tab_type, 'fas fa-link') }}"></i>
          {% endif %}
        </div>
        <div class="p-info">
          <span class="p-name">{{ link.title }}</span>
          {% if link.description %}<span class="p-desc">{{ link.description }}</span>{% endif %}
        </div>
        <i class="fas fa-arrow-right arr"></i>
      </a>
      {% endif %}
      {% endfor %}
    </div>
    {% endif %}

    </div>{# end z-index:1 wrapper #}
  </section>
  {% endfor %}

  <!-- ═══ ACTION BUTTONS ═══ -->
  <div class="action-row">
    {% if profile.show_share_icon %}
    <button class="p-card" onclick="shareProfile()">
      <i class="fas fa-share-alt" style="color:var(--primary);margin-right:7px"></i>
      <span class="p-name">SHARE PAGE</span>
    </button>
    {% endif %}
    <a href="{{ config.FRONTEND_URL }}/report?slug={{ profile.custom_slug }}" class="p-card" target="_blank">
      <i class="fas fa-flag" style="color:#e74c3c;margin-right:7px"></i>
      <span class="p-name">REPORT</span>
    </a>
  </div>

  <!-- ═══ FOOTER ═══ -->
  {% if not profile.remove_branding %}
  <footer class="footer">
    <div class="tech-layer" id="footerLayer" style="opacity:.35"></div>
    <p style="position:relative;z-index:2">
      Powered by <a href="{{ base_url }}">{{ config.SITE_NAME or 'LinkPlatform' }}</a> &bull;
      V{{ config.SITE_VERSION or '11.7.5' }}
    </p>
  </footer>
  {% endif %}
</main>

<div class="toast" id="toast"></div>

<script>
/* ── Theme setup ── */
(function() {
  const r = document.documentElement;
  const get = p => getComputedStyle(r).getPropertyValue(p).trim();

  // Apply bg glow based on current CSS vars
  const glow = document.getElementById('bgGlow');
  function setGlow() {
    const p = get('--primary'), s = get('--secondary'), a = get('--accent');
    if (glow) glow.style.background = `
      radial-gradient(ellipse at 20% 20%, ${p}14 0%, transparent 50%),
      radial-gradient(ellipse at 80% 80%, ${s}10 0%, transparent 50%),
      radial-gradient(ellipse at 50% 50%, ${a}0a 0%, transparent 50%)`;
  }
  setGlow();

  /* ── Tech layer builder ── */
  function buildTechLayer(id, binCount, lineCount) {
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = '';
    const p = get('--primary'), s = get('--secondary'), a = get('--accent');
    const grid = document.createElement('div'); grid.className = 'tech-grid-bg'; el.appendChild(grid);
    for (let i = 0; i < lineCount; i++) {
      const ln = document.createElement('div'); ln.className = 'c-line';
      ln.style.top = `${15 + i*(65/lineCount)}%`; ln.style.animationDelay = `${i*1.1}s`; el.appendChild(ln);
    }
    for (let i = 0; i < 8; i++) {
      const d = document.createElement('div'); d.className = 'c-dot';
      d.style.left = `${Math.random()*96}%`; d.style.top = `${Math.random()*90}%`; d.style.animationDelay = `${Math.random()*2.5}s`; el.appendChild(d);
    }
    const br = document.createElement('div'); br.className = 'bin-rain'; el.appendChild(br);
    for (let i = 0; i < binCount; i++) {
      const d = document.createElement('span'); d.className = 'bin-d';
      d.textContent = Math.random()>.5?'1':'0'; d.style.left = `${Math.random()*100}%`;
      d.style.animationDuration = `${Math.random()*3.5+2.5}s`; d.style.animationDelay = `${Math.random()*6}s`;
      d.style.color = Math.random()>.5?p:s; br.appendChild(d);
    }
    const h = document.createElement('div'); h.className = 'holo'; el.appendChild(h);
  }
  buildTechLayer('heroLayer', 18, 3);
  buildTechLayer('footerLayer', 6, 2);

  /* ── Holiday particle effects ── */
  const fx = window.THEME_FX || 'petals';
  const c = document.getElementById('holidayBg');
  if (c && fx) {
    const FXMAP = {
      petals:    () => { const cl=['#ff6b9d','#ffd166','#ff85b3','#ffb347']; for(let i=0;i<22;i++){const e=document.createElement('div');e.className='petal-dot';Object.assign(e.style,{left:`${Math.random()*100}%`,background:cl[i%cl.length],animationDuration:`${Math.random()*5+4}s`,animationDelay:`${Math.random()*7}s`,opacity:'0.72'});c.appendChild(e);}},
      snow:      () => { for(let i=0;i<45;i++){const e=document.createElement('div');e.className='snow-dot';const sz=Math.random()*4+2;Object.assign(e.style,{width:`${sz}px`,height:`${sz}px`,left:`${Math.random()*100}%`,top:`${-Math.random()*20}%`,animationDuration:`${Math.random()*7+5}s`,animationDelay:`${Math.random()*7}s`,opacity:`${Math.random()*0.6+0.2}`});c.appendChild(e);}},
      hearts:    () => { for(let i=0;i<22;i++){const e=document.createElement('div');e.className='heart-dot';e.textContent='♥';Object.assign(e.style,{left:`${Math.random()*100}%`,fontSize:`${Math.random()*14+9}px`,animationDuration:`${Math.random()*5+4}s`,animationDelay:`${Math.random()*7}s`,opacity:`${Math.random()*0.5+0.3}`});c.appendChild(e);}},
      bats:      () => { for(let i=0;i<14;i++){const e=document.createElement('div');e.className='bat-dot';e.textContent='🦇';Object.assign(e.style,{top:`${Math.random()*55+5}%`,fontSize:`${Math.random()*10+14}px`,animationDuration:`${Math.random()*5+4}s`,animationDelay:`${Math.random()*9}s`});c.appendChild(e);}},
      confetti:  () => { const cl=['#e74c3c','#3498db','#f1c40f','#2ecc71','#9b59b6','#e84393']; for(let i=0;i<55;i++){const e=document.createElement('div');e.className='confetti-dot';Object.assign(e.style,{left:`${Math.random()*100}%`,width:`${Math.random()*8+4}px`,height:`${Math.random()*14+6}px`,background:cl[i%cl.length],borderRadius:Math.random()>.5?'50%':'2px',animationDuration:`${Math.random()*4+3}s`,animationDelay:`${Math.random()*5}s`});c.appendChild(e);}},
      fireflies: () => { for(let i=0;i<28;i++){const e=document.createElement('div');e.className='firefly-dot';Object.assign(e.style,{left:`${Math.random()*100}%`,top:`${Math.random()*100}%`,background:i%2===0?get('--primary'):get('--secondary'),color:i%2===0?get('--primary'):get('--secondary'),animationDuration:`${Math.random()*3+2}s`,animationDelay:`${Math.random()*4}s`});c.appendChild(e);}},
      leaves:    () => { const cl=['#d35400','#e67e22','#c0392b','#a04000','#935116']; for(let i=0;i<28;i++){const e=document.createElement('div');e.className='leaf-dot';Object.assign(e.style,{left:`${Math.random()*100}%`,background:cl[i%cl.length],animationDuration:`${Math.random()*5+4}s`,animationDelay:`${Math.random()*7}s`,opacity:'0.7'});c.appendChild(e);}},
      stars:     () => { const sy=['★','✦','✧','⋆','✶'],cl=['#f1c40f','#e74c3c','#3498db','#ffffff']; for(let i=0;i<35;i++){const e=document.createElement('div');e.className='star-dot';e.textContent=sy[i%sy.length];Object.assign(e.style,{left:`${Math.random()*100}%`,top:`${Math.random()*100}%`,color:cl[i%cl.length],fontSize:`${Math.random()*16+8}px`,animationDuration:`${Math.random()*2+1}s`,animationDelay:`${Math.random()*3}s`});c.appendChild(e);}},
      bunnies:   () => { for(let i=0;i<8;i++){const e=document.createElement('div');e.className='bunny-dot';e.textContent=i%2===0?'🐰':'🥚';Object.assign(e.style,{left:`${Math.random()*88+2}%`,top:`${60+Math.random()*30}%`,fontSize:`${Math.random()*12+16}px`,animationDuration:`${Math.random()*0.9+0.7}s`,animationDelay:`${Math.random()*2}s`,opacity:'0.62'});c.appendChild(e);}},
    };
    if (FXMAP[fx]) FXMAP[fx]();
  }
})();

/* ── Utils ── */
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg; t.style.opacity = '1';
  setTimeout(() => t.style.opacity = '0', 3200);
}
async function copySlug(slug) {
  try {
    await navigator.clipboard.writeText(slug);
    showToast('📋 ' + slug + ' copied!');
  } catch(e) { showToast('Copy manually: ' + slug); }
}
function copyAddress(addr, el) {
  navigator.clipboard.writeText(addr).then(() => {
    showToast('📋 Address copied!');
    if (el) { el.style.borderColor = 'var(--accent)'; setTimeout(()=>{ el.style.borderColor=''; }, 1500); }
  }).catch(() => showToast('Copy manually: ' + addr));
}
async function shareProfile() {
  try {
    if (navigator.share) await navigator.share({ title: document.title, url: location.href });
    else { await navigator.clipboard.writeText(location.href); showToast('Link copied! 🔗'); }
  } catch(e) { showToast('Copy the URL manually'); }
}
function sharePage() { shareProfile(); }

/* ── Sensitive content gate ── */
function dismissSensitive() {
  const sg = document.getElementById('sensitiveGate');
  if (sg) sg.remove();
  {% if profile.age_restriction %}
  const ag = document.getElementById('ageGate');
  if (ag) ag.style.display = 'flex';
  {% endif %}
}

/* ── Age gate ── */
function confirmAge() {
  const ag = document.getElementById('ageGate');
  if (ag) { ag.style.opacity = '0'; ag.style.transition = 'opacity .3s'; setTimeout(() => ag.remove(), 300); }
  sessionStorage.setItem('age_confirmed_{{ profile.custom_slug }}', '1');
}
(function() {
  {% if profile.age_restriction %}
  if (sessionStorage.getItem('age_confirmed_{{ profile.custom_slug }}')) {
    const ag = document.getElementById('ageGate'); if (ag) ag.remove();
  }
  {% endif %}
})();

/* ── Cookie banner ── */
function acceptCookies() {
  const b = document.getElementById('cookieBanner');
  if (b) { b.style.transition = 'opacity .3s'; b.style.opacity = '0'; setTimeout(() => b.remove(), 300); }
  localStorage.setItem('cookies_accepted_{{ profile.custom_slug }}', '1');
}
function declineCookies() { acceptCookies(); }
(function() {
  {% if profile.cookie_popup %}
  if (!localStorage.getItem('cookies_accepted_{{ profile.custom_slug }}')) {
    const b = document.getElementById('cookieBanner');
    if (b) { setTimeout(() => b.style.display = 'flex', 800); }
  }
  {% endif %}
})();
</script>
</body>
</html>
PROFILEHTML_EOF

# ---------- Templates: landing.html ----------
cat > backend/app/templates/landing.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ link.landing_page_title or 'Redirecting...' }}</title>
    <style>
        body {
            font-family: system-ui, sans-serif;
            background: #f8fafc;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 1rem;
        }
        .landing {
            max-width: 600px;
            background: white;
            border-radius: 1rem;
            padding: 2rem;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
            text-align: center;
        }
        .btn {
            background: var(--theme-color, #6366f1);
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: 0.5rem;
            text-decoration: none;
            display: inline-block;
            margin-top: 1rem;
        }
        .theme-{{ link.landing_page_theme }} {
            /* theme styles can be added here */
        }
    </style>
</head>
<body>
    <div class="landing theme-{{ link.landing_page_theme }}">
        <h1>{{ link.landing_page_title or 'You are being redirected' }}</h1>
        <p>{{ link.landing_page_body or '' }}</p>
        {% if link.landing_page_image %}
            <img src="{{ link.landing_page_image }}" alt="" style="max-width: 100%; border-radius: 0.5rem; margin: 1rem 0;">
        {% endif %}
        <a href="{{ link.original_url }}" class="btn">Continue to destination</a>
        <p style="font-size: 0.8rem; margin-top: 1rem;">You will be redirected in 10 seconds...</p>
    </div>
    <script>
        setTimeout(() => { window.location.href = "{{ link.original_url }}"; }, 10000);
    </script>
</body>
</html>
EOF

# ---------- Templates: page.html ----------
cat > backend/app/templates/page.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ page.title }} - {{ config.SITE_NAME }}</title>
    <style>
        body {
            font-family: system-ui, sans-serif;
            background: #f8fafc;
            margin: 0;
            padding: 2rem;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 1rem;
            padding: 2rem;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }
        .footer {
            margin-top: 2rem;
            text-align: center;
            font-size: 0.8rem;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ page.title }}</h1>
        <div>{{ page.content | safe }}</div>
        <div class="footer">
            <a href="/">← Back to Home</a>
        </div>
    </div>
</body>
</html>
EOF

# ---------- main.py (with migrations) ----------
cat > backend/app/main.py << 'MAIN_EOF'
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session
from .database import engine, Base, SessionLocal, get_db
from . import models
from .routers import auth, profile, links, admin, messages, public
from .routers import admin_nav, admin_pages, public_pages, public_nav
from .routers import users, twofa, email_templates
from .routers import custom_domains, analytics
from .services.redis_client import get_redis
from .services.redirect_service import RedirectService
from .auth import get_password_hash, normalize_email
from .config import settings
import os
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
logger = logging.getLogger("linkplatform")

# create_all is safe with checkfirst — it only creates tables that don't exist.
# Using a try/except ensures a second worker starting up doesn't crash if
# a table was just created by the first worker's process.
try:
    Base.metadata.create_all(bind=engine, checkfirst=True)
except Exception as e:
    import logging as _log
    _log.getLogger("linkplatform").warning(f"create_all skipped (already exists): {e}")

def run_migrations():
    migrations = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_layout VARCHAR DEFAULT 'center'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_photo_style VARCHAR DEFAULT 'circle'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS twofa_enabled BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS twofa_secret VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS twofa_backup_codes TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS twofa_last_reset_at TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_banned BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_suspended BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_password_token VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_password_expires TIMESTAMP WITH TIME ZONE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS accept_messages BOOLEAN DEFAULT TRUE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS slug_style VARCHAR DEFAULT 'vertical-rotate'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS header_image_size VARCHAR DEFAULT 'half'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS header_bg_opacity VARCHAR DEFAULT '0.45'",
        "ALTER TABLE profile_tabs ADD COLUMN IF NOT EXISTS tab_bg_opacity VARCHAR DEFAULT '0.85'",
        "ALTER TABLE profile_tabs ADD COLUMN IF NOT EXISTS tab_text_color VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_sensitive BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS age_restriction BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS cookie_popup BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS show_share_icon BOOLEAN DEFAULT TRUE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS remove_branding BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_password VARCHAR",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS display_avatar BOOLEAN DEFAULT TRUE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_style VARCHAR DEFAULT 'none'",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS can_use_custom_domain BOOLEAN DEFAULT FALSE",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_views INTEGER DEFAULT 0",
        "ALTER TABLE pages ADD COLUMN IF NOT EXISTS meta_title VARCHAR",
        "ALTER TABLE pages ADD COLUMN IF NOT EXISTS meta_description TEXT",
        "ALTER TABLE pages ADD COLUMN IF NOT EXISTS category VARCHAR",
        "ALTER TABLE pages ADD COLUMN IF NOT EXISTS language VARCHAR DEFAULT 'en'",
        "ALTER TABLE pages ADD COLUMN IF NOT EXISTS menu_visible BOOLEAN DEFAULT TRUE",
        # clicks table
        """CREATE TABLE IF NOT EXISTS clicks (
            id SERIAL PRIMARY KEY,
            link_id INTEGER REFERENCES links(id) ON DELETE SET NULL,
            ip VARCHAR,
            country VARCHAR,
            city VARCHAR,
            device VARCHAR,
            browser VARCHAR,
            os VARCHAR,
            referer VARCHAR,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )""",
        "CREATE INDEX IF NOT EXISTS idx_clicks_link_id ON clicks(link_id)",
        "CREATE INDEX IF NOT EXISTS idx_clicks_created_at ON clicks(created_at)",
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception as e:
                print(f"Migration skipped: {e}")

run_migrations()

def seed_defaults():
    db = SessionLocal()
    try:
        admin_email = normalize_email(settings.ADMIN_EMAIL)
        if not db.query(models.User).filter(models.User.email == admin_email).first():
            db.add(models.User(email=admin_email, password_hash=get_password_hash(settings.ADMIN_PASSWORD), role="admin", custom_slug="admin"))
            db.commit()
            print(f"✅ Admin created: {admin_email}")

        defaults = {
            "site_name": settings.SITE_NAME,
            "site_tagline": settings.SITE_TAGLINE,
            "site_footer": settings.SITE_FOOTER,
            "site_emoji": settings.SITE_EMOJI,
            "allow_user_messaging": "false",
            # SMTP defaults (will be editable)
            "smtp_host": settings.SMTP_HOST,
            "smtp_port": str(settings.SMTP_PORT),
            "smtp_user": settings.SMTP_USER,
            "smtp_password": settings.SMTP_PASSWORD,
            "smtp_use_tls": "true" if settings.SMTP_USE_TLS else "false",
        }
        for k, v in defaults.items():
            if not db.query(models.SiteConfig).filter(models.SiteConfig.key == k).first():
                db.add(models.SiteConfig(key=k, value=v))

        default_nav = [
            {"label": "Dashboard",  "path": "/dashboard",  "icon": "📊", "auth_required": True,  "admin_only": False, "order": 10, "is_system": True},
            {"label": "Create",     "path": "/create",     "icon": "✨", "auth_required": True,  "admin_only": False, "order": 20, "is_system": True},
            {"label": "Contact",    "path": "/p/contact",  "icon": "📞", "auth_required": False, "admin_only": False, "order": 25, "is_system": True},
            {"label": "Bio Profile","path": "/bio",        "icon": "🎨", "auth_required": True,  "admin_only": False, "order": 30, "is_system": True},
            {"label": "Messages",   "path": "/messages",   "icon": "💬", "auth_required": True,  "admin_only": False, "order": 40, "is_system": True},
            {"label": "2FA",        "path": "/2fa",        "icon": "🔐", "auth_required": True,  "admin_only": False, "order": 45, "is_system": True},
            {"label": "My Account", "path": "/myaccount",  "icon": "👤", "auth_required": True,  "admin_only": False, "order": 60, "is_system": True},
            {"label": "Admin",      "path": "/admin",      "icon": "👑", "auth_required": True,  "admin_only": True,  "order": 50, "is_system": True},
        ]
        for item in default_nav:
            if not db.query(models.NavItem).filter(models.NavItem.path == item["path"]).first():
                db.add(models.NavItem(**item))

        email_tmpl_item = {"label": "Email Templates", "path": "/admin/email-templates", "icon": "📧", "auth_required": True, "admin_only": True, "enabled": True, "order": 55, "is_system": False}
        if not db.query(models.NavItem).filter(models.NavItem.path == email_tmpl_item["path"]).first():
            db.add(models.NavItem(**email_tmpl_item))

        # Add SMTP admin nav item
        smtp_nav_item = {"label": "SMTP Settings", "path": "/admin/smtp", "icon": "📨", "auth_required": True, "admin_only": True, "enabled": True, "order": 56, "is_system": False}
        if not db.query(models.NavItem).filter(models.NavItem.path == smtp_nav_item["path"]).first():
            db.add(models.NavItem(**smtp_nav_item))

        # Seed default password reset email template
        reset_tmpl = db.query(models.EmailTemplate).filter(models.EmailTemplate.key == "password_reset").first()
        if not reset_tmpl:
            reset_html = '''<!DOCTYPE html>
<html>
<head><title>Reset your password</title></head>
<body style="font-family: sans-serif;">
  <h2>Password Reset Request</h2>
  <p>Hi {name},</p>
  <p>We received a request to reset your password for {site_name}. Click the link below to set a new password:</p>
  <p><a href="{reset_link}">{reset_link}</a></p>
  <p>This link will expire in 1 hour.</p>
  <p>If you didn't request this, you can safely ignore this email.</p>
</body>
</html>'''
            reset_text = '''Password Reset Request

Hi {name},

We received a request to reset your password for {site_name}. Copy and paste the following link into your browser to set a new password:

{reset_link}

This link will expire in 1 hour.

If you didn't request this, you can safely ignore this email.'''
            db.add(models.EmailTemplate(
                key="password_reset",
                subject="Reset your {site_name} password",
                body_html=reset_html,
                body_text=reset_text,
                enabled=True,
                for_admin=False
            ))
            print("✅ Password reset email template seeded")

        contact_page = db.query(models.Page).filter(models.Page.slug == "contact").first()
        if not contact_page:
            contact_html = f'''
<div class="container" style="background:white;width:100%;max-width:1000px;margin:0 auto;border-radius:10px;box-shadow:0 10px 25px rgba(0,0,0,0.1);overflow:hidden;display:flex;flex-wrap:wrap;">
  <div style="background:#4a90e2;color:white;flex:1;padding:40px;min-width:300px;">
    <h2 style="font-size:2rem;margin-bottom:20px;">Get in Touch</h2>
    <p style="margin-bottom:20px;opacity:.9;">Have a question? Send us a message!</p>
  </div>
  <div style="flex:1.5;padding:40px;min-width:300px;">
    <h2 style="margin-bottom:20px;">Send a Message</h2>
    <form id="contactForm" style="display:grid;gap:1rem;">
      <input type="text" id="cf-name" class="input" placeholder="Full Name" required>
      <input type="email" id="cf-email" class="input" placeholder="Email" required>
      <input type="text" id="cf-subject" class="input" placeholder="Subject" required>
      <textarea id="cf-message" rows="5" class="input" placeholder="Your message..." required></textarea>
      <button type="submit" class="btn" id="cfSubmit">Send Message</button>
      <div id="cfResult"></div>
    </form>
  </div>
</div>
<script>
(function(){{
  var form=document.getElementById('contactForm');
  if(!form)return;
  form.addEventListener('submit',async function(e){{
    e.preventDefault();
    var btn=document.getElementById('cfSubmit');
    var result=document.getElementById('cfResult');
    btn.disabled=true; btn.textContent='Sending...';
    try{{
      var r=await fetch('{settings.BASE_URL}/api/public/contact',{{
        method:'POST',headers:{{'Content-Type':'application/json'}},
        body:JSON.stringify({{
          name:document.getElementById('cf-name').value,
          email:document.getElementById('cf-email').value,
          subject:document.getElementById('cf-subject').value,
          message:document.getElementById('cf-message').value
        }})
      }});
      var d=await r.json();
      if(r.ok){{result.innerHTML='<span style="color:green">✅ Message sent!</span>';form.reset();}}
      else{{result.innerHTML='<span style="color:red">❌ '+( d.detail||'Error')+'</span>';}}
    }}catch(err){{result.innerHTML='<span style="color:red">❌ Network error</span>';}}
    finally{{btn.disabled=false;btn.textContent='Send Message';}}
  }});
}})();
</script>'''
            db.add(models.Page(title="Contact Us", slug="contact", content=contact_html, published=True))
            print("✅ Default contact page created")

        db.commit()
        print("✅ Seed complete")
    finally:
        db.close()

seed_defaults()

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

app = FastAPI(title=settings.SITE_NAME, version="11.8.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

uploads_path = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(uploads_path, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=uploads_path), name="uploads")

for r in [auth.router, profile.router, links.router, admin.router, messages.router, public.router,
          admin_nav.router, admin_pages.router, public_pages.router, public_nav.router, users.router,
          twofa.router, email_templates.router, custom_domains.router, analytics.router]:
    app.include_router(r)

@app.get("/api")
def api_root():
    return {"message": f"Welcome to {settings.SITE_NAME} API"}

@app.get("/")
async def root(request: Request, db: Session = Depends(get_db)):
    host = request.headers.get("host", "").split(":")[0].lower()
    domain_record = db.query(models.CustomDomain).filter(
        models.CustomDomain.domain == host,
        models.CustomDomain.is_verified == True
    ).first()
    if domain_record and domain_record.root_redirect:
        return RedirectResponse(url=domain_record.root_redirect, status_code=302)
    return {"message": f"{settings.SITE_NAME} API v11.7.8", "docs": "/docs"}

@app.get("/s/{short_code}")
async def handle_short_redirect(short_code: str, request: Request, db: Session = Depends(get_db)):
    host = request.headers.get("host", "").split(":")[0].lower()
    domain_record = db.query(models.CustomDomain).filter(
        models.CustomDomain.domain == host,
        models.CustomDomain.is_verified == True
    ).first()
    query = db.query(models.Link).filter(models.Link.short_code == short_code, models.Link.is_active == True)
    if domain_record:
        query = query.filter(models.Link.user_id == domain_record.user_id)
    link = query.first()
    if not link:
        if domain_record and domain_record.not_found_redirect:
            return RedirectResponse(url=domain_record.not_found_redirect, status_code=302)
        raise HTTPException(404, "Short link not found")
    # Record click via Redis queue (or direct fallback)
    request_info = {
        "ip": request.client.host if request.client else None,
        "referer": request.headers.get("referer"),
        "user_agent": request.headers.get("user-agent"),
    }
    RedirectService.record_click(db, link, request_info)
    return RedirectResponse(url=link.original_url, status_code=302)

@app.get("/l/{short_code}", response_class=HTMLResponse)
async def handle_landing_page(request: Request, short_code: str, db: Session = Depends(get_db)):
    host = request.headers.get("host", "").split(":")[0].lower()
    domain_record = db.query(models.CustomDomain).filter(
        models.CustomDomain.domain == host,
        models.CustomDomain.is_verified == True
    ).first()
    query = db.query(models.Link).filter(models.Link.short_code == short_code, models.Link.is_active == True)
    if domain_record:
        query = query.filter(models.Link.user_id == domain_record.user_id)
    link = query.first()
    if not link:
        if domain_record and domain_record.not_found_redirect:
            return RedirectResponse(url=domain_record.not_found_redirect, status_code=302)
        raise HTTPException(404, "Link not found")
    request_info = {
        "ip": request.client.host if request.client else None,
        "referer": request.headers.get("referer"),
        "user_agent": request.headers.get("user-agent"),
    }
    RedirectService.record_click(db, link, request_info)
    if link.landing_page_enabled:
        return templates.TemplateResponse("landing.html", {"request": request, "link": link})
    return RedirectResponse(url=link.original_url, status_code=302)
MAIN_EOF

# ── Patch CORS origins in main.py ─────────────────────────────────────────────
# allow_origins=["*"] + allow_credentials=True is rejected by browsers.
# We build an explicit list: localhost variants + local IP + domain (if set).
_LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
_CORS_ORIGINS="\"http://localhost\""
_CORS_ORIGINS="${_CORS_ORIGINS}, \"http://localhost:${FRONTEND_PORT}\""
_CORS_ORIGINS="${_CORS_ORIGINS}, \"http://localhost:${BACKEND_PORT}\""
_CORS_ORIGINS="${_CORS_ORIGINS}, \"http://127.0.0.1\""
[ -n "$_LOCAL_IP" ] && _CORS_ORIGINS="${_CORS_ORIGINS}, \"http://${_LOCAL_IP}\""
[ -n "$DEPLOY_DOMAIN" ] && _CORS_ORIGINS="${_CORS_ORIGINS}, \"http://${DEPLOY_DOMAIN}\", \"https://${DEPLOY_DOMAIN}\", \"http://www.${DEPLOY_DOMAIN}\", \"https://www.${DEPLOY_DOMAIN}\""

sed -i "s|app\.add_middleware(CORSMiddleware, allow_origins=\[\"\\*\"\], allow_credentials=True, allow_methods=\[\"\\*\"\], allow_headers=\[\"\\*\"\])|app.add_middleware(CORSMiddleware, allow_origins=[${_CORS_ORIGINS}], allow_credentials=True, allow_methods=[\"*\"], allow_headers=[\"*\"])|" backend/app/main.py
echo "✅ CORS origins patched (localhost + IP${DEPLOY_DOMAIN:+ + $DEPLOY_DOMAIN})"
# ─────────────────────────────────────────────────────────────────────────────

# ============================================================================
# FRONTEND
# ============================================================================
echo "🎨 Creating frontend..."

# ---------- frontend/package.json ----------
cat > frontend/package.json << 'EOF'
{"name":"link-platform","version":"11.7.2","type":"module","scripts":{"dev":"vite --force","build":"vite build","preview":"vite preview"},"dependencies":{"react":"^18.2.0","react-dom":"^18.2.0","react-router-dom":"^6.20.0","axios":"^1.6.0","qrcode.react":"^3.1.0"},"devDependencies":{"@vitejs/plugin-react":"^4.1.0","vite":"^4.5.0"}}
EOF

# ---------- frontend/Dockerfile ----------
cat > frontend/Dockerfile << 'FNDOCKEREOF'
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --frozen-lockfile 2>/dev/null || npm install
COPY . .
EXPOSE 3000
CMD ["npm","run","dev","--","--host","0.0.0.0","--port","3000"]
FNDOCKEREOF

# ---------- frontend/vite.config.js ----------
cat > frontend/vite.config.js << 'EOF'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    strictPort: true,
    watch: { usePolling: true },
    allowedHosts: ['localhost', '127.0.0.1', '__DEPLOY_DOMAIN_PLACEHOLDER__']
  },
  build: {
    rollupOptions: {
      input: 'index.html'
    }
  },
  optimizeDeps: {
    include: ['react', 'react-dom', 'react-router-dom', 'axios']
  }
})
EOF

# ── Patch vite.config.js allowedHosts ────────────────────────────────────────
# Vite rejects requests from unknown hostnames with "Blocked request. This host
# is not allowed." We build the allowedHosts list at install time so the domain
# works immediately without any manual vite.config.js edits.
_LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
_VITE_HOSTS="'localhost', '127.0.0.1'"
[ -n "$_LOCAL_IP" ] && _VITE_HOSTS="${_VITE_HOSTS}, '${_LOCAL_IP}'"
if [ -n "$DEPLOY_DOMAIN" ]; then
  _VITE_HOSTS="${_VITE_HOSTS}, '${DEPLOY_DOMAIN}', 'www.${DEPLOY_DOMAIN}'"
fi
# Replace the placeholder with the full computed list
sed -i "s|'__DEPLOY_DOMAIN_PLACEHOLDER__'|${_VITE_HOSTS}|" frontend/vite.config.js
echo "✅ Vite allowedHosts patched: ${_VITE_HOSTS}"
# ─────────────────────────────────────────────────────────────────────────────

# ---------- frontend/.env ----------
# VITE_API_BASE_URL is intentionally left empty so all API calls use relative
# paths (e.g. /api/...). NGINX proxies them to the backend regardless of whether
# the browser hit localhost, local IP, or the domain — zero CORS issues.
cat > frontend/.env << 'EOF'
VITE_API_BASE_URL=
EOF

# ---------- frontend/index.html ----------
cat > frontend/index.html << EOF
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>${SITE_NAME}</title></head><body><div id="root"></div><script type="module" src="/src/main.jsx"></script></body></html>
EOF

# ---------- frontend/src/main.jsx ----------
cat > frontend/src/main.jsx << 'EOF'
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './styles/theme.css'
ReactDOM.createRoot(document.getElementById('root')).render(<React.StrictMode><App /></React.StrictMode>)
EOF

# ---------- frontend/src/styles/theme.css ----------
cat > frontend/src/styles/theme.css << 'EOF'
:root {
  --primary:#6366f1; --primary-hover:#4f46e5;
  --bg:#f8fafc; --surface:#fff; --surface2:#f1f5f9;
  --text:#0f172a; --text-muted:#64748b; --text-inv:#fff;
  --border:#e2e8f0; --border-strong:#cbd5e1;
  --radius:.75rem; --shadow:0 4px 6px -1px rgb(0 0 0/0.1);
  --danger:#ef4444; --success:#22c55e;
  --container-padding: 2rem;
}
[data-theme="dark"] {
  --bg:#0f172a; --surface:#1e293b; --surface2:#334155;
  --text:#f1f5f9; --text-muted:#94a3b8;
  --border:#334155; --border-strong:#475569;
  --shadow:0 4px 6px -1px rgb(0 0 0/0.4);
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:system-ui,sans-serif;
  background:var(--bg);
  color:var(--text);
  line-height:1.6;
  transition:background .2s,color .2s;
  padding:0;
}
.main-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: var(--container-padding);
}
.glass{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius);
  box-shadow:var(--shadow);
}
.btn{
  display:inline-flex;align-items:center;gap:.5rem;
  padding:.625rem 1.25rem;font-weight:500;
  border-radius:var(--radius);border:none;cursor:pointer;
  background:var(--primary);color:#fff;transition:.2s;white-space:nowrap;
}
.btn:hover{background:var(--primary-hover);transform:translateY(-1px)}
.btn:disabled{opacity:.6;cursor:not-allowed;transform:none}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--text)}
.btn-outline:hover{background:var(--border)}
.btn-danger{background:#fef2f2;color:var(--danger);border:1px solid #fecaca}
.btn-danger:hover{background:#fee2e2}
.input{
  width:100%;padding:.75rem 1rem;
  border:2px solid var(--border);border-radius:var(--radius);
  background:var(--surface);color:var(--text);font-size:.9rem;
}
.input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,.15)}
select.input{cursor:pointer}
textarea.input{resize:vertical;min-height:80px}
.nav{
  position:sticky;top:0;z-index:200;
  display:flex;align-items:center;justify-content:space-between;
  padding:.875rem 1.5rem;
  background:var(--surface);
  border-bottom:1px solid var(--border);
  flex-wrap:wrap;gap:.5rem;
}
.nav-brand{display:flex;align-items:center;gap:.5rem;font-weight:700;color:var(--text);text-decoration:none;font-size:1.1rem}
.nav-links{display:flex;gap:.25rem;align-items:center;flex-wrap:wrap}
.nav-link{padding:.45rem .9rem;color:var(--text-muted);text-decoration:none;border-radius:var(--radius);transition:.2s;font-size:.875rem}
.nav-link:hover,.nav-link.active{color:var(--primary);background:rgba(99,102,241,.08)}
.bell-wrap{position:relative;cursor:pointer;padding:.45rem;border-radius:50%;transition:.2s;margin-right:.25rem}
.bell-wrap:hover{background:var(--surface2)}
.bell-badge{position:absolute;top:2px;right:2px;background:var(--danger);color:white;font-size:.6rem;font-weight:700;min-width:16px;height:16px;border-radius:8px;display:flex;align-items:center;justify-content:center;padding:0 4px;border:2px solid var(--surface)}
.card{padding:1.25rem;display:flex;flex-direction:column;gap:.875rem}
.short-code{font-family:monospace;font-weight:600;color:var(--primary)}
.original-url{color:var(--text-muted);text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.original-url:hover{color:var(--primary)}
.actions{display:flex;gap:.25rem;flex-shrink:0}
.stats{display:flex;gap:1rem;font-size:.8rem;color:var(--text-muted)}
.empty{text-align:center;padding:3rem 1.5rem;color:var(--text-muted)}
.empty-icon{font-size:3rem;margin-bottom:.75rem;opacity:.6}
.table-responsive { overflow-x: auto; -webkit-overflow-scrolling: touch; margin: 1rem 0; }
table { width: 100%; border-collapse: collapse; min-width: 600px; }
.toast{
  position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;
  padding:.75rem 1.25rem;background:var(--surface);
  border:1px solid var(--border);border-radius:var(--radius);
  box-shadow:0 8px 24px rgba(0,0,0,.15);animation:slideIn .3s ease;
  max-width:340px;
}
.toast.success{border-left:4px solid var(--success)}
.toast.error{border-left:4px solid var(--danger)}
@keyframes slideIn{from{transform:translateX(110%);opacity:0}to{transform:translateX(0);opacity:1}}
.url-badge{
  display:inline-flex;align-items:center;gap:.2rem;
  font-size:.7rem;font-weight:700;padding:.15rem .5rem;
  border-radius:.3rem;font-family:monospace;flex-shrink:0;
}
.url-badge.short{background:#e0e7ff;color:#4338ca}
.url-badge.landing{background:#fce7f3;color:#9d174d}
@media (max-width: 768px) {
  :root { --container-padding: 1rem; }
  .nav { padding: .5rem 1rem; }
  .nav-brand { font-size: 1rem; }
  .nav-link { padding: .3rem .6rem; font-size: .8rem; }
  .btn { padding: .5rem 1rem; font-size: .875rem; }
  .card { padding: 1rem; }
  .actions { flex-wrap: wrap; justify-content: flex-end; }
  .stats { flex-wrap: wrap; gap: .5rem; }
  .toast { left: 1rem; right: 1rem; max-width: none; bottom: 1rem; }
}
@media (max-width: 480px) {
  .nav { flex-direction: column; align-items: stretch; }
  .nav-links { justify-content: center; }
  .nav-brand { text-align: center; margin-bottom: .25rem; }
  .btn { width: 100%; justify-content: center; }
  .card > div:first-child { flex-direction: column; align-items: flex-start !important; }
  .original-url { max-width: 100%; word-break: break-all; white-space: normal; }
}
EOF

# ---------- frontend/src/config.js ----------
cat > frontend/src/config.js << 'EOF'
export const SITE_NAME    = "LinkPlatform"
export const SITE_EMOJI   = "🔗"
export const SITE_TAGLINE = "Shorten, track, and manage your links. Create beautiful bio profiles."
export const SITE_FOOTER  = "© 2026 LinkPlatform. All rights reserved."
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || ""
export const shortUrl  = (code) => `${API_BASE_URL}/s/${code}`
export const landingUrl = (code) => `${API_BASE_URL}/l/${code}`
export const linkUrl = (link) => link.landing_page_enabled ? landingUrl(link.short_code) : shortUrl(link.short_code)
export const SOCIAL_PLATFORMS = ['Twitter','Facebook','Instagram','YouTube','TikTok','Twitch','Kick','Bluesky','Mastodon','LinkedIn','GitHub','Discord','Reddit','Snapchat','Pinterest','Threads','Spotify','SoundCloud','Custom']
export const TAB_TYPES = [
{ value:'links',   label:'Links',   icon:'🔗', desc:'URL links with titles' },
{ value:'social',  label:'Social',  icon:'📱', desc:'Social media cards' },
{ value:'contact', label:'Contact', icon:'📞', desc:'Email, phone, address' },
{ value:'text',    label:'Text',    icon:'📝', desc:'Text / bio block' },
{ value:'video',   label:'Video',   icon:'🎬', desc:'YouTube / Vimeo embeds' },
{ value:'gallery', label:'Gallery', icon:'🖼️', desc:'Image gallery' },
]
export const TAB_STYLES = [
{ value:'solid',       label:'Solid',       icon:'⬜' },
{ value:'glass',       label:'Glass',       icon:'🪟' },
{ value:'frost',       label:'Frost',       icon:'❄️' },
{ value:'transparent', label:'Transparent', icon:'◻️' },
]
export const HEADER_STYLES = [
{ value:'solid',       label:'Solid' },
{ value:'glass',       label:'Glass' },
{ value:'frost',       label:'Frost' },
{ value:'transparent', label:'Transparent' },
]
export const CONTACT_TYPES = [
{ value:'email',   label:'Email',   icon:'📧', prefix:'mailto:' },
{ value:'phone',   label:'Phone',   icon:'📞', prefix:'tel:' },
{ value:'address', label:'Address', icon:'📍', prefix:'' },
{ value:'website', label:'Website', icon:'🌐', prefix:'' },
{ value:'custom',  label:'Custom',  icon:'💬', prefix:'' },
]
export const LANDING_THEMES = [
{ value:'default', label:'Default' },
{ value:'light',   label:'Light' },
{ value:'dark',    label:'Dark' },
]
export const LINK_TYPES = [
  { value:'url',     label:'🔗 Link',            fieldLabel:'URL',           placeholder:'https://...',               prefix:'' },
  { value:'email',   label:'📧 Email',            fieldLabel:'Email Address', placeholder:'you@example.com',           prefix:'mailto:' },
  { value:'phone',   label:'📞 Phone',            fieldLabel:'Phone Number',  placeholder:'+1 555 123 4567',           prefix:'tel:' },
  { value:'address', label:'📍 Address / PO Box', fieldLabel:'Address',       placeholder:'PO Box 1234, City, ST ZIP', prefix:'' },
  { value:'embed',   label:'🎬 Video Embed',       fieldLabel:'Video URL',     placeholder:'https://youtube.com/...',   prefix:'' },
  { value:'image',   label:'🖼️ Image',             fieldLabel:'Image URL',     placeholder:'https://...',               prefix:'' },
]
export const SLUG_STYLES = [
  { value:'vertical-rotate', label:'Vertical (Rotated)',  icon:'↕️' },
  { value:'vertical-fixed',  label:'Vertical (Straight)', icon:'⬇️' },
  { value:'horizontal',      label:'Horizontal',          icon:'➡️' },
  { value:'hidden',          label:'Hidden',              icon:'🚫' },
]
export const HEADER_IMAGE_SIZES = [
  { value:'half',  label:'Half Banner',  icon:'🔲', desc:'Banner covers top half of header card (default)' },
  { value:'full',  label:'Full Banner',  icon:'⬛', desc:'Banner fills entire header card background' },
  { value:'cover', label:'Cover Banner', icon:'🖼️', desc:'Full bleed — image IS the header background' },
]
// 🎨 THEME PRESETS — 12 monthly themes extracted from Kara's page design
// Users pick one; no auto-rotation. May Flowers is the default.
export const THEME_PRESETS = [
  { id:'may-flowers',     month:4,  name:'🌺 May Flowers',        description:'DEFAULT — blooming pink & purple petals',    primary:'#e91e8c', secondary:'#9b59b6', accent:'#1abc9c', bg:'#100618', text:'#f8f9fa', muted:'#c070b0', fx:'petals'    },
  { id:'winter-frost',    month:0,  name:'❄️ Winter Frost',        description:'January — cool blues & icy whites',          primary:'#3498db', secondary:'#1abc9c', accent:'#9b59b6', bg:'#060d1c', text:'#ecf0f1', muted:'#7ba8cc', fx:'snow'      },
  { id:'valentines-love', month:1,  name:'💖 Valentine\'s Love',   description:'February — passionate reds & pinks',         primary:'#e74c3c', secondary:'#e84393', accent:'#fd79a8', bg:'#180608', text:'#fdf2f8', muted:'#c07898', fx:'hearts'    },
  { id:'st-patricks',     month:2,  name:'🍀 St. Patrick\'s Day',  description:'March — lucky greens & gold',                primary:'#2ecc71', secondary:'#f1c40f', accent:'#27ae60', bg:'#031008', text:'#ecf0f1', muted:'#6aba80', fx:'fireflies' },
  { id:'easter',          month:3,  name:'🐰 Easter',              description:'April — pastel purple & golden spring',      primary:'#9b59b6', secondary:'#e84393', accent:'#f1c40f', bg:'#130820', text:'#f8f9fa', muted:'#a880c8', fx:'bunnies'   },
  { id:'summer-pride',    month:5,  name:'🌈 Summer Pride',        description:'June — rainbow celebration of diversity',    primary:'#e74c3c', secondary:'#f39c12', accent:'#3498db', bg:'#180608', text:'#ffffff', muted:'#c09080', fx:'fireflies' },
  { id:'fourth-july',     month:6,  name:'🇺🇸 4th of July',        description:'July — red white & blue independence',       primary:'#e74c3c', secondary:'#3498db', accent:'#f1c40f', bg:'#060c18', text:'#ffffff', muted:'#8090b8', fx:'stars'     },
  { id:'summer-heat',     month:7,  name:'🌅 Summer Heat',         description:'August — warm oranges & sunset fire',        primary:'#e67e22', secondary:'#e74c3c', accent:'#f1c40f', bg:'#140a02', text:'#fdf2e9', muted:'#c08060', fx:'fireflies' },
  { id:'labor-day',       month:8,  name:'🔧 Labor Day',           description:'September — earthy amber & steel blue',      primary:'#d35400', secondary:'#3498db', accent:'#f1c40f', bg:'#0a1414', text:'#ecf0f1', muted:'#809898', fx:'leaves'    },
  { id:'halloween',       month:9,  name:'🎃 Halloween',           description:'October — spooky purple, gold & bats',       primary:'#9b59b6', secondary:'#f1c40f', accent:'#e74c3c', bg:'#0c0608', text:'#f8f9fa', muted:'#8860a8', fx:'bats'      },
  { id:'thanksgiving',    month:10, name:'🦃 Thanksgiving',        description:'November — warm harvest orange & brown',     primary:'#d35400', secondary:'#f39c12', accent:'#27ae60', bg:'#140c04', text:'#fdf2e9', muted:'#c08840', fx:'leaves'    },
  { id:'christmas',       month:11, name:'🎄 Christmas',           description:'December — festive red, green & snow',       primary:'#e74c3c', secondary:'#2ecc71', accent:'#f1c40f', bg:'#020802', text:'#ffffff', muted:'#88b888', fx:'snow'      },
  { id:'new-years',       month:-1, name:'🎉 New Year\'s',         description:'Holiday special — confetti celebration',     primary:'#3498db', secondary:'#9b59b6', accent:'#1abc9c', bg:'#060c20', text:'#ecf0f1', muted:'#7890c0', fx:'confetti'  },
  { id:'custom',          month:-1, name:'✏️ Custom Theme',        description:'Write your own CSS below',                   primary:'#e91e8c', secondary:'#9b59b6', accent:'#1abc9c', bg:'#100618', text:'#f8f9fa', muted:'#c070b0', fx:''          },
]
EOF

# ---------- frontend/src/useSiteConfig.js ----------
cat > frontend/src/useSiteConfig.js << 'EOF'
import { useState, useEffect } from 'react'
import { SITE_NAME, SITE_TAGLINE, SITE_FOOTER, SITE_EMOJI, API_BASE_URL } from './config'
import axios from 'axios'
let _cache = null
let _promise = null
export function useSiteConfig() {
const [config, setConfig] = useState(_cache || { site_name:SITE_NAME, site_tagline:SITE_TAGLINE, site_footer:SITE_FOOTER, site_emoji:SITE_EMOJI })
useEffect(() => {
if (_cache) { setConfig(_cache); return }
if (!_promise) {
_promise = axios.get(`${API_BASE_URL}/api/public/config`)
.then(res => { _cache = { site_name:SITE_NAME, site_tagline:SITE_TAGLINE, site_footer:SITE_FOOTER, site_emoji:SITE_EMOJI, ...res.data }; return _cache })
.catch(() => ({ site_name:SITE_NAME, site_tagline:SITE_TAGLINE, site_footer:SITE_FOOTER, site_emoji:SITE_EMOJI }))
}
_promise.then(cfg => setConfig(cfg))
}, [])
return config
}
EOF

# ---------- frontend/src/useNavItems.js ----------
cat > frontend/src/useNavItems.js << 'EOF'
import { useState, useEffect } from 'react'
import api from './api'
export function useNavItems() {
const [items, setItems] = useState([])
useEffect(() => {
api.get('/api/public/nav/').then(res => setItems(res.data)).catch(() => setItems([]))
}, [])
return { items }
}
EOF

# ---------- frontend/src/context/ThemeContext.jsx ----------
cat > frontend/src/context/ThemeContext.jsx << 'EOF'
import { createContext, useContext, useState, useEffect } from 'react'
const ThemeContext = createContext({ theme:'dark', toggle:()=>{} })
export function ThemeProvider({ children }) {
const [theme, setTheme] = useState(() => {
  const saved = localStorage.getItem('site-theme')
  return saved === 'light' || saved === 'dark' ? saved : 'dark'
})
useEffect(() => {
  document.documentElement.setAttribute('data-theme', theme)
  localStorage.setItem('site-theme', theme)
}, [theme])
const toggle = () => setTheme(current => current === 'dark' ? 'light' : 'dark')
return <ThemeContext.Provider value={{ theme, toggle }}>{children}</ThemeContext.Provider>
}
export const useTheme = () => useContext(ThemeContext)
EOF

# ---------- frontend/src/context/AuthContext.jsx ----------
cat > frontend/src/context/AuthContext.jsx << 'EOF'
import React, { createContext, useState, useContext, useEffect } from 'react'
import api from '../api'

const AuthContext = createContext()

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const [tempToken, setTempToken] = useState(null)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) {
      fetchUser()
    } else {
      setLoading(false)
    }
  }, [])

  const fetchUser = async () => {
    try {
      const res = await api.get('/api/users/me')
      setUser(res.data)
    } catch {
      logout()
    } finally {
      setLoading(false)
    }
  }

  const login = async (email, password) => {
    const formData = new FormData()
    formData.append('username', email)
    formData.append('password', password)
    const res = await api.post('/api/auth/login', formData)
    if (res.data.requires_2fa) {
      setTempToken(res.data.temp_token)
      return { requires2fa: true, tempToken: res.data.temp_token }
    } else {
      localStorage.setItem('token', res.data.access_token)
      localStorage.setItem('refresh', res.data.refresh_token)
      await fetchUser()
      return { success: true }
    }
  }

  const verify2FA = async (code) => {
    const res = await api.post('/api/auth/verify-2fa', { code, temp_token: tempToken })
    localStorage.setItem('token', res.data.access_token)
    localStorage.setItem('refresh', res.data.refresh_token)
    setTempToken(null)
    await fetchUser()
    return true
  }

  const logout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('refresh')
    setUser(null)
    setTempToken(null)
  }

  const value = {
    user,
    loading,
    tempToken,
    login,
    verify2FA,
    logout
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export const useAuth = () => useContext(AuthContext)
EOF

# ---------- frontend/src/api.js ----------
cat > frontend/src/api.js << 'EOF'
import axios from 'axios'
import { API_BASE_URL } from './config'

const api = axios.create({ baseURL: API_BASE_URL, timeout: 30000 })

api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('token')
  if (t) cfg.headers.Authorization = `Bearer ${t}`
  return cfg
})

api.interceptors.response.use(r => r, async e => {
  const originalRequest = e.config
  if (e.response?.status === 401 && !originalRequest._retry) {
    originalRequest._retry = true
    try {
      const rt = localStorage.getItem('refresh')
      if (!rt) throw new Error('No refresh token')
      const { data } = await axios.post(`${API_BASE_URL}/api/auth/refresh`, { refresh_token: rt })
      localStorage.setItem('token', data.access_token)
      localStorage.setItem('refresh', data.refresh_token)
      originalRequest.headers.Authorization = `Bearer ${data.access_token}`
      return axios(originalRequest)
    } catch (refreshError) {
      localStorage.clear()
      window.location.href = '/login'
    }
  }
  return Promise.reject(e)
})

export default api
EOF

# ---------- frontend/src/components/Navbar.jsx ----------
cat > frontend/src/components/Navbar.jsx << 'EOF'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { useState, useEffect, useCallback } from 'react'
import api from '../api'
import { useNavItems } from '../useNavItems'
import { useSiteConfig } from '../useSiteConfig'
import { useTheme } from '../context/ThemeContext'

function isExternalUrl(path) {
  return /^https?:\/\//i.test(path) || /^\/\//.test(path)
}

export default function Navbar() {
const navigate = useNavigate()
const location = useLocation()
const siteConfig = useSiteConfig()
const { theme, toggle: toggleTheme } = useTheme()
const { items } = useNavItems()
const [isAdmin, setIsAdmin] = useState(false)
const [isLoggedIn, setIsLoggedIn] = useState(false)
const [unreadCount, setUnreadCount] = useState(0)

const fetchUnread = useCallback(async () => {
if (!localStorage.getItem('token')) return
try { const res = await api.get('/api/messages/unread-count'); setUnreadCount(res.data.count) } catch {}
}, [])

useEffect(() => {
const token = localStorage.getItem('token')
if (token) {
try {
const payload = JSON.parse(atob(token.split('.')[1]))
setIsAdmin(payload.role === 'admin')
setIsLoggedIn(true)
fetchUnread()
const iv = setInterval(fetchUnread, 30000)
return () => clearInterval(iv)
} catch { setIsLoggedIn(false) }
}
}, [fetchUnread])

const active = p => location.pathname === p ? 'active' : ''
const handleLogout = () => { localStorage.clear(); navigate('/') }

const visibleItems = items.filter(item => {
if (!item.enabled) return false
if (item.auth_required && !isLoggedIn) return false
if (item.admin_only && !isAdmin) return false
return true
})

return (
<nav className="nav">
<Link to="/" className="nav-brand"><span>{siteConfig.site_emoji}</span> {siteConfig.site_name}</Link>
<div className="nav-links">
{visibleItems.map(item => {
  const external = isExternalUrl(item.path)
  return external ? (
    <a key={item.id} href={item.path} className="nav-link" target="_blank" rel="noopener noreferrer">
      {item.icon && <span>{item.icon}</span>} {item.label}
    </a>
  ) : (
    <Link key={item.id} to={item.path} className={`nav-link ${active(item.path)}`}>
      {item.icon && <span>{item.icon}</span>} {item.label}
    </Link>
  )
})}
{isLoggedIn && (
<div className="bell-wrap" onClick={() => navigate('/messages')} title={`${unreadCount} unread`}>
<span style={{fontSize:'1.15rem'}}>🔔</span>
{unreadCount > 0 && <span className="bell-badge">{unreadCount > 99 ? '99+' : unreadCount}</span>}
</div>
)}
<button onClick={toggleTheme} className="btn btn-outline" style={{padding:'.45rem .7rem',fontSize:'1rem'}}>
{theme === 'dark' ? '☀️' : '🌙'}
</button>
{isLoggedIn
? <button className="btn btn-outline" onClick={handleLogout}>Logout</button>
: <Link to="/login" className="btn">Login</Link>
}
</div>
</nav>
)
}
EOF

# ---------- frontend/src/components/Toast.jsx ----------
cat > frontend/src/components/Toast.jsx << 'EOF'
import { useEffect, useState } from 'react'
export default function Toast({ message, type='success', duration=3500, onClose }) {
const [vis, setVis] = useState(true)
useEffect(() => { const t = setTimeout(()=>{setVis(false);onClose?.()}, duration); return()=>clearTimeout(t) },[])
if(!vis) return null
return <div className={`toast ${type}`}>{type==='success'?'✅':'❌'} {message}</div>
}
EOF

# ---------- frontend/src/components/EmptyState.jsx ----------
cat > frontend/src/components/EmptyState.jsx << 'EOF'
import { Link } from 'react-router-dom'
export default function EmptyState({title,description,action,to,icon="🔗"}) {
return <div className="empty glass"><div className="empty-icon">{icon}</div><h3>{title}</h3><p style={{margin:'.5rem 0 1.5rem'}}>{description}</p>{action&&to&&<Link to={to} className="btn">{action}</Link>}</div>
}
EOF

# ---------- frontend/src/components/LinkCard.jsx ----------
cat > frontend/src/components/LinkCard.jsx << 'EOF'
import { useState } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { Link } from 'react-router-dom'
import { linkUrl } from '../config'
export default function LinkCard({link,onDelete}) {
const [qr,setQr] = useState(false)
const url = linkUrl(link)
const isLanding = link.landing_page_enabled
const copy = async () => { try{await navigator.clipboard.writeText(url);alert('✅ Copied!')}catch{} }
return (
<div className="card glass">
<div style={{display:'flex',alignItems:'center',justifyContent:'space-between',gap:'1rem',flexWrap:'wrap'}}>
<div style={{display:'flex',alignItems:'center',gap:'.5rem',flex:1,minWidth:0}}>
<span className={`url-badge ${isLanding?'landing':'short'}`}>{isLanding?'🛑 /l/':'⚡ /s/'}</span>
<span className="short-code">{link.short_code}</span>
<span>→</span>
<a href={link.original_url} target="_blank" rel="noreferrer" className="original-url">{link.original_url}</a>
</div>
<div className="actions">
<button className="btn btn-outline" onClick={()=>setQr(!qr)} title="QR Code">📱</button>
<button className="btn btn-outline" onClick={copy} title="Copy link">📋</button>
<Link to={`/analytics/${link.id}`} className="btn btn-outline" title="Analytics">📊</Link>
<Link to={`/edit/${link.id}`} className="btn btn-outline" title="Edit">✏️</Link>
<button className="btn btn-danger" onClick={()=>onDelete(link.id)} title="Delete">🗑️</button>
</div>
</div>
<div style={{display:'flex',alignItems:'center',gap:'1rem',flexWrap:'wrap'}}>
<div className="stats">
<span>👁️ {link.clicks} clicks</span>
<span>📅 {new Date(link.created_at).toLocaleDateString()}</span>
{!link.is_active&&<span style={{color:'var(--danger)'}}>⏸ Inactive</span>}
</div>
<code style={{fontSize:'.72rem',color:'var(--text-muted)',fontFamily:'monospace'}}>{url}</code>
</div>
{qr&&<div style={{paddingTop:'1rem',borderTop:'1px dashed var(--border)',display:'flex',alignItems:'center',gap:'1rem'}}><QRCodeSVG value={url} size={72}/><div><p style={{fontSize:'.75rem',color:'var(--text-muted)',marginBottom:'.25rem'}}>Scan to {isLanding?'view landing page':'visit link'}</p><code style={{fontSize:'.72rem',wordBreak:'break-all'}}>{url}</code></div></div>}
</div>
)
}
EOF

# ---------- frontend/src/pages/Home.jsx ----------
cat > frontend/src/pages/Home.jsx << 'EOF'
import { Link } from 'react-router-dom'
import Navbar from '../components/Navbar'
import { useSiteConfig } from '../useSiteConfig'
export default function Home() {
const sc = useSiteConfig()
return (
<div><Navbar/>
<div style={{maxWidth:800,margin:'4rem auto',padding:'2rem',textAlign:'center'}}>
<div className="glass" style={{padding:'3rem'}}>
<h1 style={{fontSize:'3rem',marginBottom:'1rem'}}>{sc.site_emoji} {sc.site_name}</h1>
<p style={{fontSize:'1.2rem',color:'var(--text-muted)',marginBottom:'2rem'}}>{sc.site_tagline}</p>
<div style={{display:'flex',gap:'1rem',justifyContent:'center',flexWrap:'wrap'}}>
<Link to="/signup" className="btn">Get Started</Link>
<Link to="/login" className="btn btn-outline">Login</Link>
</div>
{sc.site_footer&&<p style={{marginTop:'2rem',fontSize:'.85rem',color:'var(--text-muted)'}}>{sc.site_footer}</p>}
</div>
</div>
</div>
)
}
EOF

# ---------- frontend/src/pages/Login.jsx ----------
cat > frontend/src/pages/Login.jsx << 'EOF'
import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import Navbar from '../components/Navbar'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [show2FA, setShow2FA] = useState(false)
  const { login, verify2FA } = useAuth()
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const result = await login(email, password)
      if (result.requires2fa) {
        setShow2FA(true)
      } else {
        navigate('/dashboard')
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  const handleVerify2FA = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      await verify2FA(code)
      navigate('/dashboard')
    } catch (err) {
      setError(err.response?.data?.detail || 'Verification failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <Navbar />
      <div style={{ maxWidth: 400, margin: '4rem auto', padding: '2rem' }}>
        <div className="glass" style={{ padding: '2rem' }}>
          <h2 style={{ marginBottom: '1.5rem', textAlign: 'center' }}>
            {show2FA ? '🔐 Two‑Factor Authentication' : '🔐 Login'}
          </h2>
          {error && <p style={{ color: 'red', textAlign: 'center' }}>{error}</p>}
          {show2FA ? (
            <form onSubmit={handleVerify2FA} style={{ display: 'grid', gap: '1rem' }}>
              <input
                className="input"
                type="text"
                placeholder="Enter 6‑digit code or backup code"
                value={code}
                onChange={e => setCode(e.target.value)}
                required
                disabled={loading}
              />
              <button type="submit" className="btn" disabled={loading}>
                {loading ? 'Verifying...' : 'Verify'}
              </button>
            </form>
          ) : (
            <form onSubmit={handleSubmit} style={{ display: 'grid', gap: '1rem' }}>
              <input
                className="input"
                type="email"
                placeholder="Email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                required
                disabled={loading}
              />
              <input
                className="input"
                type="password"
                placeholder="Password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                disabled={loading}
              />
              <button type="submit" className="btn" disabled={loading}>
                {loading ? 'Logging in...' : 'Login'}
              </button>
              <div style={{ textAlign: 'center', marginTop: '0.5rem' }}>
                <Link to="/forgot-password" style={{ fontSize: '0.9rem', color: 'var(--primary)' }}>
                  Forgot password?
                </Link>
              </div>
            </form>
          )}
          <p style={{ marginTop: '1rem', textAlign: 'center' }}>
            No account? <Link to="/signup">Sign up</Link>
          </p>
        </div>
      </div>
    </div>
  )
}
EOF

# ---------- frontend/src/pages/Signup.jsx ----------
cat > frontend/src/pages/Signup.jsx << 'EOF'
import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'

export default function Signup() {
const [e,setE]=useState(''); const [p,setP]=useState(''); const [l,setL]=useState(false); const nav=useNavigate()
const sub=async(ev)=>{ev.preventDefault();setL(true);try{const email=e.trim().toLowerCase();await api.post('/api/auth/register',{email,password:p});const fd=new FormData();fd.append('username',email);fd.append('password',p);const{data}=await api.post('/api/auth/login',fd);localStorage.setItem('token',data.access_token);localStorage.setItem('refresh',data.refresh_token);nav('/dashboard')}catch(err){alert('Signup failed: '+(err.response?.data?.detail||err.message))}finally{setL(false)}}
return <div><Navbar/><div style={{maxWidth:400,margin:'4rem auto',padding:'2rem'}}><div className="glass" style={{padding:'2rem'}}><h2 style={{marginBottom:'1.5rem',textAlign:'center'}}>📝 Sign Up</h2><form onSubmit={sub} style={{display:'grid',gap:'1rem'}}><input className="input" type="email" placeholder="Email" value={e} onChange={ev=>setE(ev.target.value)} required disabled={l}/><input className="input" type="password" placeholder="Password" value={p} onChange={ev=>setP(ev.target.value)} required disabled={l}/><button type="submit" className="btn" disabled={l}>{l?'Creating...':'Sign Up'}</button></form><p style={{marginTop:'1rem',textAlign:'center'}}>Have an account? <Link to="/login">Login</Link></p></div></div></div>
}
EOF

# ---------- frontend/src/pages/ForgotPassword.jsx ----------
cat > frontend/src/pages/ForgotPassword.jsx << 'EOF'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

export default function ForgotPassword() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [toast, setToast] = useState(null)
  const [submitted, setSubmitted] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      await api.post('/api/auth/forgot-password', { email })
      setSubmitted(true)
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Request failed', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  if (submitted) {
    return (
      <div>
        <Navbar />
        <div style={{ maxWidth: 400, margin: '4rem auto', padding: '2rem' }}>
          <div className="glass" style={{ padding: '2rem', textAlign: 'center' }}>
            <h2 style={{ marginBottom: '1rem' }}>📧 Check your email</h2>
            <p>If that email exists, we've sent a password reset link.</p>
            <Link to="/login" className="btn btn-outline" style={{ marginTop: '1rem' }}>Back to Login</Link>
          </div>
        </div>
        {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
      </div>
    )
  }

  return (
    <div>
      <Navbar />
      <div style={{ maxWidth: 400, margin: '4rem auto', padding: '2rem' }}>
        <div className="glass" style={{ padding: '2rem' }}>
          <h2 style={{ marginBottom: '1.5rem', textAlign: 'center' }}>🔐 Reset Password</h2>
          <p style={{ textAlign: 'center', marginBottom: '1.5rem', color: 'var(--text-muted)' }}>
            Enter your email address and we'll send you a link to reset your password.
          </p>
          <form onSubmit={handleSubmit} style={{ display: 'grid', gap: '1rem' }}>
            <input
              className="input"
              type="email"
              placeholder="Your email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
              disabled={loading}
            />
            <button type="submit" className="btn" disabled={loading}>
              {loading ? 'Sending...' : 'Send reset link'}
            </button>
          </form>
          <p style={{ marginTop: '1rem', textAlign: 'center' }}>
            <Link to="/login">← Back to login</Link>
          </p>
        </div>
      </div>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
EOF

# ---------- frontend/src/pages/ResetPassword.jsx ----------
cat > frontend/src/pages/ResetPassword.jsx << 'EOF'
import { useState } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

export default function ResetPassword() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const navigate = useNavigate()
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [loading, setLoading] = useState(false)
  const [toast, setToast] = useState(null)
  const [success, setSuccess] = useState(false)

  if (!token) {
    return (
      <div>
        <Navbar />
        <div style={{ maxWidth: 400, margin: '4rem auto', padding: '2rem' }}>
          <div className="glass" style={{ padding: '2rem', textAlign: 'center' }}>
            <h2>❌ Invalid link</h2>
            <p>The password reset link is missing or invalid.</p>
            <Link to="/forgot-password" className="btn btn-outline">Request new link</Link>
          </div>
        </div>
      </div>
    )
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (password !== confirm) {
      setToast({ message: 'Passwords do not match', type: 'error' })
      return
    }
    setLoading(true)
    try {
      await api.post('/api/auth/reset-password', { token, new_password: password })
      setSuccess(true)
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Reset failed', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  if (success) {
    return (
      <div>
        <Navbar />
        <div style={{ maxWidth: 400, margin: '4rem auto', padding: '2rem' }}>
          <div className="glass" style={{ padding: '2rem', textAlign: 'center' }}>
            <h2 style={{ marginBottom: '1rem' }}>✅ Password updated</h2>
            <p>You can now log in with your new password.</p>
            <Link to="/login" className="btn" style={{ marginTop: '1rem' }}>Go to Login</Link>
          </div>
        </div>
        {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
      </div>
    )
  }

  return (
    <div>
      <Navbar />
      <div style={{ maxWidth: 400, margin: '4rem auto', padding: '2rem' }}>
        <div className="glass" style={{ padding: '2rem' }}>
          <h2 style={{ marginBottom: '1.5rem', textAlign: 'center' }}>🔐 Set New Password</h2>
          <form onSubmit={handleSubmit} style={{ display: 'grid', gap: '1rem' }}>
            <input
              className="input"
              type="password"
              placeholder="New password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              disabled={loading}
              minLength={6}
            />
            <input
              className="input"
              type="password"
              placeholder="Confirm new password"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
              required
              disabled={loading}
              minLength={6}
            />
            <button type="submit" className="btn" disabled={loading}>
              {loading ? 'Updating...' : 'Update password'}
            </button>
          </form>
        </div>
      </div>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
EOF

# ---------- frontend/src/pages/Dashboard.jsx ----------
cat > frontend/src/pages/Dashboard.jsx << 'EOF'
import {useEffect,useState,useCallback} from 'react'; import {Link} from 'react-router-dom'; import api from '../api'; import Navbar from '../components/Navbar'; import EmptyState from '../components/EmptyState'; import LinkCard from '../components/LinkCard'; import Toast from '../components/Toast'
export default function Dashboard() {
const [links,setLinks]=useState([]); const [loading,setLoading]=useState(true); const [toast,setToast]=useState(null)
const fetchLinks=useCallback(async()=>{try{setLoading(true);const{data}=await api.get('/api/links');setLinks(data)}catch{setToast({message:'Failed to load links',type:'error'})}finally{setLoading(false)}},[])
useEffect(()=>{fetchLinks()},[fetchLinks])
const del=async(id)=>{if(!confirm('Delete?'))return;try{await api.delete(`/api/links/${id}`);setLinks(links.filter(l=>l.id!==id));setToast({message:'Deleted',type:'success'})}catch{setToast({message:'Delete failed',type:'error'})}}
if(loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>
return <div><Navbar/><main style={{padding:'2rem',maxWidth:1000,margin:'0 auto'}}><div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'2rem',flexWrap:'wrap',gap:'1rem'}}><h1>My Links</h1><Link to="/create" className="btn">✨ Create Link</Link></div>{links.length===0?<EmptyState title="No links yet" description="Create your first short link." action="Create Link" to="/create" icon="🚀"/>:<div style={{display:'grid',gap:'1rem'}}>{links.map(l=><LinkCard key={l.id} link={l} onDelete={del}/>)}</div>}</main>{toast&&<Toast message={toast.message} type={toast.type} onClose={()=>setToast(null)}/>}</div>
}
EOF

# ---------- frontend/src/pages/Create.jsx ----------
cat > frontend/src/pages/Create.jsx << 'EOF'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'
import { LANDING_THEMES, API_BASE_URL } from '../config'
export default function Create() {
const [url,setUrl]=useState(''); const [code,setCode]=useState(''); const [title,setTitle]=useState('')
const [landing,setLanding]=useState(false); const [landingTitle,setLandingTitle]=useState('')
const [landingBody,setLandingBody]=useState(''); const [landingImage,setLandingImage]=useState('')
const [landingTheme,setLandingTheme]=useState('default'); const [loading,setLoading]=useState(false)
const [toast,setToast]=useState(null); const nav=useNavigate()
const prefix = landing ? '/l/' : '/s/'
const previewUrl = code ? `${API_BASE_URL}${prefix}${code}` : null
const handleImageUpload=async(e)=>{const file=e.target.files?.[0];if(!file)return;const fd=new FormData();fd.append('file',file);try{const res=await api.post('/api/profile/upload',fd,{headers:{'Content-Type':'multipart/form-data'}});setLandingImage(res.data.url)}catch{setToast({message:'Upload failed',type:'error'})}}
const sub=async(e)=>{e.preventDefault();setLoading(true);try{await api.post('/api/links',{original_url:url,short_code:code||undefined,title:title||undefined,landing_page_enabled:landing,landing_page_title:landingTitle||undefined,landing_page_body:landingBody||undefined,landing_page_image:landingImage||undefined,landing_page_theme:landingTheme});setToast({message:'Link created! 🎉',type:'success'});setTimeout(()=>nav('/dashboard'),1200)}catch(err){setToast({message:err.response?.data?.detail||'Failed',type:'error'})}finally{setLoading(false)}}
return (<div><Navbar/><main style={{padding:'2rem',maxWidth:600,margin:'0 auto'}}><div className="glass" style={{padding:'2rem'}}><h2 style={{marginBottom:'1.5rem'}}>✨ Create Short Link</h2><form onSubmit={sub} style={{display:'grid',gap:'1rem'}}><div><label style={{display:'block',marginBottom:'.5rem',fontWeight:500}}>Destination URL *</label><input className="input" type="url" placeholder="https://example.com" value={url} onChange={e=>setUrl(e.target.value)} required/></div><div><label style={{display:'block',marginBottom:'.5rem',fontWeight:500}}>Custom Code (optional)</label><div style={{display:'flex',gap:'.5rem',alignItems:'center'}}><span style={{background:'var(--surface2)',padding:'.75rem',borderRadius:'var(--radius)',fontSize:'.8rem',fontFamily:'monospace',whiteSpace:'nowrap',color:'var(--text-muted)'}}>{prefix}</span><input className="input" type="text" placeholder="my-link" value={code} onChange={e=>setCode(e.target.value)} style={{flex:1}}/></div>{previewUrl&&<p style={{fontSize:'.75rem',color:'var(--primary)',marginTop:'.35rem',fontFamily:'monospace'}}>{previewUrl}</p>}</div><div><label style={{display:'block',marginBottom:'.5rem',fontWeight:500}}>Title (optional)</label><input className="input" type="text" placeholder="My awesome link" value={title} onChange={e=>setTitle(e.target.value)}/></div><label style={{display:'flex',alignItems:'center',gap:'.5rem',cursor:'pointer',padding:'.75rem',background:'var(--surface2)',borderRadius:'var(--radius)'}}><input type="checkbox" checked={landing} onChange={e=>setLanding(e.target.checked)}/><div><div style={{fontWeight:500}}>Enable landing page</div><div style={{fontSize:'.75rem',color:'var(--text-muted)'}}>Shows preview at <code>/l/</code> before redirecting</div></div></label>{landing&&(<div style={{padding:'1rem',background:'var(--surface2)',borderRadius:'.5rem',display:'grid',gap:'1rem'}}><h3 style={{fontSize:'1rem'}}>🛑 Landing Page</h3><input className="input" type="text" placeholder="Landing page title" value={landingTitle} onChange={e=>setLandingTitle(e.target.value)}/><textarea className="input" rows="3" placeholder="Optional message..." value={landingBody} onChange={e=>setLandingBody(e.target.value)}/><div>{landingImage&&<img src={landingImage} alt="" style={{maxWidth:'100%',maxHeight:'150px',marginBottom:'.5rem',borderRadius:'.5rem'}}/>}<label className="btn btn-outline" style={{cursor:'pointer'}}>📁 Upload Image<input type="file" accept="image/*" style={{display:'none'}} onChange={handleImageUpload}/></label>{landingImage&&<button type="button" className="btn btn-outline" onClick={()=>setLandingImage('')} style={{marginLeft:'.5rem'}}>✕ Remove</button>}</div><select className="input" value={landingTheme} onChange={e=>setLandingTheme(e.target.value)}>{LANDING_THEMES.map(t=><option key={t.value} value={t.value}>{t.label}</option>)}</select></div>)}<button type="submit" className="btn" disabled={loading}>{loading?'Creating...':'🚀 Create'}</button></form></div></main>{toast&&<Toast message={toast.message} type={toast.type} onClose={()=>setToast(null)}/>}</div>)
}
EOF

# ---------- frontend/src/pages/EditLink.jsx ----------
cat > frontend/src/pages/EditLink.jsx << 'EOF'
import { useState, useEffect } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'
import { LANDING_THEMES, API_BASE_URL } from '../config'
export default function EditLink() {
const { id } = useParams(); const nav = useNavigate()
const [url,setUrl]=useState(''); const [code,setCode]=useState(''); const [title,setTitle]=useState('')
const [active,setActive]=useState(true); const [landing,setLanding]=useState(false)
const [landingTitle,setLandingTitle]=useState(''); const [landingBody,setLandingBody]=useState('')
const [landingImage,setLandingImage]=useState(''); const [landingTheme,setLandingTheme]=useState('default')
const [loading,setLoading]=useState(true); const [saving,setSaving]=useState(false); const [toast,setToast]=useState(null)
useEffect(()=>{api.get(`/api/links/${id}`).then(r=>{setUrl(r.data.original_url);setCode(r.data.short_code);setTitle(r.data.title||'');setActive(r.data.is_active);setLanding(r.data.landing_page_enabled||false);setLandingTitle(r.data.landing_page_title||'');setLandingBody(r.data.landing_page_body||'');setLandingImage(r.data.landing_page_image||'');setLandingTheme(r.data.landing_page_theme||'default');setLoading(false)}).catch(()=>{setToast({message:'Failed to load',type:'error'});setTimeout(()=>nav('/dashboard'),2000)})},[id,nav])
const handleImageUpload=async(e)=>{const file=e.target.files?.[0];if(!file)return;const fd=new FormData();fd.append('file',file);try{const res=await api.post('/api/profile/upload',fd,{headers:{'Content-Type':'multipart/form-data'}});setLandingImage(res.data.url)}catch{setToast({message:'Upload failed',type:'error'})}}
const sub=async(e)=>{e.preventDefault();setSaving(true);try{await api.put(`/api/links/${id}`,{original_url:url,short_code:code,title:title||undefined,is_active:active,landing_page_enabled:landing,landing_page_title:landingTitle||undefined,landing_page_body:landingBody||undefined,landing_page_image:landingImage||undefined,landing_page_theme:landingTheme});setToast({message:'Updated!',type:'success'});setTimeout(()=>nav('/dashboard'),1200)}catch(err){setToast({message:err.response?.data?.detail||'Failed',type:'error'})}finally{setSaving(false)}}
const prefix = landing ? '/l/' : '/s/'
const previewUrl = code ? `${API_BASE_URL}${prefix}${code}` : null
if(loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>
return (<div><Navbar/><main style={{padding:'2rem',maxWidth:600,margin:'0 auto'}}><div className="glass" style={{padding:'2rem'}}><h2 style={{marginBottom:'1.5rem'}}>✏️ Edit Link</h2><form onSubmit={sub} style={{display:'grid',gap:'1rem'}}><input className="input" type="url" value={url} onChange={e=>setUrl(e.target.value)} required placeholder="Destination URL"/><div><label style={{display:'block',marginBottom:'.5rem',fontWeight:500}}>Short Code</label><div style={{display:'flex',gap:'.5rem',alignItems:'center'}}><span style={{background:'var(--surface2)',padding:'.75rem',borderRadius:'var(--radius)',fontSize:'.8rem',fontFamily:'monospace',whiteSpace:'nowrap',color:'var(--text-muted)'}}>{prefix}</span><input className="input" type="text" value={code} onChange={e=>setCode(e.target.value)} required style={{flex:1}}/></div>{previewUrl&&<p style={{fontSize:'.75rem',color:'var(--primary)',marginTop:'.35rem',fontFamily:'monospace'}}>{previewUrl}</p>}</div><input className="input" type="text" value={title} onChange={e=>setTitle(e.target.value)} placeholder="Title"/><label style={{display:'flex',alignItems:'center',gap:'.5rem',cursor:'pointer'}}><input type="checkbox" checked={active} onChange={e=>setActive(e.target.checked)}/> Active</label><label style={{display:'flex',alignItems:'center',gap:'.5rem',cursor:'pointer',padding:'.75rem',background:'var(--surface2)',borderRadius:'var(--radius)'}}><input type="checkbox" checked={landing} onChange={e=>setLanding(e.target.checked)}/> Enable landing page (<code>/l/</code> prefix)</label>{landing&&(<div style={{padding:'1rem',background:'var(--surface2)',borderRadius:'.5rem',display:'grid',gap:'1rem'}}><h3 style={{fontSize:'1rem'}}>🛑 Landing Page</h3><input className="input" type="text" value={landingTitle} onChange={e=>setLandingTitle(e.target.value)} placeholder="Landing page title"/><textarea className="input" rows="3" value={landingBody} onChange={e=>setLandingBody(e.target.value)} placeholder="Body text"/><div>{landingImage&&<img src={landingImage} alt="" style={{maxWidth:'100%',maxHeight:'120px',marginBottom:'.5rem',borderRadius:'.5rem'}}/>}<label className="btn btn-outline" style={{cursor:'pointer'}}>📁 Upload Image<input type="file" accept="image/*" style={{display:'none'}} onChange={handleImageUpload}/></label>{landingImage&&<button type="button" className="btn btn-outline" onClick={()=>setLandingImage('')} style={{marginLeft:'.5rem'}}>✕</button>}</div><select className="input" value={landingTheme} onChange={e=>setLandingTheme(e.target.value)}>{LANDING_THEMES.map(t=><option key={t.value} value={t.value}>{t.label}</option>)}</select></div>)}<button type="submit" className="btn" disabled={saving}>{saving?'Saving...':'💾 Save'}</button></form></div></main>{toast&&<Toast message={toast.message} type={toast.type} onClose={()=>setToast(null)}/>}</div>)
}
EOF

# ---------- frontend/src/pages/MyAccount.jsx ----------
cat > frontend/src/pages/MyAccount.jsx << 'EOF'
import { useState, useEffect } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

export default function MyAccount() {
  const [email, setEmail] = useState('')
  const [pw, setPw] = useState('')
  const [acceptMessages, setAcceptMessages] = useState(true)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [toast, setToast] = useState(null)

  useEffect(() => {
    api.get('/api/profile/me')
      .then(r => {
        setEmail(r.data.email || '')
        setAcceptMessages(r.data.accept_messages !== false)
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  const sub = async (e) => {
    e.preventDefault()
    setSaving(true)
    try {
      await api.put('/api/profile/me', {
        email: email || undefined,
        password: pw || undefined,
        accept_messages: acceptMessages
      })
      setToast({ message: 'Saved', type: 'success' })
      setPw('')
      const res = await api.get('/api/profile/me')
      const newEmail = res.data.email
      setEmail(newEmail)
      if (newEmail !== email && email !== '') {
        setToast({ message: 'Email changed – logging out...', type: 'success' })
        setTimeout(() => { localStorage.clear(); window.location.href = '/login' }, 2000)
      }
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Failed', type: 'error' })
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>

  return (
    <div>
      <Navbar />
      <main style={{ maxWidth: 500, margin: '0 auto', padding: '2rem' }}>
        <div className="glass" style={{ padding: '2rem' }}>
          <h2 style={{ marginBottom: '1.5rem' }}>👤 My Account</h2>
          <form onSubmit={sub} style={{ display: 'grid', gap: '1rem' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '.5rem', fontWeight: 500 }}>Email</label>
              <input className="input" type="email" value={email} onChange={e => setEmail(e.target.value)} required />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: '.5rem', fontWeight: 500 }}>New Password</label>
              <input className="input" type="password" placeholder="Leave blank to keep current" value={pw} onChange={e => setPw(e.target.value)} />
            </div>
            <div>
              <label style={{ display: 'flex', alignItems: 'center', gap: '.5rem', cursor: 'pointer', padding: '.5rem', background: 'var(--surface2)', borderRadius: 'var(--radius)' }}>
                <input
                  type="checkbox"
                  checked={acceptMessages}
                  onChange={e => setAcceptMessages(e.target.checked)}
                />
                <span>Accept messages from other users</span>
              </label>
              <p style={{ fontSize: '.8rem', color: 'var(--text-muted)', marginTop: '.25rem' }}>
                If unchecked, only admins can send you messages.
              </p>
            </div>
            <button type="submit" className="btn" disabled={saving}>{saving ? 'Saving...' : 'Save'}</button>
          </form>
        </div>
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
EOF

# ---------- frontend/src/pages/BioProfile.jsx ----------
cat > frontend/src/pages/BioProfile.jsx << 'JSXEOF'
import { useState, useEffect } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'
import { SOCIAL_PLATFORMS, TAB_TYPES, TAB_STYLES, HEADER_STYLES, THEME_PRESETS, LINK_TYPES, SLUG_STYLES, HEADER_IMAGE_SIZES, API_BASE_URL } from '../config'

// Avatar shape — maps to profile_photo_style (circle/rounded/square)
const AVATAR_SHAPES = [
  { value: 'circle',  label: 'Circle',          icon: '⭕' },
  { value: 'rounded', label: 'Rounded Square',   icon: '🟦' },
  { value: 'square',  label: 'Square',           icon: '⬜' },
]

// Avatar effect — stored in avatar_style (none/pulse/glow/rainbow)
const AVATAR_EFFECTS = [
  { value: 'none',    label: 'None',             icon: '✖️' },
  { value: 'pulse',   label: 'Pulse Ring',       icon: '🔵' },
  { value: 'glow',    label: 'Glow',             icon: '✨' },
  { value: 'rainbow', label: 'Rainbow Border',   icon: '🌈' },
]

const LAYOUT_OPTIONS = [
  { value: 'left',   label: 'Left',   icon: '⬅️' },
  { value: 'center', label: 'Center', icon: '↔️' },
  { value: 'right',  label: 'Right',  icon: '➡️' },
]

export default function BioProfile() {
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [toast, setToast] = useState(null)
  const [profile, setProfile] = useState({
    custom_slug: '', bio_description: '', header_text: '', sub_header_text: '',
    theme_color: '#a78bfa', selected_theme_id: 'may-flowers', profile_photo_url: '', header_image_url: '',
    page_bg_url: '', header_style: 'solid', theme_html: '',
    profile_redirect_url: '', is_redirect_enabled: false,
    show_social_icons: true, daily_status: '',
    profile_layout: 'center', profile_photo_style: 'circle',
    slug_style: 'vertical-rotate', header_image_size: 'half', header_bg_opacity: '0.45',
    is_verified: false, is_sensitive: false, age_restriction: false,
    cookie_popup: false, show_share_icon: true, remove_branding: false,
    profile_password: '', display_avatar: true, avatar_style: 'none',
    can_use_custom_domain: false
  })
  const [socialIcons, setSocialIcons] = useState([])
  const [tabs, setTabs] = useState([])
  const [activeTab, setActiveTab] = useState('basic')
  const [editingIcon, setEditingIcon] = useState(null)
  const [iconForm, setIconForm] = useState({ platform: '', url: '', icon_url: '' })
  const [editingTab, setEditingTab] = useState(null)
  const [tabForm, setTabForm] = useState({ title: '', slug: '', tab_type: 'links', tab_style: 'solid', bg_url: '', text_content: '', tab_bg_opacity: '0.85', tab_text_color: '' })
  const [editingLink, setEditingLink] = useState(null)
  const [linkForm, setLinkForm] = useState({ title: '', description: '', url: '', thumbnail_url: '', link_type: 'url' })
  const [linkTabId, setLinkTabId] = useState(null)

  const [userDomain, setUserDomain] = useState(null)

  useEffect(() => {
    Promise.all([
      api.get('/api/profile/me/bio'),
      api.get('/api/profile/me/bio/social-icons'),
      api.get('/api/profile/me/bio/tabs')
    ]).then(([p, i, t]) => {
      const pdata = p.data
      // Derive which preset is active based on theme_color match (THEME_PRESETS already imported above)
      const matched = THEME_PRESETS.find(t => t.id !== 'custom' && pdata.theme_color === t.primary)
      setProfile({ ...profile, ...pdata, selected_theme_id: matched ? matched.id : (pdata.selected_theme_id || 'custom') })
      setSocialIcons(i.data)
      setTabs(t.data)
      // Load custom domain if user has access
      if (pdata.can_use_custom_domain) {
        api.get('/api/domains/my').then(dr => {
          if (dr.data && dr.data.domain) setUserDomain(dr.data)
        }).catch(() => {})
      }
    }).catch(() => setToast({ message: 'Failed to load profile', type: 'error' }))
    .finally(() => setLoading(false))
  }, [])

  const uploadFile = async (file) => {
    if (!file) return null
    const fd = new FormData()
    fd.append('file', file)
    try {
      const res = await api.post('/api/profile/upload', fd, { headers: { 'Content-Type': 'multipart/form-data' } })
      return res.data.url
    } catch {
      setToast({ message: 'Upload failed', type: 'error' })
      return null
    }
  }

  const UploadBtn = ({ onUpload, label = '📁 Upload' }) => (
    <label className="btn btn-outline" style={{ cursor: 'pointer', whiteSpace: 'nowrap', flexShrink: 0 }}>
      {label}
      <input type="file" accept="image/*" style={{ display: 'none' }} onChange={async (e) => {
        const url = await uploadFile(e.target.files?.[0])
        if (url) onUpload(url)
      }} />
    </label>
  )

  const ImageField = ({ label, value, field, helpText }) => (
    <div>
      <label style={{ display: 'block', marginBottom: '.35rem', fontWeight: 500 }}>{label}</label>
      {helpText && <p style={{ fontSize: '.75rem', color: 'var(--text-muted)', marginBottom: '.4rem' }}>{helpText}</p>}
      <div style={{ display: 'flex', gap: '.5rem' }}>
        <input className="input" value={value || ''} onChange={e => setProfile({ ...profile, [field]: e.target.value })} placeholder="https://..." />
        <UploadBtn onUpload={url => setProfile({ ...profile, [field]: url })} />
        {value && <button type="button" className="btn btn-outline" title="Clear" onClick={() => setProfile({ ...profile, [field]: '' })}>✕</button>}
      </div>
      {value && <img src={value} alt="" style={{ marginTop: '.5rem', maxHeight: 80, borderRadius: '.5rem', border: '1px solid var(--border)' }} />}
    </div>
  )

  const saveProfile = async (e) => {
    e?.preventDefault()
    setSaving(true)
    try {
      await api.put('/api/profile/me/bio', profile)
      setToast({ message: 'Profile saved ✅', type: 'success' })
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Save failed', type: 'error' })
    } finally {
      setSaving(false)
    }
  }

  const handleIconSubmit = async (e) => {
    e.preventDefault()
    try {
      if (editingIcon) {
        await api.put(`/api/profile/me/bio/social-icons/${editingIcon.id}`, { url: iconForm.url, icon_url: iconForm.icon_url })
      } else {
        await api.post('/api/profile/me/bio/social-icons', iconForm)
      }
      const res = await api.get('/api/profile/me/bio/social-icons')
      setSocialIcons(res.data)
      setToast({ message: editingIcon ? 'Icon updated' : 'Icon added', type: 'success' })
      setEditingIcon(null)
      setIconForm({ platform: '', url: '', icon_url: '' })
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Failed', type: 'error' })
    }
  }

  const deleteIcon = async (id) => {
    if (!confirm('Delete?')) return
    await api.delete(`/api/profile/me/bio/social-icons/${id}`)
    setSocialIcons(icons => icons.filter(i => i.id !== id))
    setToast({ message: 'Deleted', type: 'success' })
  }

  const handleTabSubmit = async (e) => {
    e.preventDefault()
    try {
      if (editingTab) {
        await api.put(`/api/profile/me/bio/tabs/${editingTab.id}`, tabForm)
      } else {
        await api.post('/api/profile/me/bio/tabs', tabForm)
      }
      const res = await api.get('/api/profile/me/bio/tabs')
      setTabs(res.data)
      setToast({ message: editingTab ? 'Tab updated' : 'Tab created', type: 'success' })
      setEditingTab(null)
      setTabForm({ title: '', slug: '', tab_type: 'links', tab_style: 'solid', bg_url: '', text_content: '', tab_bg_opacity: '0.85', tab_text_color: '' })
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Failed', type: 'error' })
    }
  }

  const deleteTab = async (id) => {
    if (!confirm('Delete tab and all its links?')) return
    await api.delete(`/api/profile/me/bio/tabs/${id}`)
    setTabs(tabs.filter(t => t.id !== id))
    setToast({ message: 'Tab deleted', type: 'success' })
  }

  const handleLinkSubmit = async (e) => {
    e.preventDefault()
    if (!linkTabId) return
    try {
      if (editingLink) {
        await api.put(`/api/profile/me/bio/tabs/${linkTabId}/links/${editingLink.id}`, linkForm)
      } else {
        await api.post(`/api/profile/me/bio/tabs/${linkTabId}/links`, linkForm)
      }
      const res = await api.get('/api/profile/me/bio/tabs')
      setTabs(res.data)
      setToast({ message: editingLink ? 'Link updated' : 'Link added', type: 'success' })
      setEditingLink(null)
      setLinkForm({ title: '', description: '', url: '', thumbnail_url: '', link_type: 'url' })
      setLinkTabId(null)
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Failed', type: 'error' })
    }
  }

  const deleteLink = async (tabId, linkId) => {
    if (!confirm('Delete link?')) return
    await api.delete(`/api/profile/me/bio/tabs/${tabId}/links/${linkId}`)
    const res = await api.get('/api/profile/me/bio/tabs')
    setTabs(res.data)
    setToast({ message: 'Link deleted', type: 'success' })
  }

  if (loading) return <div><Navbar /><div style={{ padding: '2rem' }}>Loading…</div></div>

  return (
    <div>
      <Navbar />
      <main style={{ maxWidth: 1000, margin: '0 auto', padding: '2rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
          <h1>🎨 Bio Profile Editor</h1>
          {profile.custom_slug ? (
            <a href={`${API_BASE_URL}/@${profile.custom_slug}`} target="_blank" rel="noopener" className="btn btn-outline">
              👁️ Preview Profile
            </a>
          ) : (
            <span className="btn btn-outline" style={{ opacity: .45, cursor: 'default' }} title="Set a slug below to preview your profile">
              👁️ Set slug to preview
            </span>
          )}
        </div>

        <div style={{ display: 'flex', gap: '.5rem', marginBottom: '2rem', borderBottom: '1px solid var(--border)', paddingBottom: '1rem', flexWrap: 'wrap' }}>
          {[['basic', '👤 Basic'], ['social', '📱 Social Icons'], ['tabs', '📑 Tabs & Links'], ['settings', '🔒 Profile Settings'], ['domain', '🌐 Domain']].map(([t, l]) => (
            <button key={t} className={`btn ${activeTab === t ? '' : 'btn-outline'}`} onClick={() => setActiveTab(t)}>{l}</button>
          ))}
        </div>

        {activeTab === 'basic' && (
          <form onSubmit={saveProfile}>
            <div style={{ display: 'grid', gap: '2rem' }}>
              <div className="glass" style={{ padding: '1.5rem', display: 'grid', gap: '1.25rem' }}>
                <h3 style={{ marginBottom: '-.25rem', color: 'var(--primary)' }}>🪪 Identity</h3>
                <div>
                  <label style={{ fontWeight: 500, display: 'block', marginBottom: '.35rem' }}>Custom Slug (your profile URL)</label>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '.5rem' }}>
                    <span style={{ background: 'var(--surface2)', padding: '.65rem .75rem', borderRadius: 'var(--radius)', fontSize: '.8rem', fontFamily: 'monospace', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>@</span>
                    <input className="input" value={profile.custom_slug || ''} onChange={e => setProfile({ ...profile, custom_slug: e.target.value })} placeholder="yourname" />
                  </div>
                  <div style={{ marginTop: '.5rem', padding: '.5rem .75rem', background: 'var(--surface2)', borderRadius: 8, display: 'flex', alignItems: 'center', gap: '.5rem', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '.75rem', opacity: .6 }}>Your profile URL:</span>
                    <span style={{ fontFamily: 'monospace', fontSize: '.8rem', color: 'var(--primary)', wordBreak: 'break-all', flex: 1 }}>
                      {userDomain && userDomain.is_verified
                        ? `https://${userDomain.domain}/@${profile.custom_slug || 'yourslug'}`
                        : `${API_BASE_URL}/@${profile.custom_slug || 'yourslug'}`}
                    </span>
                    {profile.custom_slug && (
                      <a href={userDomain && userDomain.is_verified ? `https://${userDomain.domain}/@${profile.custom_slug}` : `${API_BASE_URL}/@${profile.custom_slug}`}
                        target="_blank" rel="noopener"
                        style={{ fontSize: '.75rem', color: 'var(--primary)', textDecoration: 'none', whiteSpace: 'nowrap' }}>
                        Open ↗
                      </a>
                    )}
                  </div>
                  {profile.can_use_custom_domain && (
                    <div style={{ marginTop: '.35rem', fontSize: '.75rem', display: 'flex', gap: '.5rem', alignItems: 'center' }}>
                      {userDomain ? (
                        <span style={{ color: userDomain.is_verified ? '#10b981' : '#f59e0b' }}>
                          {userDomain.is_verified ? `✅ Using custom domain: ${userDomain.domain}` : `⏳ Domain pending DNS: ${userDomain.domain}`}
                        </span>
                      ) : (
                        <span style={{ opacity: .6 }}>🌐 You can add a custom domain —</span>
                      )}
                      <a href="/custom-domain" style={{ color: 'var(--primary)', textDecoration: 'none', fontWeight: 500 }}>
                        {userDomain ? 'Manage domain ↗' : 'Add domain ↗'}
                      </a>
                    </div>
                  )}
                  {!profile.custom_slug && (
                    <p style={{ fontSize: '.72rem', color: 'var(--text-muted)', marginTop: '.35rem' }}>
                      ⚠️ Set a slug above to make your profile public and shareable.
                    </p>
                  )}
                </div>
                <div>
                  <label style={{ fontWeight: 500, display: 'block', marginBottom: '.35rem' }}>Header Text</label>
                  <input className="input" value={profile.header_text || ''} onChange={e => setProfile({ ...profile, header_text: e.target.value })} placeholder="Your Name" />
                </div>
                <div>
                  <label style={{ fontWeight: 500, display: 'block', marginBottom: '.35rem' }}>Sub-header Text</label>
                  <input className="input" value={profile.sub_header_text || ''} onChange={e => setProfile({ ...profile, sub_header_text: e.target.value })} placeholder="Designer · Creator · Builder" />
                </div>
                <div>
                  <label style={{ fontWeight: 500, display: 'block', marginBottom: '.35rem' }}>Bio Description</label>
                  <textarea className="input" rows="3" value={profile.bio_description || ''} onChange={e => setProfile({ ...profile, bio_description: e.target.value })} placeholder="Tell the world about yourself…" />
                </div>
                <div>
                  <label style={{ fontWeight: 500, display: 'block', marginBottom: '.35rem' }}>💬 Daily Status (shown as bubble on profile photo)</label>
                  <input className="input" value={profile.daily_status || ''} onChange={e => setProfile({ ...profile, daily_status: e.target.value })} placeholder="e.g. Building in public! 🚀" />
                  <p style={{ fontSize: '.72rem', color: 'var(--text-muted)', marginTop: '.3rem' }}>Appears as a bubble on your photo. Fades after 24 hrs.</p>
                </div>
              </div>

              <div className="glass" style={{ padding: '1.5rem', display: 'grid', gap: '1.25rem' }}>
                <h3 style={{ marginBottom: '-.25rem', color: 'var(--primary)' }}>🎨 Appearance</h3>

                {/* 🎨 Theme Preset Selector — all 12 monthly themes */}
                <div>
                  <label style={{ fontWeight: 500, display: 'block', marginBottom: '.6rem' }}>🎨 Select a Theme</label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(170px,1fr))', gap: '.55rem', marginBottom: '.75rem' }}>
                    {THEME_PRESETS.map(preset => {
                      const isActive = profile.selected_theme_id === preset.id
                      return (
                        <button
                          type="button"
                          key={preset.id}
                          onClick={() => {
                            if (preset.id === 'custom') {
                              setProfile({ ...profile, theme_color: preset.primary, selected_theme_id: 'custom' })
                            } else {
                              setProfile({
                                ...profile,
                                theme_color: preset.primary,
                                selected_theme_id: preset.id,
                                theme_html: `<script>window.THEME_FX='${preset.fx}';<\/script>\n<style>\n:root{\n  --primary:${preset.primary};\n  --secondary:${preset.secondary};\n  --accent:${preset.accent};\n  --bg:${preset.bg};\n  --text-color:${preset.text};\n  --text-muted-color:${preset.muted};\n}\n</style>`
                              })
                            }
                          }}
                          style={{
                            border: `2px solid ${isActive ? preset.primary : 'var(--border)'}`,
                            borderRadius: '.75rem',
                            padding: '.65rem .75rem',
                            cursor: 'pointer',
                            background: isActive ? `${preset.primary}22` : 'var(--surface2)',
                            textAlign: 'left',
                            transition: '.2s',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: '.2rem'
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '.4rem' }}>
                            <span style={{ display: 'flex', gap: '2px', flexShrink: 0 }}>
                              <span style={{ width: 10, height: 10, borderRadius: '50%', background: preset.primary,   display: 'inline-block' }} />
                              <span style={{ width: 10, height: 10, borderRadius: '50%', background: preset.secondary, display: 'inline-block' }} />
                              <span style={{ width: 10, height: 10, borderRadius: '50%', background: preset.accent,    display: 'inline-block' }} />
                            </span>
                            <strong style={{ fontSize: '.8rem', lineHeight: 1.2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{preset.name}</strong>
                          </div>
                          <span style={{ fontSize: '.68rem', color: 'var(--text-muted)', lineHeight: 1.3 }}>{preset.description}</span>
                        </button>
                      )
                    })}
                  </div>
                  <p style={{ fontSize: '.72rem', color: 'var(--text-muted)' }}>
                    Clicking a theme sets colors &amp; particle effects. ✏️ Custom = write your own CSS.
                  </p>
                </div>
                <div>
                  <label style={{ fontWeight: 500, display: 'block', marginBottom: '.5rem' }}>Theme Color (accent)</label>
                  <div style={{ display: 'flex', gap: '.75rem', alignItems: 'center' }}>
                    <input type="color" value={profile.theme_color} onChange={e => setProfile({ ...profile, theme_color: e.target.value })} style={{ width: 48, height: 40, border: '2px solid var(--border)', borderRadius: '.5rem', cursor: 'pointer', background: 'transparent' }} />
                    <input className="input" value={profile.theme_color} onChange={e => setProfile({ ...profile, theme_color: e.target.value })} placeholder="#a78bfa" style={{ flex: 1 }} />
                  </div>
                </div>
                <div>
                  <label style={{ fontWeight: 500, display: 'block', marginBottom: '.5rem' }}>Card Style</label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(130px,1fr))', gap: '.5rem' }}>
                    {HEADER_STYLES.map(s => (
                      <label key={s.value} style={{ display: 'flex', alignItems: 'center', gap: '.5rem', padding: '.65rem .875rem', borderRadius: 'var(--radius)', border: `2px solid ${profile.header_style === s.value ? 'var(--primary)' : 'var(--border)'}`, cursor: 'pointer', background: profile.header_style === s.value ? 'rgba(99,102,241,.08)' : 'transparent', transition: '.2s' }}>
                        <input type="radio" name="header_style" value={s.value} checked={profile.header_style === s.value} onChange={e => setProfile({ ...profile, header_style: e.target.value })} style={{ display: 'none' }} />
                        <span style={{ fontSize: '1.1rem' }}>{s.value === 'solid' ? '⬜' : s.value === 'glass' ? '🪟' : s.value === 'frost' ? '❄️' : '◻️'}</span>
                        <span style={{ fontSize: '.875rem', fontWeight: 500 }}>{s.label}</span>
                      </label>
                    ))}
                  </div>
                  <p style={{ fontSize: '.72rem', color: 'var(--text-muted)', marginTop: '.4rem' }}>Glass/Frost/Transparent effects require a page background image to look best.</p>
                </div>
                <ImageField label="Page Background Image" value={profile.page_bg_url} field="page_bg_url" helpText="Used as the full-page wallpaper behind the card. Works great with glass/frost styles." />
                <ImageField label="Header Image (banner)" value={profile.header_image_url} field="header_image_url" helpText="Wide banner shown at the top of your profile card." />

                {/* Header Image Size */}
                {profile.header_image_url && (
                  <div>
                    <label style={{ fontWeight: 500, display: 'block', marginBottom: '.5rem' }}>🖼️ Header Image Size</label>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px,1fr))', gap: '.5rem' }}>
                      {HEADER_IMAGE_SIZES.map(s => (
                        <label key={s.value} style={{ display: 'flex', flexDirection: 'column', gap: '.25rem', padding: '.65rem .875rem', borderRadius: 'var(--radius)', border: `2px solid ${profile.header_image_size === s.value ? 'var(--primary)' : 'var(--border)'}`, cursor: 'pointer', background: profile.header_image_size === s.value ? 'rgba(99,102,241,.08)' : 'transparent', transition: '.2s' }}>
                          <input type="radio" name="header_image_size" value={s.value} checked={(profile.header_image_size || 'half') === s.value} onChange={e => setProfile({ ...profile, header_image_size: e.target.value })} style={{ display: 'none' }} />
                          <span style={{ fontSize: '1.2rem' }}>{s.icon}</span>
                          <span style={{ fontSize: '.875rem', fontWeight: 600 }}>{s.label}</span>
                          <span style={{ fontSize: '.7rem', color: 'var(--text-muted)' }}>{s.desc}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                {/* Header Background Opacity */}
                {profile.header_image_url && (
                  <div>
                    <label style={{ fontWeight: 500, display: 'block', marginBottom: '.35rem' }}>
                      Header Image Opacity — <strong>{Math.round(parseFloat(profile.header_bg_opacity || 0.45) * 100)}%</strong>
                    </label>
                    <input type="range" min="0" max="1" step="0.05"
                      value={profile.header_bg_opacity || 0.45}
                      onChange={e => setProfile({ ...profile, header_bg_opacity: e.target.value })}
                      style={{ width: '100%' }} />
                    <p style={{ fontSize: '.72rem', color: 'var(--text-muted)', marginTop: '.3rem' }}>
                      Higher = more visible image. For "Cover" mode this controls the text overlay darkness (inverted).
                    </p>
                  </div>
                )}

                {/* @Slug Display Style */}
                <div>
                  <label style={{ fontWeight: 500, display: 'block', marginBottom: '.5rem' }}>🏷️ @Slug Display Style</label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(130px,1fr))', gap: '.5rem' }}>
                    {SLUG_STYLES.map(s => (
                      <label key={s.value} style={{ display: 'flex', alignItems: 'center', gap: '.5rem', padding: '.65rem .875rem', borderRadius: 'var(--radius)', border: `2px solid ${(profile.slug_style || 'vertical-rotate') === s.value ? 'var(--primary)' : 'var(--border)'}`, cursor: 'pointer', background: (profile.slug_style || 'vertical-rotate') === s.value ? 'rgba(99,102,241,.08)' : 'transparent', transition: '.2s' }}>
                        <input type="radio" name="slug_style" value={s.value} checked={(profile.slug_style || 'vertical-rotate') === s.value} onChange={e => setProfile({ ...profile, slug_style: e.target.value })} style={{ display: 'none' }} />
                        <span style={{ fontSize: '1.1rem' }}>{s.icon}</span>
                        <span style={{ fontSize: '.875rem', fontWeight: 500 }}>{s.label}</span>
                      </label>
                    ))}
                  </div>
                  <p style={{ fontSize: '.72rem', color: 'var(--text-muted)', marginTop: '.4rem' }}>Visitors can click your @slug to copy it. "Hidden" removes it entirely.</p>
                </div>
              </div>

              <div className="glass" style={{ padding: '1.5rem', display: 'grid', gap: '1.25rem' }}>
                <h3 style={{ marginBottom: '-.25rem', color: 'var(--primary)' }}>⚙️ Advanced</h3>
                <div>
                  <label style={{ fontWeight: 500, display: 'block', marginBottom: '.35rem' }}>Custom HTML / CSS Theme</label>
                  <textarea className="input" rows="4" value={profile.theme_html || ''} onChange={e => setProfile({ ...profile, theme_html: e.target.value })} placeholder={'<style>\nbody { font-family: "Georgia", serif; }\n</style>'} />
                </div>
                <div>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '.5rem', cursor: 'pointer', padding: '.75rem', background: 'var(--surface2)', borderRadius: 'var(--radius)' }}>
                    <input type="checkbox" checked={profile.is_redirect_enabled} onChange={e => setProfile({ ...profile, is_redirect_enabled: e.target.checked })} />
                    <div>
                      <div style={{ fontWeight: 500 }}>Profile redirect</div>
                      <div style={{ fontSize: '.75rem', color: 'var(--text-muted)' }}>Visitors will be sent to an external URL instead of seeing your profile</div>
                    </div>
                  </label>
                  {profile.is_redirect_enabled && (
                    <input className="input" style={{ marginTop: '.5rem' }} value={profile.profile_redirect_url || ''} onChange={e => setProfile({ ...profile, profile_redirect_url: e.target.value })} placeholder="https://..." />
                  )}
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: '.5rem', cursor: 'pointer' }}>
                  <input type="checkbox" checked={profile.show_social_icons} onChange={e => setProfile({ ...profile, show_social_icons: e.target.checked })} />
                  Show social icons on profile
                </label>
              </div>

              <button type="submit" className="btn" style={{ width: '100%', justifyContent: 'center', padding: '1rem', fontSize: '1rem' }} disabled={saving}>
                {saving ? 'Saving…' : '💾 Save Profile'}
              </button>
            </div>
          </form>
        )}

        {activeTab === 'social' && (
          <div className="glass" style={{ padding: '2rem' }}>
            <h2 style={{ marginBottom: '1.5rem' }}>📱 Social Icons</h2>
            <form onSubmit={handleIconSubmit} style={{ display: 'grid', gap: '1rem', padding: '1.25rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', marginBottom: '2rem' }}>
              <h3 style={{ fontSize: '1rem' }}>{editingIcon ? 'Edit Icon' : 'Add Icon'}</h3>
              {!editingIcon && (
                <select className="input" value={iconForm.platform} onChange={e => setIconForm({ ...iconForm, platform: e.target.value })} required>
                  <option value="">Select Platform</option>
                  {SOCIAL_PLATFORMS.map(p => <option key={p} value={p}>{p}</option>)}
                </select>
              )}
              <input className="input" placeholder="Profile URL" value={iconForm.url} onChange={e => setIconForm({ ...iconForm, url: e.target.value })} required />
              <div>
                <label style={{ display: 'block', marginBottom: '.35rem', fontSize: '.85rem', fontWeight: 500 }}>Icon Image (optional)</label>
                <div style={{ display: 'flex', gap: '.5rem' }}>
                  <input className="input" placeholder="https://... or upload" value={iconForm.icon_url} onChange={e => setIconForm({ ...iconForm, icon_url: e.target.value })} />
                  <UploadBtn onUpload={url => setIconForm({ ...iconForm, icon_url: url })} />
                </div>
                {iconForm.icon_url && <img src={iconForm.icon_url} alt="" style={{ width: 40, height: 40, borderRadius: '50%', objectFit: 'cover', marginTop: '.5rem' }} />}
              </div>
              <div style={{ display: 'flex', gap: '.5rem' }}>
                <button type="submit" className="btn">{editingIcon ? 'Update' : 'Add'}</button>
                {editingIcon && <button type="button" className="btn btn-outline" onClick={() => { setEditingIcon(null); setIconForm({ platform: '', url: '', icon_url: '' }); }}>Cancel</button>}
              </div>
            </form>
            <div style={{ display: 'grid', gap: '.75rem' }}>
              {socialIcons.map(icon => (
                <div key={icon.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '.875rem', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    {icon.icon_url ? <img src={icon.icon_url} alt={icon.platform} style={{ width: 36, height: 36, borderRadius: '50%', objectFit: 'cover' }} /> : <span style={{ fontSize: '1.5rem' }}>{icon.platform[0]}</span>}
                    <div><strong>{icon.platform}</strong><br /><a href={icon.url} target="_blank" rel="noreferrer" style={{ fontSize: '.8rem', color: 'var(--primary)' }}>{icon.url}</a></div>
                  </div>
                  <div style={{ display: 'flex', gap: '.4rem' }}>
                    <button className="btn btn-outline" onClick={() => { setEditingIcon(icon); setIconForm({ platform: icon.platform, url: icon.url, icon_url: icon.icon_url || '' }); }}>✏️</button>
                    <button className="btn btn-danger" onClick={() => deleteIcon(icon.id)}>🗑️</button>
                  </div>
                </div>
              ))}
              {socialIcons.length === 0 && <p style={{ color: 'var(--text-muted)' }}>No social icons yet.</p>}
            </div>
          </div>
        )}

        {activeTab === 'tabs' && (
          <div className="glass" style={{ padding: '2rem' }}>
            <h2 style={{ marginBottom: '1.5rem' }}>📑 Tabs &amp; Links</h2>

            <form onSubmit={handleTabSubmit} style={{ display: 'grid', gap: '1rem', padding: '1.25rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', marginBottom: '2rem' }}>
              <h3 style={{ fontSize: '1rem' }}>{editingTab ? 'Edit Tab' : 'Create New Tab'}</h3>
              <input className="input" placeholder="Tab Title" value={tabForm.title} onChange={e => setTabForm({ ...tabForm, title: e.target.value })} required />
              <input className="input" placeholder="Slug (auto-generated from title if blank)" value={tabForm.slug} onChange={e => setTabForm({ ...tabForm, slug: e.target.value })} />
              <div style={{ display: 'grid', gap: '.5rem', gridTemplateColumns: '1fr 1fr' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '.35rem', fontSize: '.85rem', fontWeight: 500 }}>Tab Type</label>
                  <select className="input" value={tabForm.tab_type} onChange={e => setTabForm({ ...tabForm, tab_type: e.target.value })}>
                    {TAB_TYPES.map(t => <option key={t.value} value={t.value}>{t.icon} {t.label}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: '.35rem', fontSize: '.85rem', fontWeight: 500 }}>Tab Style</label>
                  <select className="input" value={tabForm.tab_style} onChange={e => setTabForm({ ...tabForm, tab_style: e.target.value })}>
                    {TAB_STYLES.map(s => <option key={s.value} value={s.value}>{s.icon} {s.label}</option>)}
                  </select>
                </div>
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '.35rem', fontSize: '.85rem', fontWeight: 500 }}>
                  Tab Background Image
                </label>
                <div style={{ display: 'flex', gap: '.5rem' }}>
                  <input className="input" placeholder="https://..." value={tabForm.bg_url} onChange={e => setTabForm({ ...tabForm, bg_url: e.target.value })} />
                  <UploadBtn onUpload={url => setTabForm({ ...tabForm, bg_url: url })} />
                  {tabForm.bg_url && <button type="button" className="btn btn-outline" onClick={() => setTabForm({ ...tabForm, bg_url: '' })}>✕</button>}
                </div>
                {tabForm.bg_url && <img src={tabForm.bg_url} alt="" style={{ marginTop: '.5rem', maxHeight: 80, borderRadius: '.5rem', border: '1px solid var(--border)' }} />}
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '.35rem', fontSize: '.85rem', fontWeight: 500 }}>
                  {tabForm.bg_url
                    ? <>Image Visibility — <strong>{Math.round(parseFloat(tabForm.tab_bg_opacity || 0.85) * 100)}%</strong> <span style={{ fontWeight: 400, color: 'var(--text-muted)', fontSize: '.8rem' }}>(0% = fully hidden, 100% = fully visible)</span></>
                    : <>Card Background Opacity — <strong>{Math.round(parseFloat(tabForm.tab_bg_opacity || 0.85) * 100)}%</strong></>
                  }
                </label>
                <input type="range" min="0" max="1" step="0.05"
                  value={tabForm.tab_bg_opacity || 0.85}
                  onChange={e => setTabForm({ ...tabForm, tab_bg_opacity: e.target.value })}
                  style={{ width: '100%' }} />
                <p style={{ fontSize: '.72rem', color: 'var(--text-muted)', marginTop: '.25rem' }}>
                  {tabForm.bg_url
                    ? 'Controls how visible the background image is — independent of Tab Style.'
                    : 'Lower opacity = more wallpaper visible through the card.'}
                </p>
              </div>
              <div style={{ display: 'grid', gap: '.5rem', gridTemplateColumns: '1fr 1fr', alignItems: 'end' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '.35rem', fontSize: '.85rem', fontWeight: 500 }}>Text Color</label>
                  <div style={{ display: 'flex', gap: '.5rem', alignItems: 'center' }}>
                    <input type="color"
                      value={tabForm.tab_text_color || '#ffffff'}
                      onChange={e => setTabForm({ ...tabForm, tab_text_color: e.target.value })}
                      style={{ width: 40, height: 36, padding: 2, borderRadius: 6, border: '1px solid var(--border)', cursor: 'pointer', background: 'none' }}
                    />
                    <input className="input" placeholder="Auto (theme default)" value={tabForm.tab_text_color}
                      onChange={e => setTabForm({ ...tabForm, tab_text_color: e.target.value })}
                      style={{ flex: 1 }} />
                    {tabForm.tab_text_color && <button type="button" className="btn btn-outline" style={{ whiteSpace: 'nowrap', fontSize: '.75rem' }} onClick={() => setTabForm({ ...tabForm, tab_text_color: '' })}>Reset</button>}
                  </div>
                  <p style={{ fontSize: '.72rem', color: 'var(--text-muted)', marginTop: '.25rem' }}>
                    Override text color — useful when bg image or opacity makes theme text unreadable.
                  </p>
                </div>
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '.35rem', fontSize: '.85rem', fontWeight: 500 }}>Text Content (shown above links)</label>
                <textarea className="input" rows="3" value={tabForm.text_content} onChange={e => setTabForm({ ...tabForm, text_content: e.target.value })} placeholder="Bio text, description, anything…" />
              </div>
              <div style={{ display: 'flex', gap: '.5rem' }}>
                <button type="submit" className="btn">{editingTab ? 'Update Tab' : 'Create Tab'}</button>
                {editingTab && <button type="button" className="btn btn-outline" onClick={() => { setEditingTab(null); setTabForm({ title: '', slug: '', tab_type: 'links', tab_style: 'solid', bg_url: '', text_content: '', tab_bg_opacity: '0.85', tab_text_color: '' }); }}>Cancel</button>}
              </div>
            </form>

            {linkTabId && (
              <form onSubmit={handleLinkSubmit} style={{ display: 'grid', gap: '1rem', padding: '1.25rem', background: 'rgba(99,102,241,.06)', borderRadius: 'var(--radius)', border: '2px solid var(--primary)', marginBottom: '2rem' }}>
                <h3 style={{ fontSize: '1rem' }}>{editingLink ? '✏️ Edit Link' : '➕ Add Link'}</h3>
                <input className="input" placeholder="Title *" value={linkForm.title} onChange={e => setLinkForm({ ...linkForm, title: e.target.value })} required />
                <input className="input" placeholder="URL *" value={linkForm.url} onChange={e => setLinkForm({ ...linkForm, url: e.target.value })} required />
                <textarea className="input" rows="2" placeholder="Description (optional)" value={linkForm.description} onChange={e => setLinkForm({ ...linkForm, description: e.target.value })} />
                <div>
                  <label style={{ display: 'block', marginBottom: '.35rem', fontSize: '.85rem', fontWeight: 500 }}>Thumbnail Image</label>
                  <div style={{ display: 'flex', gap: '.5rem' }}>
                    <input className="input" placeholder="https://..." value={linkForm.thumbnail_url} onChange={e => setLinkForm({ ...linkForm, thumbnail_url: e.target.value })} />
                    <UploadBtn onUpload={url => setLinkForm({ ...linkForm, thumbnail_url: url })} />
                    {linkForm.thumbnail_url && <button type="button" className="btn btn-outline" onClick={() => setLinkForm({ ...linkForm, thumbnail_url: '' })}>✕</button>}
                  </div>
                  {linkForm.thumbnail_url && <img src={linkForm.thumbnail_url} alt="" style={{ marginTop: '.5rem', width: 60, height: 60, objectFit: 'cover', borderRadius: '.5rem', border: '1px solid var(--border)' }} />}
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: '.35rem', fontSize: '.85rem', fontWeight: 500 }}>🔗 Link Type</label>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px,1fr))', gap: '.4rem' }}>
                    {LINK_TYPES.map(lt => (
                      <label key={lt.value} style={{ display: 'flex', alignItems: 'center', gap: '.4rem', padding: '.5rem .7rem', borderRadius: 'var(--radius)', border: `2px solid ${(linkForm.link_type || 'url') === lt.value ? 'var(--primary)' : 'var(--border)'}`, cursor: 'pointer', background: (linkForm.link_type || 'url') === lt.value ? 'rgba(99,102,241,.08)' : 'transparent', fontSize: '.82rem', fontWeight: 500, transition: '.2s' }}>
                        <input type="radio" name="link_type" value={lt.value} checked={(linkForm.link_type || 'url') === lt.value} onChange={e => setLinkForm({ ...linkForm, link_type: e.target.value })} style={{ display: 'none' }} />
                        {lt.label}
                      </label>
                    ))}
                  </div>
                  {(linkForm.link_type === 'email' || linkForm.link_type === 'phone' || linkForm.link_type === 'address') && (
                    <p style={{ fontSize: '.72rem', color: 'var(--primary)', marginTop: '.35rem' }}>
                      {linkForm.link_type === 'email' && '📧 Enter the email address. The "mailto:" prefix is added automatically.'}
                      {linkForm.link_type === 'phone' && '📞 Enter the phone number. The "tel:" prefix is added automatically.'}
                      {linkForm.link_type === 'address' && '📍 Visitors can click to copy the address to clipboard.'}
                    </p>
                  )}
                </div>
                <div style={{ display: 'flex', gap: '.5rem' }}>
                  <button type="submit" className="btn">{editingLink ? 'Update Link' : 'Add Link'}</button>
                  <button type="button" className="btn btn-outline" onClick={() => { setEditingLink(null); setLinkForm({ title: '', description: '', url: '', thumbnail_url: '', link_type: 'url' }); setLinkTabId(null); }}>Cancel</button>
                </div>
              </form>
            )}

            <div style={{ display: 'grid', gap: '1.5rem' }}>
              {tabs.map(tab => (
                <div key={tab.id} style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius)', overflow: 'hidden', background: 'var(--surface)' }}>
                  <div style={{ padding: '.875rem 1rem', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '.5rem', background: 'var(--surface2)' }}>
                    <div>
                      <strong>{tab.title}</strong>
                      <span style={{ marginLeft: '.5rem', fontSize: '.75rem', color: 'var(--text-muted)' }}>({tab.tab_type} · {tab.tab_style})</span>
                      <br /><code style={{ fontSize: '.72rem', color: 'var(--text-muted)' }}>/{tab.slug}</code>
                    </div>
                    <div style={{ display: 'flex', gap: '.35rem' }}>
                      <button className="btn btn-outline" style={{ fontSize: '.8rem', padding: '.35rem .75rem' }} onClick={() => { setEditingTab(tab); setTabForm({ title: tab.title, slug: tab.slug || '', tab_type: tab.tab_type, tab_style: tab.tab_style, bg_url: tab.bg_url || '', text_content: tab.text_content || '', tab_bg_opacity: tab.tab_bg_opacity || '0.85', tab_text_color: tab.tab_text_color || '' }); }}>✏️ Edit Tab</button>
                      <button className="btn btn-danger" style={{ fontSize: '.8rem', padding: '.35rem .75rem' }} onClick={() => deleteTab(tab.id)}>🗑️</button>
                    </div>
                  </div>
                  <div style={{ padding: '1rem' }}>
                    {tab.links?.length > 0 ? (
                      <div style={{ display: 'grid', gap: '.6rem', marginBottom: '.75rem' }}>
                        {tab.links.map(link => (
                          <div key={link.id} style={{ display: 'flex', alignItems: 'center', gap: '.75rem', padding: '.75rem', background: 'var(--surface2)', borderRadius: '.625rem', border: '1px solid var(--border)' }}>
                            {link.thumbnail_url ? <img src={link.thumbnail_url} alt="" style={{ width: 40, height: 40, borderRadius: '.375rem', objectFit: 'cover', flexShrink: 0 }} /> : <span style={{ fontSize: '1.25rem', flexShrink: 0 }}>🔗</span>}
                            <div style={{ flex: 1, minWidth: 0 }}>
                              <strong style={{ fontSize: '.875rem' }}>{link.title}</strong>
                              <div style={{ fontSize: '.75rem', color: 'var(--primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{link.url}</div>
                            </div>
                            <div style={{ display: 'flex', gap: '.35rem', flexShrink: 0 }}>
                              <button className="btn btn-outline" style={{ fontSize: '.78rem', padding: '.3rem .6rem' }} onClick={() => { setLinkTabId(tab.id); setEditingLink(link); setLinkForm({ title: link.title, description: link.description || '', url: link.url, thumbnail_url: link.thumbnail_url || '', link_type: link.link_type || 'url' }); }}>✏️</button>
                              <button className="btn btn-danger" style={{ fontSize: '.78rem', padding: '.3rem .6rem' }} onClick={() => deleteLink(tab.id, link.id)}>🗑️</button>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p style={{ color: 'var(--text-muted)', fontSize: '.875rem', marginBottom: '.75rem' }}>No links yet.</p>
                    )}
                    <button className="btn btn-outline" style={{ fontSize: '.875rem' }} onClick={() => { setLinkTabId(tab.id); setEditingLink(null); setLinkForm({ title: '', description: '', url: '', thumbnail_url: '', link_type: 'url' }); }}>
                      ➕ Add Link to this Tab
                    </button>
                  </div>
                </div>
              ))}
              {tabs.length === 0 && <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '2rem' }}>No tabs yet. Create one above!</p>}
            </div>
          </div>
        )}

        {activeTab === 'settings' && (
          <form onSubmit={saveProfile}>
            <div style={{ display: 'grid', gap: '2rem' }}>

              {/* ── Profiles Section ── */}
              <div className="glass" style={{ padding: '1.5rem', display: 'grid', gap: '1rem' }}>
                <h3 style={{ marginBottom: '-.25rem', color: 'var(--primary)' }}>👤 Profiles</h3>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '.75rem', cursor: 'pointer', padding: '.875rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', border: `2px solid ${profile.is_verified ? 'var(--primary)' : 'var(--border)'}` }}>
                  <input type="checkbox" checked={profile.is_verified || false} onChange={e => setProfile({ ...profile, is_verified: e.target.checked })} style={{ marginTop: '.15rem' }} />
                  <div>
                    <div style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '.4rem' }}>✅ Verified Badge <span style={{ background: 'linear-gradient(135deg,#1d9bf0,#0d6efd)', color: '#fff', fontSize: '.65rem', fontWeight: 700, padding: '.15rem .4rem', borderRadius: '9999px' }}>✓ Verified</span></div>
                    <div style={{ fontSize: '.78rem', color: 'var(--text-muted)', marginTop: '.2rem' }}>Display the verified badge on your Bio Page next to your name.</div>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '.75rem', cursor: 'pointer', padding: '.875rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', border: `2px solid ${profile.is_sensitive ? 'var(--primary)' : 'var(--border)'}` }}>
                  <input type="checkbox" checked={profile.is_sensitive || false} onChange={e => setProfile({ ...profile, is_sensitive: e.target.checked })} style={{ marginTop: '.15rem' }} />
                  <div>
                    <div style={{ fontWeight: 600 }}>⚠️ Sensitive Content</div>
                    <div style={{ fontSize: '.78rem', color: 'var(--text-muted)', marginTop: '.2rem' }}>Warns users before showing them your Bio Page.</div>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '.75rem', cursor: 'pointer', padding: '.875rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', border: `2px solid ${profile.age_restriction ? 'var(--primary)' : 'var(--border)'}` }}>
                  <input type="checkbox" checked={profile.age_restriction || false} onChange={e => setProfile({ ...profile, age_restriction: e.target.checked })} style={{ marginTop: '.15rem' }} />
                  <div>
                    <div style={{ fontWeight: 600 }}>🔞 Age Restriction</div>
                    <div style={{ fontSize: '.78rem', color: 'var(--text-muted)', marginTop: '.2rem' }}>Require users to confirm they are 18+ before accessing your Bio Page.</div>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '.75rem', cursor: 'pointer', padding: '.875rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', border: `2px solid ${profile.cookie_popup ? 'var(--primary)' : 'var(--border)'}` }}>
                  <input type="checkbox" checked={profile.cookie_popup || false} onChange={e => setProfile({ ...profile, cookie_popup: e.target.checked })} style={{ marginTop: '.15rem' }} />
                  <div>
                    <div style={{ fontWeight: 600 }}>🍪 Cookie Popup</div>
                    <div style={{ fontSize: '.78rem', color: 'var(--text-muted)', marginTop: '.2rem' }}>Show a cookie consent banner so visitors can review your cookie usage terms.</div>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '.75rem', cursor: 'pointer', padding: '.875rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', border: `2px solid ${profile.show_share_icon ? 'var(--primary)' : 'var(--border)'}` }}>
                  <input type="checkbox" checked={profile.show_share_icon !== false} onChange={e => setProfile({ ...profile, show_share_icon: e.target.checked })} style={{ marginTop: '.15rem' }} />
                  <div>
                    <div style={{ fontWeight: 600 }}>📤 Share Icon</div>
                    <div style={{ fontSize: '.78rem', color: 'var(--text-muted)', marginTop: '.2rem' }}>Show a Share button next to the Report button at the bottom of your Bio Page.</div>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '.75rem', cursor: 'pointer', padding: '.875rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', border: `2px solid ${profile.remove_branding ? 'var(--primary)' : 'var(--border)'}` }}>
                  <input type="checkbox" checked={profile.remove_branding || false} onChange={e => setProfile({ ...profile, remove_branding: e.target.checked })} style={{ marginTop: '.15rem' }} />
                  <div>
                    <div style={{ fontWeight: 600 }}>🚫 Remove Branding</div>
                    <div style={{ fontSize: '.78rem', color: 'var(--text-muted)', marginTop: '.2rem' }}>Remove the "Powered by" footer branding from your Bio Page.</div>
                  </div>
                </label>

                <div style={{ padding: '.875rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', border: `2px solid ${profile.profile_password ? 'var(--primary)' : 'var(--border)'}` }}>
                  <div style={{ fontWeight: 600, marginBottom: '.4rem' }}>🔐 Password Protection</div>
                  <div style={{ fontSize: '.78rem', color: 'var(--text-muted)', marginBottom: '.75rem' }}>Restrict access to your Bio Page with a password. Leave blank to remove protection.</div>
                  <div style={{ display: 'flex', gap: '.5rem' }}>
                    <input className="input" type="password" placeholder="Set a password (leave blank to disable)" value={profile.profile_password || ''} onChange={e => setProfile({ ...profile, profile_password: e.target.value })} style={{ flex: 1 }} />
                    {profile.profile_password && <button type="button" className="btn btn-outline" onClick={() => setProfile({ ...profile, profile_password: '' })} style={{ whiteSpace: 'nowrap' }}>🗑 Remove</button>}
                  </div>
                </div>
              </div>

              {/* ── Settings Section ── */}
              <div className="glass" style={{ padding: '1.5rem', display: 'grid', gap: '1.25rem' }}>
                <h3 style={{ marginBottom: '-.25rem', color: 'var(--primary)' }}>📸 Profile Photo &amp; Avatar</h3>

                <ImageField label="Profile Photo" value={profile.profile_photo_url} field="profile_photo_url" />

                <div>
                  <label style={{ fontWeight: 500, display: 'block', marginBottom: '.5rem' }}>Photo Alignment</label>
                  <div style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap' }}>
                    {LAYOUT_OPTIONS.map(opt => (
                      <label key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: '.4rem', padding: '.6rem 1rem', borderRadius: 'var(--radius)', border: `2px solid ${profile.profile_layout === opt.value ? 'var(--primary)' : 'var(--border)'}`, cursor: 'pointer', background: profile.profile_layout === opt.value ? 'rgba(99,102,241,.08)' : 'transparent', transition: '.2s' }}>
                        <input type="radio" name="profile_layout" value={opt.value} checked={profile.profile_layout === opt.value} onChange={e => setProfile({ ...profile, profile_layout: e.target.value })} style={{ display: 'none' }} />
                        <span>{opt.icon}</span>
                        <span style={{ fontSize: '.875rem', fontWeight: 500 }}>{opt.label}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: '.75rem', cursor: 'pointer', padding: '.875rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', border: `2px solid ${profile.display_avatar !== false ? 'var(--primary)' : 'var(--border)'}` }}>
                  <input type="checkbox" checked={profile.display_avatar !== false} onChange={e => setProfile({ ...profile, display_avatar: e.target.checked })} style={{ marginTop: '.15rem' }} />
                  <div>
                    <div style={{ fontWeight: 600 }}>Show Avatar on Bio Page</div>
                    <div style={{ fontSize: '.78rem', color: 'var(--text-muted)', marginTop: '.2rem' }}>Toggle your profile photo visible or hidden.</div>
                  </div>
                </label>

                {profile.display_avatar !== false && (<>
                  <div>
                    <label style={{ fontWeight: 500, display: 'block', marginBottom: '.5rem' }}>Avatar Shape</label>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '.5rem' }}>
                      {AVATAR_SHAPES.map(s => (
                        <label key={s.value} style={{ display: 'flex', alignItems: 'center', gap: '.5rem', padding: '.65rem .875rem', borderRadius: 'var(--radius)', border: `2px solid ${(profile.profile_photo_style || 'circle') === s.value ? 'var(--primary)' : 'var(--border)'}`, cursor: 'pointer', background: (profile.profile_photo_style || 'circle') === s.value ? 'rgba(99,102,241,.08)' : 'transparent', transition: '.2s' }}>
                          <input type="radio" name="profile_photo_style" value={s.value} checked={(profile.profile_photo_style || 'circle') === s.value} onChange={e => setProfile({ ...profile, profile_photo_style: e.target.value })} style={{ display: 'none' }} />
                          <span style={{ fontSize: '1.2rem' }}>{s.icon}</span>
                          <span style={{ fontSize: '.85rem', fontWeight: 500 }}>{s.label}</span>
                        </label>
                      ))}
                    </div>
                    <p style={{ fontSize: '.72rem', color: 'var(--text-muted)', marginTop: '.3rem' }}>Sets the crop shape of your photo.</p>
                  </div>

                  <div>
                    <label style={{ fontWeight: 500, display: 'block', marginBottom: '.5rem' }}>Avatar Effect</label>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '.5rem' }}>
                      {AVATAR_EFFECTS.map(s => (
                        <label key={s.value} style={{ display: 'flex', alignItems: 'center', gap: '.5rem', padding: '.65rem .875rem', borderRadius: 'var(--radius)', border: `2px solid ${(profile.avatar_style || 'none') === s.value ? 'var(--primary)' : 'var(--border)'}`, cursor: 'pointer', background: (profile.avatar_style || 'none') === s.value ? 'rgba(99,102,241,.08)' : 'transparent', transition: '.2s' }}>
                          <input type="radio" name="avatar_style" value={s.value} checked={(profile.avatar_style || 'none') === s.value} onChange={e => setProfile({ ...profile, avatar_style: e.target.value })} style={{ display: 'none' }} />
                          <span style={{ fontSize: '1.2rem' }}>{s.icon}</span>
                          <span style={{ fontSize: '.85rem', fontWeight: 500 }}>{s.label}</span>
                        </label>
                      ))}
                    </div>
                    <p style={{ fontSize: '.72rem', color: 'var(--text-muted)', marginTop: '.3rem' }}>Adds an animated border or glow around your avatar — independent of shape.</p>
                  </div>
                </>)}
              </div>

              <button type="submit" className="btn" style={{ width: '100%', justifyContent: 'center', padding: '1rem', fontSize: '1rem' }} disabled={saving}>
                {saving ? 'Saving…' : '💾 Save Settings'}
              </button>
            </div>
          </form>
        )}

        {activeTab === 'domain' && (
          <div>
            {!profile.can_use_custom_domain ? (
              <div className="glass" style={{ padding: '2.5rem', textAlign: 'center', borderRadius: 12 }}>
                <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔒</div>
                <h3 style={{ marginBottom: '.5rem' }}>Custom Domains Not Enabled</h3>
                <p style={{ opacity: .7, maxWidth: 400, margin: '0 auto' }}>
                  Contact an admin to enable custom domain access for your account.
                </p>
              </div>
            ) : (
              <DomainTab apiBaseUrl={API_BASE_URL} />
            )}
          </div>
        )}
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}

function DomainTab({ apiBaseUrl }) {
  const [record, setRecord] = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [toast, setToast] = useState(null)
  const [domain, setDomain] = useState('')
  const [rootRedirect, setRootRedirect] = useState('')
  const [notFoundRedirect, setNotFoundRedirect] = useState('')
  const token = localStorage.getItem('token')
  const API = apiBaseUrl || ''

  const showToast = (msg, type = 'success') => { setToast({ msg, type }); setTimeout(() => setToast(null), 4000) }

  const load = () => {
    fetch(`${API}/api/domains/my`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.status === 403 ? null : r.json())
      .then(d => {
        if (d && d.id) {
          setRecord(d); setDomain(d.domain || ''); setRootRedirect(d.root_redirect || ''); setNotFoundRedirect(d.not_found_redirect || '')
        }
        setLoading(false)
      }).catch(() => setLoading(false))
  }
  useEffect(load, [])

  const save = () => {
    if (!domain.trim()) return showToast('Enter a domain name', 'error')
    setSaving(true)
    const clean = domain.replace(/^https?:\/\//, '').split('/')[0].toLowerCase()
    const method = record ? 'PUT' : 'POST'
    const body = record
      ? { root_redirect: rootRedirect, not_found_redirect: notFoundRedirect }
      : { domain: clean, root_redirect: rootRedirect, not_found_redirect: notFoundRedirect }
    fetch(`${API}/api/domains/my`, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(async r => { setSaving(false); if (!r.ok) { const e = await r.json(); return showToast(e.detail || 'Error', 'error') } showToast('✅ Saved!'); load() })
  }

  const verify = () => {
    setVerifying(true)
    fetch(`${API}/api/domains/my/verify`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } })
      .then(async r => { setVerifying(false); if (!r.ok) { const e = await r.json(); return showToast(e.detail || 'DNS not ready yet', 'error') } showToast('✅ Verified and live!'); load() })
  }

  const remove = () => {
    if (!confirm('Remove your custom domain?')) return
    fetch(`${API}/api/domains/my`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } })
      .then(() => { setRecord(null); setDomain(''); setRootRedirect(''); setNotFoundRedirect(''); showToast('Domain removed') })
  }

  if (loading) return <div style={{ padding: '2rem', opacity: .6 }}>Loading…</div>

  const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0].toLowerCase()

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr)', gap: '1.5rem' }}>
      {toast && <div style={{ gridColumn: '1/-1', padding: '.75rem 1.25rem', borderRadius: 10, background: toast.type === 'error' ? '#ef4444' : 'var(--primary)', color: '#fff' }}>{toast.msg}</div>}

      <div className="glass" style={{ padding: '1.5rem', borderRadius: 12 }}>
        <h3 style={{ margin: '0 0 1.25rem', color: 'var(--primary)' }}>🌐 Your Custom Domain</h3>
        {record && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '.5rem', marginBottom: '1rem', padding: '.5rem .75rem', background: 'var(--surface2)', borderRadius: 8 }}>
            <span style={{ fontFamily: 'monospace', fontWeight: 600, fontSize: '.9rem' }}>{record.domain}</span>
            <span style={{ marginLeft: 'auto', padding: '2px 8px', borderRadius: 99, fontSize: '.75rem', fontWeight: 600,
              background: record.is_verified ? '#10b98120' : '#f59e0b20', color: record.is_verified ? '#10b981' : '#f59e0b' }}>
              {record.is_verified ? '✅ Live' : '⏳ Pending DNS'}
            </span>
          </div>
        )}
        <div style={{ display: 'grid', gap: '1rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '.4rem', fontSize: '.875rem', fontWeight: 500 }}>Domain Name</label>
            <input className="input" placeholder="yourdomain.com" value={domain} onChange={e => setDomain(e.target.value)} disabled={!!record} style={{ opacity: record ? .6 : 1 }} />
            {cleanDomain && <p style={{ fontSize: '.72rem', color: 'var(--primary)', marginTop: '.3rem', fontFamily: 'monospace' }}>https://{cleanDomain}/@yourslug</p>}
            {record && <p style={{ fontSize: '.72rem', opacity: .5, marginTop: '.25rem' }}>Remove domain to change it.</p>}
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '.4rem', fontSize: '.875rem', fontWeight: 500 }}>Root Redirect <span style={{ opacity: .5, fontWeight: 400 }}>(optional)</span></label>
            <input className="input" placeholder={`https://${cleanDomain || 'yourdomain.com'}/@yourslug`} value={rootRedirect} onChange={e => setRootRedirect(e.target.value)} />
            <p style={{ fontSize: '.72rem', opacity: .5, marginTop: '.25rem' }}>Where to redirect visitors who open your bare domain.</p>
          </div>
          <div>
            <label style={{ display: 'block', marginBottom: '.4rem', fontSize: '.875rem', fontWeight: 500 }}>404 Redirect <span style={{ opacity: .5, fontWeight: 400 }}>(optional)</span></label>
            <input className="input" placeholder={`https://${cleanDomain || 'yourdomain.com'}/not-found`} value={notFoundRedirect} onChange={e => setNotFoundRedirect(e.target.value)} />
            <p style={{ fontSize: '.72rem', opacity: .5, marginTop: '.25rem' }}>Where to redirect if a short link isn't found.</p>
          </div>
          <div style={{ display: 'flex', gap: '.75rem', flexWrap: 'wrap' }}>
            <button className="btn" onClick={save} disabled={saving}>{saving ? 'Saving…' : record ? '💾 Update' : '➕ Add Domain'}</button>
            {record && !record.is_verified && <button className="btn btn-outline" onClick={verify} disabled={verifying}>{verifying ? 'Checking…' : '🔍 Verify DNS'}</button>}
            {record && <button className="btn btn-outline" onClick={remove} style={{ color: '#ef4444', borderColor: '#ef4444' }}>🗑 Remove</button>}
          </div>
        </div>
      </div>

      <div className="glass" style={{ padding: '1.5rem', borderRadius: 12 }}>
        <h3 style={{ margin: '0 0 1rem' }}>📋 DNS Setup</h3>
        <p style={{ fontSize: '.875rem', opacity: .8, lineHeight: 1.7, margin: '0 0 1rem' }}>
          Add an A record at your registrar pointing your domain to this server:
        </p>
        {[['Type', 'A'], ['Name', '@  (root domain)'], ['Value', 'Your server IP'], ['TTL', '3600 or Auto']].map(([k, v]) => (
          <div key={k} style={{ display: 'flex', gap: '.75rem', padding: '.4rem .75rem', background: 'var(--surface2)', borderRadius: 7, marginBottom: '.35rem' }}>
            <span style={{ minWidth: 90, fontSize: '.8rem', opacity: .6 }}>{k}</span>
            <span style={{ fontFamily: 'monospace', fontSize: '.85rem', fontWeight: 600 }}>{v}</span>
          </div>
        ))}
        <div style={{ marginTop: '1rem', padding: '.75rem 1rem', background: 'rgba(99,102,241,.08)', borderRadius: 8, borderLeft: '3px solid var(--primary)', fontSize: '.82rem', lineHeight: 1.7 }}>
          💡 After DNS propagates (up to 48h), click <strong>Verify DNS</strong>. Your profile will be at<br />
          <code>https://{cleanDomain || 'yourdomain.com'}/@yourslug</code>
        </div>
        <div style={{ marginTop: '.75rem', padding: '.75rem 1rem', background: 'rgba(245,158,11,.08)', borderRadius: 8, borderLeft: '3px solid #f59e0b', fontSize: '.82rem', lineHeight: 1.6 }}>
          🔶 For HTTPS, use Cloudflare proxy (orange cloud) for automatic SSL.
        </div>
      </div>
    </div>
  )
}
JSXEOF

# ---------- frontend/src/pages/Messages.jsx (v11.8.0 — fixed reply routing) ----------
cat > frontend/src/pages/Messages.jsx << 'MSGJSXEOF'
import { useState, useEffect, useCallback } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

function MsgCard({ msg, onReply, onDelete, isSent }) {
  const [expanded, setExpanded] = useState(false)
  const isUnread = msg.status === 'unread'
  // Self-notifications (admin-to-self report alerts) can't be replied to
  const isSelfNotification = msg.sender_id && msg.sender_id === msg.recipient_id
  // Guest/null sender_id = no reply address available
  const canReply = !isSent && !isSelfNotification && msg.sender_id != null

  return (
    <div style={{ border: `1px solid var(--border)`, borderLeft: `4px solid ${isUnread ? 'var(--primary)' : 'var(--border)'}`, borderRadius: '.75rem', overflow: 'hidden', background: 'var(--surface)', marginBottom: '.75rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '.75rem', padding: '.875rem 1rem', cursor: 'pointer', flexWrap: 'wrap' }} onClick={() => setExpanded(!expanded)}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '.5rem', flexWrap: 'wrap' }}>
            {isUnread && <span style={{ background: 'var(--primary)', color: '#fff', fontSize: '.65rem', fontWeight: 700, padding: '2px 8px', borderRadius: '999px' }}>NEW</span>}
            {isSelfNotification && <span style={{ background: 'var(--surface2)', color: 'var(--text-muted)', fontSize: '.65rem', fontWeight: 600, padding: '2px 8px', borderRadius: '999px' }}>NOTIFICATION</span>}
            <strong style={{ fontSize: '.9rem' }}>{msg.subject}</strong>
          </div>
          <div style={{ fontSize: '.78rem', color: 'var(--text-muted)', marginTop: '.15rem' }}>
            {isSent
              ? `To: ${msg.recipient_email || 'Unknown'}`
              : isSelfNotification
                ? 'System notification'
                : `From: ${msg.sender_email || msg.guest_name || 'Guest'}`
            } · {new Date(msg.created_at).toLocaleString()}
          </div>
        </div>
        <span style={{ color: 'var(--text-muted)', fontSize: '.85rem' }}>{expanded ? '▲' : '▼'}</span>
      </div>
      {expanded && (
        <div style={{ borderTop: '1px solid var(--border)', padding: '1rem' }}>
          <p style={{ whiteSpace: 'pre-wrap', fontSize: '.875rem', lineHeight: 1.6, marginBottom: '1rem' }}>{msg.content}</p>
          <div style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap' }}>
            {canReply && (
              <button className="btn btn-outline" onClick={() => onReply(msg)} style={{ fontSize: '.8rem' }}>💬 Reply</button>
            )}
            {!canReply && !isSent && (
              <span style={{ fontSize: '.78rem', color: 'var(--text-muted)', padding: '.4rem .75rem', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                {isSelfNotification ? '📋 Notification only' : '📧 Guest — no reply address'}
              </span>
            )}
            <button className="btn btn-danger" style={{ fontSize: '.8rem' }} onClick={() => onDelete(msg.id)}>🗑️ Delete</button>
          </div>
        </div>
      )}
    </div>
  )
}

export default function Messages() {
  const [tab, setTab] = useState('inbox')
  const [messages, setMessages] = useState([])
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState(null)
  const [replyTo, setReplyTo] = useState(null)
  const [subject, setSubject] = useState('')
  const [content, setContent] = useState('')
  const [sending, setSending] = useState(false)
  const [recipientSlug, setRecipientSlug] = useState('')

  const fetchMessages = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await api.get(tab === 'inbox' ? '/api/messages/inbox' : '/api/messages/sent')
      setMessages(data)
      if (tab === 'inbox') api.patch('/api/messages/inbox/read-all').catch(() => {})
    } catch {
      setToast({ message: 'Failed to load messages', type: 'error' })
    } finally {
      setLoading(false)
    }
  }, [tab])

  useEffect(() => { if (tab !== 'compose') fetchMessages() }, [fetchMessages, tab])

  const startReply = (msg) => {
    setReplyTo(msg)
    setRecipientSlug('')
    setSubject(`Re: ${msg.subject.replace(/^Re:\s*/i, '')}`)
    setContent(`\n─────────────────────\nOn ${new Date(msg.created_at).toLocaleString()}, ${msg.sender_email || msg.guest_name || 'Guest'} wrote:\n${msg.content}`)
    setTab('compose')
    window.scrollTo(0, 0)
  }

  const cancelReply = () => { setReplyTo(null); setRecipientSlug(''); setSubject(''); setContent('') }

  const sendMessage = async (e) => {
    e.preventDefault()
    if (!subject.trim() || !content.trim()) { setToast({ message: 'Subject and message are required', type: 'error' }); return }
    if (!replyTo && !recipientSlug.trim()) { setToast({ message: 'Enter a recipient @username', type: 'error' }); return }
    if (replyTo && !replyTo.sender_id) { setToast({ message: 'Cannot reply — no recipient address', type: 'error' }); return }
    setSending(true)
    try {
      const payload = { subject: subject.trim(), content: content.trim(), reply_to_id: replyTo?.id || null }
      if (replyTo) {
        payload.recipient_id = replyTo.sender_id
      } else {
        payload.recipient_slug = recipientSlug.replace(/^@/, '').trim()
      }
      await api.post('/api/messages', payload)
      setToast({ message: '✉️ Message sent!', type: 'success' })
      cancelReply()
      setTab('sent')
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Failed to send', type: 'error' })
    } finally {
      setSending(false)
    }
  }

  const deleteMessage = async (id) => {
    if (!confirm('Delete this message?')) return
    try {
      await api.delete(`/api/messages/${id}`)
      setMessages(prev => prev.filter(m => m.id !== id))
      setToast({ message: 'Message deleted', type: 'success' })
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Delete failed', type: 'error' })
    }
  }

  return (
    <div>
      <Navbar />
      <main style={{ padding: '2rem', maxWidth: 820, margin: '0 auto' }}>
        <h1 style={{ marginBottom: '1.5rem' }}>📬 Messages</h1>
        <div style={{ display: 'flex', gap: '.5rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border)', paddingBottom: '1rem', flexWrap: 'wrap' }}>
          {['inbox', 'sent', 'compose'].map(t => (
            <button key={t} className={`btn ${tab === t ? '' : 'btn-outline'}`}
              onClick={() => { if (t !== 'compose') cancelReply(); setTab(t) }}
              style={{ fontSize: '.875rem' }}>
              {t === 'inbox' ? '📥 Inbox' : t === 'sent' ? '📤 Sent' : '✏️ Compose'}
            </button>
          ))}
        </div>
        {tab === 'compose' && (
          <div className="glass" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h2 style={{ fontSize: '1.1rem' }}>{replyTo ? `↩ Replying to ${replyTo.sender_email || 'message'}` : '📝 New Message'}</h2>
              {replyTo && <button className="btn btn-outline" onClick={cancelReply}>✕ Cancel reply</button>}
            </div>
            <form onSubmit={sendMessage} style={{ display: 'grid', gap: '1rem' }}>
              {!replyTo ? (
                <div>
                  <label style={{ display: 'block', marginBottom: '.35rem', fontWeight: 500 }}>To (username)</label>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '.5rem' }}>
                    <span style={{ padding: '.75rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', fontSize: '.85rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>@</span>
                    <input className="input" type="text" placeholder="username" value={recipientSlug.replace(/^@/, '')} onChange={e => setRecipientSlug(e.target.value)} required style={{ flex: 1 }} />
                  </div>
                </div>
              ) : (
                <div style={{ padding: '.6rem .9rem', background: 'var(--surface2)', borderRadius: 'var(--radius)', fontSize: '.85rem', color: 'var(--text-muted)' }}>
                  📨 Replying to <strong>{replyTo.sender_email}</strong>
                </div>
              )}
              <div>
                <label style={{ display: 'block', marginBottom: '.35rem', fontWeight: 500 }}>Subject</label>
                <input className="input" type="text" placeholder="Subject" value={subject} onChange={e => setSubject(e.target.value)} required />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '.35rem', fontWeight: 500 }}>Message</label>
                <textarea className="input" rows="7" placeholder="Write your message…" value={content} onChange={e => setContent(e.target.value)} required />
              </div>
              <button type="submit" className="btn" disabled={sending} style={{ justifyContent: 'center' }}>
                {sending ? '⏳ Sending…' : '📤 Send Message'}
              </button>
            </form>
          </div>
        )}
        {(tab === 'inbox' || tab === 'sent') && (
          loading ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>Loading…</div>
          ) : messages.length === 0 ? (
            <div className="empty glass">
              <div className="empty-icon">📭</div>
              <h3>{tab === 'inbox' ? 'Inbox empty' : 'No sent messages'}</h3>
            </div>
          ) : messages.map(msg => (
            <MsgCard key={msg.id} msg={msg} isSent={tab === 'sent'} onReply={startReply} onDelete={deleteMessage} />
          ))
        )}
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
MSGJSXEOF

# ---------- frontend/src/pages/TwoFA.jsx ----------
cat > frontend/src/pages/TwoFA.jsx << 'EOF'
import { useState, useEffect } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'
import { QRCodeSVG } from 'qrcode.react'

export default function TwoFA() {
  const [loading, setLoading] = useState(true)
  const [status, setStatus] = useState({ enabled: false, has_backup_codes: false, last_reset_at: null })
  const [setupData, setSetupData] = useState(null)
  const [verifyCode, setVerifyCode] = useState('')
  const [backupCodes, setBackupCodes] = useState([])
  const [password, setPassword] = useState('')
  const [toast, setToast] = useState(null)

  useEffect(() => {
    fetchStatus()
  }, [])

  const fetchStatus = async () => {
    try {
      const res = await api.get('/api/auth/2fa/status')
      setStatus(res.data)
    } catch (err) {
      setToast({ message: 'Failed to load 2FA status', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  const startSetup = async () => {
    try {
      const res = await api.post('/api/auth/2fa/setup', { generate_backup_codes: true })
      setSetupData(res.data)
      setBackupCodes(res.data.backup_codes || [])
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Setup failed', type: 'error' })
    }
  }

  const verifyAndEnable = async () => {
    if (!verifyCode) return
    try {
      await api.post('/api/auth/2fa/verify', { code: verifyCode })
      setToast({ message: '2FA enabled successfully', type: 'success' })
      setSetupData(null)
      setVerifyCode('')
      fetchStatus()
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Verification failed', type: 'error' })
    }
  }

  const disable2FA = async () => {
    if (!password) {
      setToast({ message: 'Password required', type: 'error' })
      return
    }
    try {
      await api.post('/api/auth/2fa/disable', { password })
      setToast({ message: '2FA disabled', type: 'success' })
      setPassword('')
      fetchStatus()
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Disable failed', type: 'error' })
    }
  }

  if (loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>

  return (
    <div>
      <Navbar />
      <main style={{ maxWidth: 600, margin: '0 auto', padding: '2rem' }}>
        <div className="glass" style={{ padding: '2rem' }}>
          <h2 style={{ marginBottom: '1.5rem' }}>🔐 Two‑Factor Authentication</h2>

          {!status.enabled && !setupData && (
            <div>
              <p>Protect your account with 2FA. When enabled, you'll need both your password and a one‑time code from an authenticator app.</p>
              <button className="btn" onClick={startSetup} style={{ marginTop: '1rem' }}>Enable 2FA</button>
            </div>
          )}

          {setupData && (
            <div>
              <h3>Scan QR Code</h3>
              <div style={{ background: '#fff', padding: '1rem', borderRadius: '0.5rem', display: 'inline-block', margin: '1rem 0' }}>
                <QRCodeSVG value={setupData.provisioning_uri} size={200} />
              </div>
              <p>Or enter this secret manually: <code>{setupData.secret}</code></p>
              {backupCodes.length > 0 && (
                <div style={{ margin: '1rem 0' }}>
                  <h4>Backup Codes</h4>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Save these in a safe place. Each can be used once if you lose access to your authenticator.</p>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,1fr)', gap: '0.5rem', fontFamily: 'monospace', fontSize: '0.9rem', background: 'var(--surface2)', padding: '1rem', borderRadius: '0.5rem' }}>
                    {backupCodes.map(code => <div key={code}>{code}</div>)}
                  </div>
                </div>
              )}
              <div style={{ marginTop: '1rem' }}>
                <label>Enter the 6‑digit code from your app</label>
                <input className="input" type="text" value={verifyCode} onChange={e => setVerifyCode(e.target.value)} maxLength="6" />
                <button className="btn" onClick={verifyAndEnable} style={{ marginTop: '0.5rem' }}>Verify & Enable</button>
              </div>
            </div>
          )}

          {status.enabled && (
            <div>
              <p style={{ color: 'var(--success)' }}>✅ 2FA is enabled</p>
              {status.has_backup_codes && <p>You have backup codes saved.</p>}
              <div style={{ marginTop: '1rem' }}>
                <label>Enter your password to disable 2FA</label>
                <input className="input" type="password" value={password} onChange={e => setPassword(e.target.value)} />
                <button className="btn btn-danger" onClick={disable2FA} style={{ marginTop: '0.5rem' }}>Disable 2FA</button>
              </div>
            </div>
          )}
        </div>
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
EOF

# ---------- frontend/src/pages/Admin.jsx (updated with SMTP tab) ----------
cat > frontend/src/pages/Admin.jsx << 'EOF'
import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

function AdminDomainsInline({ api, showToast }) {
  const [domains, setDomains] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')

  const load = () => {
    api.get('/api/domains/admin/all').then(r => {
      setDomains(Array.isArray(r.data) ? r.data : [])
      setLoading(false)
    }).catch(() => setLoading(false))
  }
  useEffect(load, [])

  const deleteDomain = (id) => {
    if (!confirm('Delete this domain record?')) return
    api.delete(`/api/domains/admin/domain/${id}`).then(() => { showToast('🗑 Domain deleted'); load() })
  }

  const filtered = domains.filter(d => {
    const matchSearch = !search || d.domain.includes(search) || (d.user_email||'').includes(search) || (d.user_slug||'').includes(search)
    const matchFilter = filter === 'all' || (filter === 'verified' && d.is_verified) || (filter === 'pending' && !d.is_verified) || (filter === 'enabled' && d.can_use_custom_domain) || (filter === 'disabled' && !d.can_use_custom_domain)
    return matchSearch && matchFilter
  })

  const counts = {
    all: domains.length,
    verified: domains.filter(d => d.is_verified).length,
    pending: domains.filter(d => !d.is_verified).length,
    enabled: domains.filter(d => d.can_use_custom_domain).length,
    disabled: domains.filter(d => !d.can_use_custom_domain).length,
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: '.5rem', marginBottom: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <input className="input" placeholder="🔍 Search domain, email or slug…" value={search} onChange={e => setSearch(e.target.value)} style={{ minWidth: 220 }} />
        <div style={{ display: 'flex', gap: '.35rem', flexWrap: 'wrap' }}>
          {[['all','All'],['verified','✅ Verified'],['pending','⏳ Pending'],['enabled','🔓 Enabled'],['disabled','🔒 Disabled']].map(([k,l]) => (
            <button key={k} onClick={() => setFilter(k)}
              style={{ padding: '.3rem .75rem', borderRadius: 8, border: '1px solid var(--border)', cursor: 'pointer', fontSize: '.8rem',
                background: filter === k ? 'var(--primary)' : 'transparent', color: filter === k ? '#fff' : 'inherit' }}>
              {l} <span style={{ opacity: .7 }}>({counts[k]})</span>
            </button>
          ))}
        </div>
      </div>
      <div className="glass" style={{ padding: '1rem', overflowX: 'auto' }}>
        {loading && <p>Loading…</p>}
        {!loading && filtered.length === 0 && <p style={{ opacity: .6, padding: '.5rem' }}>No domains found.</p>}
        {!loading && filtered.length > 0 && (
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '.875rem' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border)' }}>
                {['User', 'Domain', 'Root Redirect', '404 Redirect', 'DNS', 'Access', 'Actions'].map(h => (
                  <th key={h} style={{ padding: '.5rem .75rem', textAlign: 'left', fontSize: '.78rem', color: 'var(--text-muted)', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(d => (
                <tr key={d.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '.55rem .75rem' }}>
                    <div style={{ fontSize: '.85rem', fontWeight: 500 }}>{d.user_email || '—'}</div>
                    {d.user_slug && <div style={{ fontSize: '.75rem', opacity: .5, fontFamily: 'monospace' }}>@{d.user_slug}</div>}
                  </td>
                  <td style={{ padding: '.55rem .75rem', fontFamily: 'monospace', fontSize: '.85rem' }}>{d.domain}</td>
                  <td style={{ padding: '.55rem .75rem', fontSize: '.78rem', opacity: .7, maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.root_redirect || <span style={{ opacity: .4 }}>—</span>}</td>
                  <td style={{ padding: '.55rem .75rem', fontSize: '.78rem', opacity: .7, maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.not_found_redirect || <span style={{ opacity: .4 }}>—</span>}</td>
                  <td style={{ padding: '.55rem .75rem' }}>
                    <span style={{ padding: '2px 8px', borderRadius: 99, fontSize: '.75rem', fontWeight: 600,
                      background: d.is_verified ? '#10b98120' : '#f59e0b20',
                      color: d.is_verified ? '#10b981' : '#f59e0b' }}>
                      {d.is_verified ? '✅ Live' : '⏳ Pending'}
                    </span>
                  </td>
                  <td style={{ padding: '.55rem .75rem' }}>
                    <span style={{ padding: '2px 8px', borderRadius: 99, fontSize: '.75rem', fontWeight: 600,
                      background: d.can_use_custom_domain ? '#6366f120' : 'var(--surface2)',
                      color: d.can_use_custom_domain ? 'var(--primary)' : 'var(--text-muted)' }}>
                      {d.can_use_custom_domain ? '🔓 Enabled' : '🔒 Disabled'}
                    </span>
                  </td>
                  <td style={{ padding: '.55rem .75rem' }}>
                    <button onClick={() => deleteDomain(d.id)}
                      style={{ padding: '.25rem .6rem', borderRadius: 6, border: 'none', background: '#ef444420', color: '#ef4444', cursor: 'pointer', fontSize: '.78rem' }}>
                      🗑 Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

export default function Admin() {
  const navigate = useNavigate()
  const [tab, setTab] = useState('users')
  const [users, setUsers] = useState([])
  const [links, setLinks] = useState([])
  const [settings, setSettings] = useState([])
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState(null)
  const [editKey, setEditKey] = useState(null)
  const [editVal, setEditVal] = useState('')
  const [editingUser, setEditingUser] = useState(null)
  const [userForm, setUserForm] = useState({ email: '', role: '', is_active: true, is_banned: false, is_suspended: false })

  useEffect(() => {
    Promise.all([
      api.get('/api/admin/users'),
      api.get('/api/admin/links'),
      api.get('/api/admin/settings')
    ])
      .then(([u, l, s]) => {
        setUsers(u.data)
        setLinks(l.data)
        setSettings(s.data)
      })
      .catch(() => setToast({ message: 'Failed to load', type: 'error' }))
      .finally(() => setLoading(false))
  }, [])

  const impersonate = async (id) => {
    try {
      const { data } = await api.post(`/api/admin/users/${id}/impersonate`)
      localStorage.setItem('token', data.access_token)
      localStorage.setItem('refresh', data.refresh_token)
      window.location.href = '/dashboard'
    } catch {
      setToast({ message: 'Failed', type: 'error' })
    }
  }

  const banUser = async (id) => {
    if (!confirm('Ban this user?')) return
    try {
      await api.post(`/api/admin/users/${id}/ban`)
      setToast({ message: 'User banned', type: 'success' })
      setUsers(users.map(u => u.id === id ? { ...u, is_banned: true, is_active: false } : u))
    } catch {
      setToast({ message: 'Failed', type: 'error' })
    }
  }

  const unbanUser = async (id) => {
    try {
      await api.post(`/api/admin/users/${id}/unban`)
      setToast({ message: 'User unbanned', type: 'success' })
      setUsers(users.map(u => u.id === id ? { ...u, is_banned: false, is_active: true } : u))
    } catch {
      setToast({ message: 'Failed', type: 'error' })
    }
  }

  const suspendUser = async (id) => {
    try {
      await api.post(`/api/admin/users/${id}/suspend`)
      setToast({ message: 'User suspended', type: 'success' })
      setUsers(users.map(u => u.id === id ? { ...u, is_suspended: true } : u))
    } catch {
      setToast({ message: 'Failed', type: 'error' })
    }
  }

  const unsuspendUser = async (id) => {
    try {
      await api.post(`/api/admin/users/${id}/unsuspend`)
      setToast({ message: 'User unsuspended', type: 'success' })
      setUsers(users.map(u => u.id === id ? { ...u, is_suspended: false } : u))
    } catch {
      setToast({ message: 'Failed', type: 'error' })
    }
  }

  const changeRole = async (id, role) => {
    try {
      await api.post(`/api/admin/users/${id}/role?role=${role}`)
      setToast({ message: `Role changed to ${role}`, type: 'success' })
      setUsers(users.map(u => u.id === id ? { ...u, role } : u))
    } catch {
      setToast({ message: 'Failed', type: 'error' })
    }
  }

  const toggleDomain = async (u) => {
    const endpoint = u.can_use_custom_domain
      ? `/api/domains/admin/revoke/${u.id}`
      : `/api/domains/admin/grant/${u.id}`
    try {
      await api.put(endpoint)
      setToast({ message: u.can_use_custom_domain ? '🔒 Domain access revoked' : '✅ Domain access granted', type: 'success' })
      setUsers(users.map(x => x.id === u.id ? { ...x, can_use_custom_domain: !x.can_use_custom_domain } : x))
    } catch {
      setToast({ message: 'Failed to update domain access', type: 'error' })
    }
  }

  const openEditUser = (user) => {
    setEditingUser(user)
    setUserForm({
      email: user.email,
      role: user.role,
      is_active: user.is_active,
      is_banned: user.is_banned,
      is_suspended: user.is_suspended
    })
  }

  const saveUserEdit = async (e) => {
    e.preventDefault()
    if (!editingUser) return
    try {
      await api.put(`/api/admin/users/${editingUser.id}`, userForm)
      setToast({ message: 'User updated', type: 'success' })
      setEditingUser(null)
      const res = await api.get('/api/admin/users')
      setUsers(res.data)
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Update failed', type: 'error' })
    }
  }

  const delUser = async (id) => {
    if (!confirm('Delete user?')) return
    try {
      await api.delete(`/api/admin/users/${id}`)
      setToast({ message: 'Deleted', type: 'success' })
      setUsers(users.filter(u => u.id !== id))
    } catch {
      setToast({ message: 'Failed', type: 'error' })
    }
  }

  const delLink = async (id) => {
    if (!confirm('Delete link?')) return
    try {
      await api.delete(`/api/admin/links/${id}`)
      setToast({ message: 'Deleted', type: 'success' })
      setLinks(links.filter(l => l.id !== id))
    } catch {
      setToast({ message: 'Failed', type: 'error' })
    }
  }

  const saveSetting = async (key) => {
    try {
      await api.put(`/api/admin/settings/${key}`, { value: editVal })
      setSettings(settings.map(s => s.key === key ? { ...s, value: editVal } : s))
      setToast({ message: `"${key}" saved`, type: 'success' })
      setEditKey(null)
    } catch {
      setToast({ message: 'Failed', type: 'error' })
    }
  }

  if (loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>

  const tabs = [
    ['users', '👥 Users'],
    ['links', '🔗 Links'],
    ['site settings', '⚙️ Settings'],
    ['nav', '🧭 Navigation'],
    ['pages', '📄 Pages'],
    ['email-templates', '📧 Email Templates'],
    ['smtp', '📨 SMTP'],
    ['stats', '📊 Statistics'],
    ['reports', '🚩 Reports'],
    ['files', '🗂️ Files'],
    ['domains', '🌐 Domains']
  ]

  return (
    <div>
      <Navbar />
      <main style={{ padding: '2rem', maxWidth: 1200, margin: '0 auto' }}>
        <h1 style={{ marginBottom: '1.5rem' }}>👑 Admin Dashboard</h1>
        <div style={{ display: 'flex', gap: '.5rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--border)', paddingBottom: '1rem', flexWrap: 'wrap' }}>
          {tabs.map(([t, l]) => (
            <button key={t} className={`btn ${tab === t ? '' : 'btn-outline'}`} onClick={() => setTab(t)} style={{ fontSize: '.875rem' }}>{l}</button>
          ))}
        </div>

        {tab === 'users' && (
          <div className="glass" style={{ padding: '1rem', overflowX: 'auto' }}>
            <h3 style={{ marginBottom: '1rem' }}>Users ({users.length})</h3>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--border)' }}>
                  {['ID', 'Email', 'Role', 'Active', 'Banned', 'Suspended', 'Domain', 'Actions'].map(h => <th key={h} style={{ padding: '.5rem .75rem', textAlign: 'left', fontSize: '.8rem', color: 'var(--text-muted)' }}>{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '.5rem .75rem', fontSize: '.85rem' }}>{u.id}</td>
                    <td style={{ padding: '.5rem .75rem', fontSize: '.85rem' }}>{u.email}</td>
                    <td style={{ padding: '.5rem .75rem' }}>
                      <select value={u.role} onChange={(e) => changeRole(u.id, e.target.value)} style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: '4px', padding: '2px 4px' }}>
                        <option value="user">User</option>
                        <option value="moderator">Moderator</option>
                        <option value="admin">Admin</option>
                      </select>
                    </td>
                    <td style={{ padding: '.5rem .75rem' }}>{u.is_active ? '✅' : '❌'}</td>
                    <td style={{ padding: '.5rem .75rem' }}>{u.is_banned ? '✅' : ''}</td>
                    <td style={{ padding: '.5rem .75rem' }}>{u.is_suspended ? '✅' : ''}</td>
                    <td style={{ padding: '.5rem .75rem' }}>
                      {u.role !== 'admin' && (
                        <label style={{ display: 'flex', alignItems: 'center', gap: '.4rem', cursor: 'pointer' }}>
                          <div onClick={() => toggleDomain(u)} style={{
                            width: 36, height: 20, borderRadius: 10, transition: '.2s',
                            background: u.can_use_custom_domain ? 'var(--primary)' : 'var(--border)',
                            position: 'relative', cursor: 'pointer', flexShrink: 0
                          }}>
                            <div style={{
                              position: 'absolute', top: 2, left: u.can_use_custom_domain ? 18 : 2,
                              width: 16, height: 16, borderRadius: '50%', background: '#fff', transition: '.2s'
                            }} />
                          </div>
                          <span style={{ fontSize: '.75rem', opacity: .7 }}>{u.can_use_custom_domain ? 'On' : 'Off'}</span>
                        </label>
                      )}
                    </td>
                    <td style={{ padding: '.5rem .75rem', display: 'flex', gap: '.25rem', flexWrap: 'wrap' }}>
                      <button className="btn btn-outline" style={{ fontSize: '.78rem', padding: '.35rem .7rem' }} onClick={() => impersonate(u.id)}>Login As</button>
                      {u.role !== 'admin' && (
                        <>
                          <button className="btn btn-outline" style={{ fontSize: '.78rem', padding: '.35rem .7rem' }} onClick={() => openEditUser(u)}>✏️ Edit</button>
                          {u.is_banned ? (
                            <button className="btn btn-outline" style={{ fontSize: '.78rem', padding: '.35rem .7rem' }} onClick={() => unbanUser(u.id)}>Unban</button>
                          ) : (
                            <button className="btn btn-outline" style={{ fontSize: '.78rem', padding: '.35rem .7rem' }} onClick={() => banUser(u.id)}>Ban</button>
                          )}
                          {u.is_suspended ? (
                            <button className="btn btn-outline" style={{ fontSize: '.78rem', padding: '.35rem .7rem' }} onClick={() => unsuspendUser(u.id)}>Unsuspend</button>
                          ) : (
                            <button className="btn btn-outline" style={{ fontSize: '.78rem', padding: '.35rem .7rem' }} onClick={() => suspendUser(u.id)}>Suspend</button>
                          )}
                          <button className="btn btn-danger" style={{ fontSize: '.78rem', padding: '.35rem .7rem' }} onClick={() => delUser(u.id)}>Delete</button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {editingUser && (
              <div style={{ marginTop: '2rem', padding: '1.5rem', background: 'var(--surface2)', borderRadius: 'var(--radius)' }}>
                <h4>Edit User</h4>
                <form onSubmit={saveUserEdit} style={{ display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fit, minmax(200px,1fr))' }}>
                  <input className="input" placeholder="Email" value={userForm.email} onChange={e => setUserForm({...userForm, email: e.target.value})} required />
                  <select className="input" value={userForm.role} onChange={e => setUserForm({...userForm, role: e.target.value})}>
                    <option value="user">User</option>
                    <option value="moderator">Moderator</option>
                    <option value="admin">Admin</option>
                  </select>
                  <label><input type="checkbox" checked={userForm.is_active} onChange={e => setUserForm({...userForm, is_active: e.target.checked})} /> Active</label>
                  <label><input type="checkbox" checked={userForm.is_banned} onChange={e => setUserForm({...userForm, is_banned: e.target.checked})} /> Banned</label>
                  <label><input type="checkbox" checked={userForm.is_suspended} onChange={e => setUserForm({...userForm, is_suspended: e.target.checked})} /> Suspended</label>
                  <div style={{ gridColumn: '1 / -1', display: 'flex', gap: '.5rem' }}>
                    <button type="submit" className="btn">Save</button>
                    <button type="button" className="btn btn-outline" onClick={() => setEditingUser(null)}>Cancel</button>
                  </div>
                </form>
              </div>
            )}
          </div>
        )}

        {tab === 'links' && (
          <div className="glass" style={{ padding: '1rem', overflowX: 'auto' }}>
            <h3 style={{ marginBottom: '1rem' }}>All Links ({links.length})</h3>
            {links.length === 0 ? <p style={{ color: 'var(--text-muted)' }}>No links yet</p> : (
              links.map(l => (
                <div key={l.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '.5rem', borderBottom: '1px solid var(--border)', gap: '.5rem', flexWrap: 'wrap' }}>
                  <span style={{ fontFamily: 'monospace', fontSize: '.85rem' }}>/s/{l.short_code} → {l.original_url.substring(0, 50)}{l.original_url.length > 50 ? '…' : ''}</span>
                  <button className="btn btn-danger" style={{ fontSize: '.78rem', padding: '.35rem .7rem' }} onClick={() => delLink(l.id)}>Delete</button>
                </div>
              ))
            )}
          </div>
        )}

        {tab === 'site settings' && (
          <div className="glass" style={{ padding: '1.5rem' }}>
            <h3 style={{ marginBottom: '.5rem' }}>Site Settings</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '.8rem', marginBottom: '1rem' }}>Changes apply on next page load.</p>
            <div style={{ display: 'grid', gap: '.75rem' }}>
              {settings.map(s => (
                <div key={s.key} style={{ padding: '1rem', background: 'var(--surface2)', borderRadius: '.5rem', border: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', flexWrap: 'wrap' }}>
                    <div style={{ flex: 1 }}>
                      <code style={{ fontWeight: 600, color: 'var(--primary)', fontSize: '.875rem' }}>{s.key}</code>
                      {editKey === s.key ? (
                        <div style={{ display: 'flex', gap: '.5rem', marginTop: '.5rem', flexWrap: 'wrap' }}>
                          <input className="input" value={editVal} onChange={e => setEditVal(e.target.value)} style={{ flex: 1, minWidth: 180 }} autoFocus />
                          <button className="btn" onClick={() => saveSetting(s.key)} style={{ fontSize: '.875rem' }}>Save</button>
                          <button className="btn btn-outline" onClick={() => setEditKey(null)} style={{ fontSize: '.875rem' }}>Cancel</button>
                        </div>
                      ) : (
                        <p style={{ marginTop: '.25rem', color: 'var(--text-muted)', fontSize: '.875rem' }}>{s.value || <em>empty</em>}</p>
                      )}
                    </div>
                    {editKey !== s.key && <button className="btn btn-outline" onClick={() => { setEditKey(s.key); setEditVal(s.value || ''); }} style={{ fontSize: '.8rem', padding: '.4rem .75rem' }}>✏️ Edit</button>}
                  </div>
                </div>
              ))}
              {settings.length === 0 && <p style={{ color: 'var(--text-muted)' }}>No settings yet.</p>}
            </div>
          </div>
        )}

        {tab === 'nav' && (
          <div className="glass" style={{ padding: '2rem', textAlign: 'center' }}>
            <h3>Navigation Manager</h3>
            <p style={{ margin: '1rem 0' }}>Manage navbar items.</p>
            <button className="btn" onClick={() => navigate('/admin/nav')}>Go to Nav Manager</button>
          </div>
        )}

        {tab === 'pages' && (
          <div className="glass" style={{ padding: '2rem', textAlign: 'center' }}>
            <h3>Pages Manager</h3>
            <p style={{ margin: '1rem 0' }}>Manage custom pages.</p>
            <button className="btn" onClick={() => navigate('/admin/pages')}>Go to Pages Manager</button>
          </div>
        )}

        {tab === 'email-templates' && (
          <div className="glass" style={{ padding: '2rem', textAlign: 'center' }}>
            <h3>Email Templates</h3>
            <p style={{ margin: '1rem 0' }}>Manage email templates.</p>
            <button className="btn" onClick={() => navigate('/admin/email-templates')}>Go to Email Templates</button>
          </div>
        )}

        {tab === 'smtp' && (
          <div className="glass" style={{ padding: '2rem', textAlign: 'center' }}>
            <h3>SMTP Settings</h3>
            <p style={{ margin: '1rem 0' }}>Configure outgoing email server.</p>
            <button className="btn" onClick={() => navigate('/admin/smtp')}>Go to SMTP Settings</button>
          </div>
        )}

        {tab === 'stats' && (
          <div className="glass" style={{ padding: '2rem', textAlign: 'center' }}>
            <h3>Statistics Dashboard</h3>
            <p style={{ margin: '1rem 0' }}>View platform-wide analytics: users, clicks, profile views, messages, and reports.</p>
            <button className="btn" onClick={() => navigate('/admin/stats')}>Go to Statistics</button>
          </div>
        )}

        {tab === 'reports' && (
          <div className="glass" style={{ padding: '2rem', textAlign: 'center' }}>
            <h3>Reports Dashboard</h3>
            <p style={{ margin: '1rem 0' }}>Review, dismiss, or act on reported profiles.</p>
            <button className="btn" onClick={() => navigate('/admin/reports')}>Go to Reports</button>
          </div>
        )}

        {tab === 'files' && (
          <div className="glass" style={{ padding: '2rem', textAlign: 'center' }}>
            <h3>File Upload Manager</h3>
            <p style={{ margin: '1rem 0' }}>Upload and manage site asset files (images, documents, etc.).</p>
            <button className="btn" onClick={() => navigate('/admin/files')}>Go to File Manager</button>
          </div>
        )}

        {tab === 'domains' && <AdminDomainsInline api={api} showToast={(m,t) => setToast({message:m,type:t||'success'})} />}
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
EOF

# ---------- frontend/src/pages/AdminSmtp.jsx ----------
cat > frontend/src/pages/AdminSmtp.jsx << 'EOF'
import { useState, useEffect } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

export default function AdminSmtp() {
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [toast, setToast] = useState(null)
  const [settings, setSettings] = useState({
    host: '',
    port: 25,
    user: '',
    password: '',
    use_tls: false
  })
  const [testEmail, setTestEmail] = useState('')

  useEffect(() => {
    fetchSettings()
  }, [])

  const fetchSettings = async () => {
    try {
      const res = await api.get('/api/admin/smtp-settings')
      setSettings(res.data)
    } catch {
      setToast({ message: 'Failed to load SMTP settings', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSaving(true)
    try {
      await api.put('/api/admin/smtp-settings', settings)
      setToast({ message: 'SMTP settings saved', type: 'success' })
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Save failed', type: 'error' })
    } finally {
      setSaving(false)
    }
  }

  const handleTest = async () => {
    if (!testEmail) {
      setToast({ message: 'Please enter a test email address', type: 'error' })
      return
    }
    setTesting(true)
    try {
      await api.post('/api/admin/test-email', { to_email: testEmail })
      setToast({ message: 'Test email sent!', type: 'success' })
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Test failed', type: 'error' })
    } finally {
      setTesting(false)
    }
  }

  if (loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>

  return (
    <div>
      <Navbar />
      <main style={{ maxWidth: 600, margin: '0 auto', padding: '2rem' }}>
        <div className="glass" style={{ padding: '2rem' }}>
          <h2 style={{ marginBottom: '1.5rem' }}>📨 SMTP Settings</h2>
          <form onSubmit={handleSubmit} style={{ display: 'grid', gap: '1rem' }}>
            <div>
              <label style={{ display: 'block', marginBottom: '.5rem', fontWeight: 500 }}>SMTP Host</label>
              <input
                className="input"
                type="text"
                value={settings.host}
                onChange={e => setSettings({ ...settings, host: e.target.value })}
                required
              />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: '.5rem', fontWeight: 500 }}>Port</label>
              <input
                className="input"
                type="number"
                value={settings.port}
                onChange={e => setSettings({ ...settings, port: parseInt(e.target.value) || 25 })}
                required
              />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: '.5rem', fontWeight: 500 }}>Username (optional)</label>
              <input
                className="input"
                type="text"
                value={settings.user}
                onChange={e => setSettings({ ...settings, user: e.target.value })}
              />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: '.5rem', fontWeight: 500 }}>Password (optional)</label>
              <input
                className="input"
                type="password"
                value={settings.password}
                onChange={e => setSettings({ ...settings, password: e.target.value })}
              />
            </div>
            <label style={{ display: 'flex', alignItems: 'center', gap: '.5rem', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={settings.use_tls}
                onChange={e => setSettings({ ...settings, use_tls: e.target.checked })}
              />
              <span>Use TLS</span>
            </label>
            <button type="submit" className="btn" disabled={saving}>
              {saving ? 'Saving...' : 'Save Settings'}
            </button>
          </form>

          <hr style={{ margin: '2rem 0', borderColor: 'var(--border)' }} />

          <h3 style={{ marginBottom: '1rem' }}>Send Test Email</h3>
          <div style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap' }}>
            <input
              className="input"
              style={{ flex: 1 }}
              type="email"
              placeholder="Your email address"
              value={testEmail}
              onChange={e => setTestEmail(e.target.value)}
            />
            <button className="btn btn-outline" onClick={handleTest} disabled={testing}>
              {testing ? 'Sending...' : 'Send Test'}
            </button>
          </div>
        </div>
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
EOF

# ---------- frontend/src/pages/AdminEmailTemplates.jsx ----------
cat > frontend/src/pages/AdminEmailTemplates.jsx << 'EOF'
import { useState, useEffect } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

export default function AdminEmailTemplates() {
  const [templates, setTemplates] = useState([])
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState(null)
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState({ key: '', subject: '', body_html: '', body_text: '', enabled: true, for_admin: false })
  const [testEmail, setTestEmail] = useState({ to: '', template_key: '', context: '{}' })
  const [sendingTest, setSendingTest] = useState(false)

  useEffect(() => { fetchTemplates() }, [])

  const fetchTemplates = async () => {
    try {
      const res = await api.get('/api/admin/email-templates')
      setTemplates(res.data)
    } catch {
      setToast({ message: 'Failed to load templates', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    try {
      if (editing) {
        await api.put(`/api/admin/email-templates/${form.key}`, form)
        setToast({ message: 'Template updated', type: 'success' })
      } else {
        await api.post('/api/admin/email-templates', form)
        setToast({ message: 'Template created', type: 'success' })
      }
      setEditing(null)
      setForm({ key: '', subject: '', body_html: '', body_text: '', enabled: true, for_admin: false })
      fetchTemplates()
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Save failed', type: 'error' })
    }
  }

  const handleEdit = (tmpl) => {
    setEditing(tmpl)
    setForm({ ...tmpl })
  }

  const handleDelete = async (key) => {
    if (!confirm('Delete this template?')) return
    try {
      await api.delete(`/api/admin/email-templates/${key}`)
      setToast({ message: 'Deleted', type: 'success' })
      fetchTemplates()
    } catch {
      setToast({ message: 'Delete failed', type: 'error' })
    }
  }

  const sendTest = async (e) => {
    e.preventDefault()
    setSendingTest(true)
    try {
      let context = {}
      try { context = JSON.parse(testEmail.context) } catch { context = {} }
      await api.post('/api/admin/email-templates/test', {
        to_email: testEmail.to,
        template_key: testEmail.template_key,
        context
      })
      setToast({ message: 'Test email sent', type: 'success' })
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Failed to send', type: 'error' })
    } finally {
      setSendingTest(false)
    }
  }

  if (loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>

  return (
    <div>
      <Navbar />
      <main style={{ padding: '2rem', maxWidth: 1000, margin: '0 auto' }}>
        <h1 style={{ marginBottom: '1.5rem' }}>📧 Email Templates</h1>

        <div className="glass" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
          <h2 style={{ marginBottom: '1rem' }}>{editing ? 'Edit' : 'Create'} Template</h2>
          <form onSubmit={handleSubmit} style={{ display: 'grid', gap: '1rem' }}>
            <input className="input" placeholder="Key (e.g. welcome_email)" value={form.key} onChange={e => setForm({ ...form, key: e.target.value })} required disabled={editing} />
            <input className="input" placeholder="Subject" value={form.subject} onChange={e => setForm({ ...form, subject: e.target.value })} required />
            <textarea className="input" rows="4" placeholder="HTML Body (optional)" value={form.body_html} onChange={e => setForm({ ...form, body_html: e.target.value })} />
            <textarea className="input" rows="4" placeholder="Text Body (optional)" value={form.body_text} onChange={e => setForm({ ...form, body_text: e.target.value })} />
            <div style={{ display: 'flex', gap: '2rem', alignItems: 'center' }}>
              <label><input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} /> Enabled</label>
              <label><input type="checkbox" checked={form.for_admin} onChange={e => setForm({ ...form, for_admin: e.target.checked })} /> For Admin (internal use)</label>
            </div>
            <div style={{ display: 'flex', gap: '.5rem' }}>
              <button type="submit" className="btn">{editing ? 'Update' : 'Create'}</button>
              {editing && <button type="button" className="btn btn-outline" onClick={() => { setEditing(null); setForm({ key: '', subject: '', body_html: '', body_text: '', enabled: true, for_admin: false }); }}>Cancel</button>}
            </div>
          </form>
        </div>

        <div className="glass" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
          <h2 style={{ marginBottom: '1rem' }}>Send Test Email</h2>
          <form onSubmit={sendTest} style={{ display: 'grid', gap: '1rem' }}>
            <input className="input" placeholder="To Email" value={testEmail.to} onChange={e => setTestEmail({...testEmail, to: e.target.value})} required />
            <select className="input" value={testEmail.template_key} onChange={e => setTestEmail({...testEmail, template_key: e.target.value})} required>
              <option value="">Select template</option>
              {templates.map(t => <option key={t.key} value={t.key}>{t.key}</option>)}
            </select>
            <textarea className="input" rows="3" placeholder='Context JSON (e.g. {"name":"John"})' value={testEmail.context} onChange={e => setTestEmail({...testEmail, context: e.target.value})} />
            <button type="submit" className="btn" disabled={sendingTest}>{sendingTest ? 'Sending...' : 'Send Test'}</button>
          </form>
        </div>

        <div className="glass" style={{ padding: '1rem' }}>
          <h3 style={{ marginBottom: '1rem' }}>Existing Templates</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr><th>Key</th><th>Subject</th><th>Enabled</th><th>For Admin</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {templates.map(t => (
                <tr key={t.key} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '.5rem' }}><code>{t.key}</code></td>
                  <td style={{ padding: '.5rem' }}>{t.subject}</td>
                  <td style={{ padding: '.5rem' }}>{t.enabled ? '✅' : '❌'}</td>
                  <td style={{ padding: '.5rem' }}>{t.for_admin ? '✅' : ''}</td>
                  <td style={{ padding: '.5rem', display: 'flex', gap: '.25rem' }}>
                    <button className="btn btn-outline" onClick={() => handleEdit(t)}>✏️</button>
                    <button className="btn btn-danger" onClick={() => handleDelete(t.key)}>🗑️</button>
                  </td>
                </tr>
              ))}
              {templates.length === 0 && <tr><td colSpan="5" style={{ padding: '1rem', textAlign: 'center' }}>No templates yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
EOF

# ---------- frontend/src/pages/AdminNav.jsx ----------
cat > frontend/src/pages/AdminNav.jsx << 'EOF'
import { useState, useEffect } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

function isExternal(val) { return /^https?:\/\//i.test(val) }

export default function AdminNav() {
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState(null)
  const [editingId, setEditingId] = useState(null)
  const [form, setForm] = useState({ label: '', path: '', icon: '', auth_required: false, admin_only: false, enabled: true, order: 0 })

  useEffect(() => { fetchItems() }, [])

  const fetchItems = async () => {
    try {
      const res = await api.get('/api/admin/nav')
      setItems(res.data)
    } catch {
      setToast({ message: 'Failed to load', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    try {
      if (editingId) {
        await api.put(`/api/admin/nav/${editingId}`, form)
        setToast({ message: 'Updated', type: 'success' })
      } else {
        await api.post('/api/admin/nav', form)
        setToast({ message: 'Created', type: 'success' })
      }
      setEditingId(null)
      setForm({ label: '', path: '', icon: '', auth_required: false, admin_only: false, enabled: true, order: 0 })
      fetchItems()
    } catch {
      setToast({ message: 'Save failed', type: 'error' })
    }
  }

  const handleEdit = (item) => {
    setEditingId(item.id)
    setForm({ ...item })
  }

  const handleDelete = async (id) => {
    if (!confirm('Delete?')) return
    try {
      await api.delete(`/api/admin/nav/${id}`)
      setToast({ message: 'Deleted', type: 'success' })
      fetchItems()
    } catch {
      setToast({ message: 'Delete failed', type: 'error' })
    }
  }

  const toggleEnabled = async (item) => {
    try {
      await api.put(`/api/admin/nav/${item.id}`, { enabled: !item.enabled })
      fetchItems()
    } catch {
      setToast({ message: 'Toggle failed', type: 'error' })
    }
  }

  const external = isExternal(form.path)

  if (loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>

  return (
    <div>
      <Navbar />
      <main style={{ padding: '2rem', maxWidth: 1000, margin: '0 auto' }}>
        <h1 style={{ marginBottom: '.5rem' }}>⚙️ Navigation Manager</h1>
        <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem', fontSize: '.875rem' }}>
          Manage navbar links. Use an internal path like <code>/dashboard</code> to link within the site,
          or a full URL like <code>https://example.com</code> to link anywhere — external links open in a new tab.
        </p>

        <div className="glass" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
          <h2 style={{ marginBottom: '1rem' }}>{editingId ? 'Edit' : 'Add'} Nav Item</h2>
          <form onSubmit={handleSubmit} style={{ display: 'grid', gap: '1rem' }}>
            <div style={{ display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fit, minmax(200px,1fr))' }}>
              <div>
                <label style={{ display: 'block', marginBottom: '.35rem', fontWeight: 500, fontSize: '.875rem' }}>Label *</label>
                <input className="input" placeholder="e.g. Contact Us" value={form.label} onChange={e => setForm({ ...form, label: e.target.value })} required />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '.35rem', fontWeight: 500, fontSize: '.875rem' }}>
                  URL / Path *
                  {external ? <span style={{ marginLeft: '.5rem', fontSize: '.75rem', color: 'var(--success)', fontWeight: 400 }}>🌐 External link — opens in new tab</span> : form.path ? <span style={{ marginLeft: '.5rem', fontSize: '.75rem', color: 'var(--primary)', fontWeight: 400 }}>🔗 Internal route</span> : null}
                </label>
                <input className="input" placeholder="e.g. /dashboard  or  https://example.com" value={form.path} onChange={e => setForm({ ...form, path: e.target.value })} required />
                <p style={{ fontSize: '.72rem', color: 'var(--text-muted)', marginTop: '.3rem' }}>Internal path <code>/page-slug</code> or full URL <code>https://…</code></p>
              </div>
            </div>
            <div style={{ display: 'grid', gap: '1rem', gridTemplateColumns: 'repeat(auto-fit, minmax(150px,1fr))' }}>
              <div>
                <label style={{ display: 'block', marginBottom: '.35rem', fontWeight: 500, fontSize: '.875rem' }}>Icon (emoji)</label>
                <input className="input" placeholder="🔗" value={form.icon} onChange={e => setForm({ ...form, icon: e.target.value })} />
              </div>
              <div>
                <label style={{ display: 'block', marginBottom: '.35rem', fontWeight: 500, fontSize: '.875rem' }}>Order</label>
                <input className="input" type="number" placeholder="0" value={form.order} onChange={e => setForm({ ...form, order: parseInt(e.target.value) || 0 })} />
              </div>
            </div>
            <div style={{ display: 'flex', gap: '1.5rem', alignItems: 'center', flexWrap: 'wrap', padding: '.75rem', background: 'var(--surface2)', borderRadius: 'var(--radius)' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '.4rem', cursor: 'pointer', fontSize: '.875rem' }}><input type="checkbox" checked={form.auth_required} onChange={e => setForm({ ...form, auth_required: e.target.checked })} /> Requires Login</label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '.4rem', cursor: 'pointer', fontSize: '.875rem' }}><input type="checkbox" checked={form.admin_only} onChange={e => setForm({ ...form, admin_only: e.target.checked })} /> Admin Only</label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '.4rem', cursor: 'pointer', fontSize: '.875rem' }}><input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} /> Enabled (visible in nav)</label>
            </div>
            <div style={{ display: 'flex', gap: '.5rem' }}>
              <button type="submit" className="btn">{editingId ? 'Update' : 'Create'}</button>
              {editingId && <button type="button" className="btn btn-outline" onClick={() => { setEditingId(null); setForm({ label: '', path: '', icon: '', auth_required: false, admin_only: false, enabled: true, order: 0 }); }}>Cancel</button>}
            </div>
          </form>
        </div>

        <div className="glass" style={{ padding: '1rem' }}>
          <h3 style={{ marginBottom: '1rem' }}>Current Nav Items ({items.length})</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border)' }}>
                {['Order', 'Label', 'URL / Path', 'Icon', 'Auth', 'Admin', 'Visible', 'Actions'].map(h => <th key={h} style={{ padding: '.5rem', textAlign: 'left', fontSize: '.8rem', color: 'var(--text-muted)' }}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {items.map(item => (
                <tr key={item.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '.5rem', fontSize: '.85rem' }}>{item.order}</td>
                  <td style={{ padding: '.5rem', fontWeight: 500 }}>{item.label}</td>
                  <td style={{ padding: '.5rem', maxWidth: 220 }}>
                    <code style={{ fontSize: '.78rem', wordBreak: 'break-all' }}>
                      {isExternal(item.path) ? '🌐 ' : ''}{item.path}
                    </code>
                  </td>
                  <td style={{ padding: '.5rem' }}>{item.icon}</td>
                  <td style={{ padding: '.5rem' }}>{item.auth_required ? '✅' : ''}</td>
                  <td style={{ padding: '.5rem' }}>{item.admin_only ? '👑' : ''}</td>
                  <td style={{ padding: '.5rem' }}>
                    <button className="btn btn-outline" style={{ padding: '.2rem .5rem', fontSize: '.8rem' }} onClick={() => toggleEnabled(item)}>{item.enabled ? '✅' : '❌'}</button>
                  </td>
                  <td style={{ padding: '.5rem', display: 'flex', gap: '.25rem' }}>
                    <button className="btn btn-outline" style={{ padding: '.2rem .5rem', fontSize: '.8rem' }} onClick={() => handleEdit(item)}>✏️</button>
                    {!item.is_system && <button className="btn btn-danger" style={{ padding: '.2rem .5rem', fontSize: '.8rem' }} onClick={() => handleDelete(item.id)}>🗑️</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
EOF

# ---------- frontend/src/pages/AdminPages.jsx ----------
cat > frontend/src/pages/AdminPages.jsx << 'EOF'
import { useState, useEffect } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

export default function AdminPages() {
  const [pages, setPages] = useState([])
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState(null)
  const [editingId, setEditingId] = useState(null)
  const [form, setForm] = useState({ title: '', slug: '', content: '', published: true, meta_title: '', meta_description: '', category: '', language: 'en', menu_visible: true })

  useEffect(() => { fetchPages() }, [])

  const fetchPages = async () => {
    try {
      const res = await api.get('/api/admin/pages')
      setPages(res.data)
    } catch {
      setToast({ message: 'Failed', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    try {
      if (editingId) {
        await api.put(`/api/admin/pages/${editingId}`, form)
        setToast({ message: 'Updated ✅', type: 'success' })
      } else {
        await api.post('/api/admin/pages', form)
        setToast({ message: 'Created ✅ — nav item auto-added', type: 'success' })
      }
      setEditingId(null)
      setForm({ title: '', slug: '', content: '', published: true, meta_title: '', meta_description: '', category: '', language: 'en', menu_visible: true })
      fetchPages()
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Save failed', type: 'error' })
    }
  }

  const handleEdit = (page) => {
    setEditingId(page.id)
    setForm({ ...page })
  }

  const handleDelete = async (id) => {
    if (!confirm('Delete page? Its nav item will also be removed.')) return
    try {
      await api.delete(`/api/admin/pages/${id}`)
      setToast({ message: 'Deleted', type: 'success' })
      fetchPages()
    } catch {
      setToast({ message: 'Delete failed', type: 'error' })
    }
  }

  const togglePublish = async (page) => {
    try {
      await api.put(`/api/admin/pages/${page.id}`, { published: !page.published })
      fetchPages()
    } catch {
      setToast({ message: 'Toggle failed', type: 'error' })
    }
  }

  if (loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>

  return (
    <div>
      <Navbar />
      <main style={{ padding: '2rem', maxWidth: 1000, margin: '0 auto' }}>
        <h1 style={{ marginBottom: '.5rem' }}>📄 Pages Manager</h1>
        <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem', fontSize: '.875rem' }}>
          Pages are accessible at <code>/p/slug</code> and automatically appear in Navigation Manager.
        </p>

        <div className="glass" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
          <h2 style={{ marginBottom: '1rem' }}>{editingId ? 'Edit' : 'Create'} Page</h2>
          <form onSubmit={handleSubmit} style={{ display: 'grid', gap: '1rem' }}>
            <input className="input" placeholder="Title" value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} required />
            <div>
              <div style={{ display: 'flex', gap: '.5rem', alignItems: 'center' }}>
                <span style={{ background: 'var(--surface2)', padding: '.75rem', borderRadius: 'var(--radius)', fontSize: '.8rem', fontFamily: 'monospace', whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>/p/</span>
                <input className="input" placeholder="contactus" value={form.slug} onChange={e => setForm({ ...form, slug: e.target.value })} required style={{ flex: 1 }} />
              </div>
              {form.slug && <p style={{ fontSize: '.75rem', color: 'var(--primary)', marginTop: '.35rem', fontFamily: 'monospace' }}>/p/{form.slug}</p>}
            </div>
            <textarea className="input" rows="10" placeholder="HTML Content" value={form.content} onChange={e => setForm({ ...form, content: e.target.value })} required />
            <details style={{ cursor: 'pointer' }}>
              <summary style={{ fontWeight: 600, marginBottom: '.75rem', color: 'var(--primary)' }}>🔍 SEO & Metadata (optional)</summary>
              <div style={{ display: 'grid', gap: '.75rem', marginTop: '.75rem' }}>
                <input className="input" placeholder="Meta Title (overrides page title in browser tab)" value={form.meta_title || ''} onChange={e => setForm({ ...form, meta_title: e.target.value })} />
                <textarea className="input" rows="2" placeholder="Meta Description (for search engine snippets)" value={form.meta_description || ''} onChange={e => setForm({ ...form, meta_description: e.target.value })} />
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '.75rem' }}>
                  <input className="input" placeholder="Category (e.g. Legal, Help)" value={form.category || ''} onChange={e => setForm({ ...form, category: e.target.value })} />
                  <input className="input" placeholder="Language (e.g. en, fr, de)" value={form.language || 'en'} onChange={e => setForm({ ...form, language: e.target.value })} />
                </div>
              </div>
            </details>
            <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '.5rem', cursor: 'pointer' }}>
                <input type="checkbox" checked={form.published} onChange={e => setForm({ ...form, published: e.target.checked })} /> Published
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '.5rem', cursor: 'pointer' }}>
                <input type="checkbox" checked={form.menu_visible !== false} onChange={e => setForm({ ...form, menu_visible: e.target.checked })} /> Show in Menu
              </label>
            </div>
            <div style={{ display: 'flex', gap: '.5rem' }}>
              <button type="submit" className="btn">{editingId ? 'Update' : 'Create'}</button>
              {editingId && <button type="button" className="btn btn-outline" onClick={() => { setEditingId(null); setForm({ title: '', slug: '', content: '', published: true, meta_title: '', meta_description: '', category: '', language: 'en', menu_visible: true }); }}>Cancel</button>}
            </div>
          </form>
        </div>

        <div className="glass" style={{ padding: '1rem' }}>
          <h3 style={{ marginBottom: '1rem' }}>Existing Pages</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border)' }}>
                {['Title', 'URL', 'Category', 'Lang', 'Published', 'Menu', 'Actions'].map(h => <th key={h} style={{ padding: '.5rem', textAlign: 'left', fontSize: '.8rem' }}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {pages.map(page => (
                <tr key={page.id} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '.5rem' }}>{page.title}</td>
                  <td style={{ padding: '.5rem' }}><code style={{ fontSize: '.8rem' }}>/p/{page.slug}</code></td>
                  <td style={{ padding: '.5rem', fontSize: '.8rem', opacity: .7 }}>{page.category || '—'}</td>
                  <td style={{ padding: '.5rem', fontSize: '.8rem', opacity: .7 }}>{page.language || 'en'}</td>
                  <td style={{ padding: '.5rem' }}>
                    <button className="btn btn-outline" style={{ padding: '.2rem .5rem', fontSize: '.8rem' }} onClick={() => togglePublish(page)}>
                      {page.published ? '✅ Published' : '❌ Hidden'}
                    </button>
                  </td>
                  <td style={{ padding: '.5rem', fontSize: '.8rem', opacity: .7 }}>{page.menu_visible !== false ? '✅' : '❌'}</td>
                  <td style={{ padding: '.5rem', display: 'flex', gap: '.25rem' }}>
                    <button className="btn btn-outline" style={{ padding: '.2rem .5rem', fontSize: '.8rem' }} onClick={() => handleEdit(page)}>✏️</button>
                    <button className="btn btn-danger" style={{ padding: '.2rem .5rem', fontSize: '.8rem' }} onClick={() => handleDelete(page.id)}>🗑️</button>
                    <a href={`/p/${page.slug}`} target="_blank" rel="noopener" className="btn btn-outline" style={{ padding: '.2rem .5rem', fontSize: '.8rem' }}>👁️</a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
EOF

# ---------- frontend/src/pages/Report.jsx ----------
cat > frontend/src/pages/Report.jsx << 'JSXEOF'
import { useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'

const REASONS = [
  'Spam or self-promotion', 'Hate speech or harassment',
  'Misleading content', 'Impersonation', 'Inappropriate content', 'Other'
]

export default function Report() {
  const [params] = useSearchParams()
  const slug = params.get('slug') || ''
  const [reason, setReason] = useState('')
  const [details, setDetails] = useState('')
  const [email, setEmail] = useState('')
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    if (!reason) return
    setLoading(true)
    try {
      await api.post('/api/public/report-profile', { slug, reason, details: details || null, reporter_email: email || null })
      setStatus('success')
    } catch (err) {
      setStatus('error: ' + (err.response?.data?.detail || 'Unknown error'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <Navbar />
      <div style={{ maxWidth: 480, margin: '3rem auto', padding: '1.5rem' }}>
        <div className="glass" style={{ padding: '2rem' }}>
          <h2 style={{ marginBottom: '.5rem' }}>🚩 Report Profile</h2>
          {slug && <p style={{ color: 'var(--text-muted)', fontSize: '.875rem', marginBottom: '1.5rem' }}>Reporting: <strong>@{slug}</strong></p>}

          {status === 'success' ? (
            <div style={{ textAlign: 'center', padding: '1.5rem' }}>
              <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>✅</div>
              <h3>Report Submitted</h3>
              <p style={{ color: 'var(--text-muted)', margin: '1rem 0' }}>Thank you. Our team will review it shortly.</p>
              <Link to="/" className="btn btn-outline">← Back to Home</Link>
            </div>
          ) : (
            <form onSubmit={submit} style={{ display: 'grid', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', fontWeight: 500, marginBottom: '.4rem' }}>Reason *</label>
                <select className="input" value={reason} onChange={e => setReason(e.target.value)} required>
                  <option value="">Select a reason…</option>
                  {REASONS.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
              <div>
                <label style={{ display: 'block', fontWeight: 500, marginBottom: '.4rem' }}>Additional Details</label>
                <textarea className="input" rows="4" value={details} onChange={e => setDetails(e.target.value)} placeholder="Describe the issue in more detail…" />
              </div>
              <div>
                <label style={{ display: 'block', fontWeight: 500, marginBottom: '.4rem' }}>Your Email (optional)</label>
                <input className="input" type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="For follow-up if needed" />
              </div>
              {status && status !== 'success' && (
                <div style={{ padding: '.75rem', background: '#fef2f2', borderRadius: 'var(--radius)', color: 'var(--danger)', fontSize: '.875rem' }}>❌ {status}</div>
              )}
              <button type="submit" className="btn" disabled={loading || !reason}>
                {loading ? 'Submitting…' : '🚩 Submit Report'}
              </button>
              <Link to={slug ? `/@${slug}` : '/'} style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '.875rem' }}>← Cancel</Link>
            </form>
          )}
        </div>
      </div>
    </div>
  )
}
JSXEOF

# ---------- frontend/src/pages/CustomPage.jsx ----------
cat > frontend/src/pages/CustomPage.jsx << 'EOF'
import { useState, useEffect, useRef } from 'react'
import { useParams, Link } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'

export default function CustomPage() {
  const { slug } = useParams()
  const [page, setPage] = useState(null)
  const [loading, setLoading] = useState(true)
  const contentRef = useRef(null)

  useEffect(() => {
    api.get(`/api/public/pages/${slug}`)
      .then(res => setPage(res.data))
      .catch(() => setPage(null))
      .finally(() => setLoading(false))
  }, [slug])

  useEffect(() => {
    if (!page || !contentRef.current) return
    const container = contentRef.current
    const scripts = container.querySelectorAll('script')
    scripts.forEach(oldScript => {
      const newScript = document.createElement('script')
      if (oldScript.src) {
        newScript.src = oldScript.src
      } else {
        newScript.textContent = oldScript.textContent
      }
      oldScript.remove()
      document.body.appendChild(newScript)
    })
  }, [page])

  if (loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>
  if (!page) return (
    <div><Navbar/>
      <div style={{padding:'2rem',textAlign:'center'}}>
        <h2>Page not found</h2>
        <Link to="/">← Home</Link>
      </div>
    </div>
  )

  return (
    <div>
      <Navbar/>
      <main style={{padding:'2rem',maxWidth:800,margin:'0 auto'}}>
        <div className="glass" style={{padding:'2rem'}}>
          <h1 style={{marginBottom:'1.5rem'}}>{page.title}</h1>
          <div ref={contentRef} dangerouslySetInnerHTML={{__html: page.content}} />
          <Link to="/" style={{display:'inline-block',marginTop:'2rem',color:'var(--primary)'}}>← Back to Home</Link>
        </div>
      </main>
    </div>
  )
}
EOF

# ---------- frontend/src/pages/AdminStats.jsx ----------
cat > frontend/src/pages/AdminStats.jsx << 'JSXEOF'
import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import Navbar from '../components/Navbar'

export default function AdminStats() {
  const token = localStorage.getItem('token')
  const API = import.meta.env.VITE_API_BASE_URL || ''
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    fetch(`${API}/api/admin/stats`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then(d => { setStats(d); setLoading(false) })
      .catch(() => { setError('Failed to load stats'); setLoading(false) })
  }, [])

  const cards = stats ? [
    { label: 'Total Users', value: stats.total_users, icon: '👥' },
    { label: 'Short Links', value: stats.total_links, icon: '🔗' },
    { label: 'Total Clicks', value: stats.total_clicks, icon: '🖱️' },
    { label: 'Profile Views', value: stats.total_profile_views, icon: '👁️' },
    { label: 'Messages', value: stats.total_messages, icon: '✉️' },
    { label: 'Total Reports', value: stats.total_reports, icon: '🚩' },
    { label: 'Pending Reports', value: stats.pending_reports, icon: '⚠️' },
  ] : []

  return (
    <div>
      <Navbar />
      <main style={{ padding: '2rem', maxWidth: 900, margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem' }}>
          <Link to="/admin" style={{ color: 'var(--primary)' }}>← Admin</Link>
          <h2 style={{ margin: 0 }}>📊 Statistics Dashboard</h2>
        </div>
        {loading && <p>Loading…</p>}
        {error && <p style={{ color: 'red' }}>{error}</p>}
        {stats && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '1rem' }}>
            {cards.map(c => (
              <div key={c.label} className="glass" style={{ padding: '1.5rem', textAlign: 'center', borderRadius: 12 }}>
                <div style={{ fontSize: '2rem', marginBottom: '.5rem' }}>{c.icon}</div>
                <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--primary)' }}>{c.value.toLocaleString()}</div>
                <div style={{ fontSize: '.85rem', opacity: .7, marginTop: '.25rem' }}>{c.label}</div>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  )
}
JSXEOF

# ---------- frontend/src/pages/AdminReports.jsx ----------
cat > frontend/src/pages/AdminReports.jsx << 'JSXEOF'
import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import Navbar from '../components/Navbar'

const STATUS_COLORS = { pending: '#f59e0b', reviewed: '#10b981', dismissed: '#6b7280' }

export default function AdminReports() {
  const token = localStorage.getItem('token')
  const API = import.meta.env.VITE_API_BASE_URL || ''
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')

  const load = () => {
    fetch(`${API}/api/admin/reports`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then(d => { setReports(Array.isArray(d) ? d : []); setLoading(false) })
  }
  useEffect(load, [])

  const updateStatus = (id, status) => {
    fetch(`${API}/api/admin/reports/${id}`, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ status })
    }).then(load)
  }

  const deleteReport = (id) => {
    if (!confirm('Delete this report?')) return
    fetch(`${API}/api/admin/reports/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    }).then(load)
  }

  const filtered = filter === 'all' ? reports : reports.filter(r => r.status === filter)

  return (
    <div>
      <Navbar />
      <main style={{ padding: '2rem', maxWidth: 1000, margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
          <Link to="/admin" style={{ color: 'var(--primary)' }}>← Admin</Link>
          <h2 style={{ margin: 0 }}>🚩 Reports Dashboard</h2>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: '.5rem' }}>
            {['all','pending','reviewed','dismissed'].map(s => (
              <button key={s} onClick={() => setFilter(s)}
                style={{ padding: '.3rem .8rem', borderRadius: 8, border: '1px solid var(--border)',
                  background: filter === s ? 'var(--primary)' : 'transparent',
                  color: filter === s ? '#fff' : 'inherit', cursor: 'pointer', fontSize: '.85rem' }}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
              </button>
            ))}
          </div>
        </div>
        {loading && <p>Loading…</p>}
        {!loading && filtered.length === 0 && <p style={{ opacity: .6 }}>No reports found.</p>}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '.75rem' }}>
          {filtered.map(r => (
            <div key={r.id} className="glass" style={{ padding: '1rem', borderRadius: 10, display: 'flex', gap: '1rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: 200 }}>
                <div style={{ display: 'flex', gap: '.5rem', alignItems: 'center', marginBottom: '.25rem' }}>
                  <span style={{ fontWeight: 600 }}>@{r.reported_slug || r.reported_user_id}</span>
                  <span style={{ fontSize: '.75rem', background: STATUS_COLORS[r.status] + '33', color: STATUS_COLORS[r.status], padding: '2px 8px', borderRadius: 99 }}>{r.status}</span>
                </div>
                <div style={{ fontSize: '.85rem', opacity: .7 }}>Reason: <strong>{r.reason}</strong></div>
                {r.details && <div style={{ fontSize: '.82rem', opacity: .6, marginTop: '.2rem' }}>{r.details}</div>}
                <div style={{ fontSize: '.78rem', opacity: .5, marginTop: '.3rem' }}>
                  Reporter: {r.reporter_email || 'Anonymous'} · {new Date(r.created_at).toLocaleDateString()}
                </div>
              </div>
              <div style={{ display: 'flex', gap: '.5rem', flexWrap: 'wrap' }}>
                {r.status !== 'reviewed' && <button onClick={() => updateStatus(r.id, 'reviewed')} style={{ padding: '.3rem .7rem', borderRadius: 7, border: 'none', background: '#10b981', color: '#fff', cursor: 'pointer', fontSize: '.8rem' }}>✓ Reviewed</button>}
                {r.status !== 'dismissed' && <button onClick={() => updateStatus(r.id, 'dismissed')} style={{ padding: '.3rem .7rem', borderRadius: 7, border: 'none', background: '#6b7280', color: '#fff', cursor: 'pointer', fontSize: '.8rem' }}>Dismiss</button>}
                {r.status !== 'pending' && <button onClick={() => updateStatus(r.id, 'pending')} style={{ padding: '.3rem .7rem', borderRadius: 7, border: 'none', background: '#f59e0b', color: '#fff', cursor: 'pointer', fontSize: '.8rem' }}>Re-open</button>}
                <button onClick={() => deleteReport(r.id)} style={{ padding: '.3rem .7rem', borderRadius: 7, border: 'none', background: '#ef4444', color: '#fff', cursor: 'pointer', fontSize: '.8rem' }}>🗑</button>
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  )
}
JSXEOF

# ---------- frontend/src/pages/AdminFiles.jsx ----------
cat > frontend/src/pages/AdminFiles.jsx << 'JSXEOF'
import { useState, useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import Navbar from '../components/Navbar'

function fmtSize(bytes) {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
}

export default function AdminFiles() {
  const token = localStorage.getItem('token')
  const API = import.meta.env.VITE_API_BASE_URL || ''
  const [files, setFiles] = useState([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [toast, setToast] = useState('')
  const fileRef = useRef()

  const load = () => {
    fetch(`${API}/api/admin/files`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.json())
      .then(d => { setFiles(Array.isArray(d) ? d : []); setLoading(false) })
  }
  useEffect(load, [])

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3000) }

  const uploadFile = async (e) => {
    const file = e.target.files[0]
    if (!file) return
    setUploading(true)
    const form = new FormData()
    form.append('file', file)
    const res = await fetch(`${API}/api/admin/files/upload`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: form
    })
    setUploading(false)
    if (res.ok) { showToast('✅ Uploaded!'); load() }
    else showToast('❌ Upload failed')
    fileRef.current.value = ''
  }

  const deleteFile = (name) => {
    if (!confirm(`Delete ${name}?`)) return
    fetch(`${API}/api/admin/files/${name}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    }).then(r => { if (r.ok) { showToast('Deleted'); load() } })
  }

  const copyUrl = (url) => {
    navigator.clipboard.writeText(`${API}${url}`)
    showToast('📋 URL copied!')
  }

  const isImage = (name) => /\.(png|jpg|jpeg|gif|webp|svg)$/i.test(name)

  return (
    <div>
      <Navbar />
      {toast && <div style={{ position: 'fixed', top: 80, right: 20, zIndex: 9999, background: 'var(--primary)', color: '#fff', padding: '.75rem 1.25rem', borderRadius: 10 }}>{toast}</div>}
      <main style={{ padding: '2rem', maxWidth: 900, margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
          <Link to="/admin" style={{ color: 'var(--primary)' }}>← Admin</Link>
          <h2 style={{ margin: 0 }}>🗂️ File Upload Manager</h2>
          <div style={{ marginLeft: 'auto' }}>
            <input ref={fileRef} type="file" style={{ display: 'none' }} onChange={uploadFile} />
            <button onClick={() => fileRef.current.click()} disabled={uploading}
              style={{ padding: '.5rem 1.2rem', borderRadius: 8, border: 'none', background: 'var(--primary)', color: '#fff', cursor: 'pointer' }}>
              {uploading ? '⏳ Uploading…' : '⬆️ Upload File'}
            </button>
          </div>
        </div>
        {loading && <p>Loading…</p>}
        {!loading && files.length === 0 && <p style={{ opacity: .6 }}>No files uploaded yet.</p>}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '1rem' }}>
          {files.map(f => (
            <div key={f.name} className="glass" style={{ borderRadius: 10, overflow: 'hidden' }}>
              {isImage(f.name)
                ? <img src={`${API}${f.url}`} alt={f.name} style={{ width: '100%', height: 120, objectFit: 'cover' }} />
                : <div style={{ height: 80, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '2.5rem' }}>📄</div>
              }
              <div style={{ padding: '.75rem' }}>
                <div style={{ fontSize: '.8rem', wordBreak: 'break-all', opacity: .8, marginBottom: '.4rem' }}>{f.name}</div>
                <div style={{ fontSize: '.75rem', opacity: .5, marginBottom: '.6rem' }}>{fmtSize(f.size)}</div>
                <div style={{ display: 'flex', gap: '.4rem' }}>
                  <button onClick={() => copyUrl(f.url)} style={{ flex: 1, padding: '.3rem', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: 'inherit', cursor: 'pointer', fontSize: '.75rem' }}>📋 Copy URL</button>
                  <button onClick={() => deleteFile(f.name)} style={{ padding: '.3rem .6rem', borderRadius: 6, border: 'none', background: '#ef4444', color: '#fff', cursor: 'pointer', fontSize: '.75rem' }}>🗑</button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </main>
    </div>
  )
}
JSXEOF

# ---------- frontend/src/pages/AdminDomains.jsx ----------
cat > frontend/src/pages/AdminDomains.jsx << 'JSXEOF'
import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import Navbar from '../components/Navbar'

export default function AdminDomains() {
  const API = import.meta.env.VITE_API_BASE_URL || ''
  const token = localStorage.getItem('token')
  const [domains, setDomains] = useState([])
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState('')
  const [search, setSearch] = useState('')

  const showToast = (msg) => { setToast(msg); setTimeout(() => setToast(''), 3500) }

  const load = () => {
    Promise.all([
      fetch(`${API}/api/domains/admin/all`, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json()),
      fetch(`${API}/api/admin/users`, { headers: { Authorization: `Bearer ${token}` } }).then(r => r.json()),
    ]).then(([d, u]) => {
      setDomains(Array.isArray(d) ? d : [])
      setUsers(Array.isArray(u) ? u : [])
      setLoading(false)
    })
  }
  useEffect(load, [])

  const grant = (userId) => {
    fetch(`${API}/api/domains/admin/grant/${userId}`, { method: 'PUT', headers: { Authorization: `Bearer ${token}` } })
      .then(() => { showToast('✅ Domain access granted'); load() })
  }

  const revoke = (userId) => {
    if (!confirm('Revoke custom domain access for this user?')) return
    fetch(`${API}/api/domains/admin/revoke/${userId}`, { method: 'PUT', headers: { Authorization: `Bearer ${token}` } })
      .then(() => { showToast('🚫 Domain access revoked'); load() })
  }

  const deleteDomain = (domainId) => {
    if (!confirm('Delete this domain record? The user will need to re-add their domain.')) return
    fetch(`${API}/api/domains/admin/domain/${domainId}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } })
      .then(() => { showToast('🗑 Domain deleted'); load() })
  }

  const nonAdminUsers = users.filter(u => u.role !== 'admin')
  const filtered = search
    ? nonAdminUsers.filter(u => u.email.toLowerCase().includes(search.toLowerCase()) || (u.custom_slug || '').toLowerCase().includes(search.toLowerCase()))
    : nonAdminUsers

  return (
    <div>
      <Navbar />
      {toast && <div style={{ position: 'fixed', top: 80, right: 20, zIndex: 9999, background: 'var(--primary)', color: '#fff', padding: '.75rem 1.25rem', borderRadius: 10 }}>{toast}</div>}
      <main style={{ padding: '2rem', maxWidth: 1100, margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
          <Link to="/admin" style={{ color: 'var(--primary)' }}>← Admin</Link>
          <h2 style={{ margin: 0 }}>🌐 Branded Domains</h2>
          <div style={{ marginLeft: 'auto', display: 'flex', gap: '.5rem', alignItems: 'center' }}>
            <input className="input" placeholder="🔍 Search email or slug…" value={search} onChange={e => setSearch(e.target.value)} style={{ minWidth: 220 }} />
          </div>
        </div>

        {/* All Users Table */}
        <div className="glass" style={{ padding: '1.5rem', borderRadius: 12, marginBottom: '1.5rem', overflowX: 'auto' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ margin: 0 }}>All Users ({filtered.length})</h3>
            <span style={{ fontSize: '.8rem', opacity: .6 }}>
              {users.filter(u => u.can_use_custom_domain).length} with domain access ·{' '}
              {domains.length} domains configured
            </span>
          </div>
          {loading && <p>Loading…</p>}
          {!loading && filtered.length === 0 && <p style={{ opacity: .6 }}>No users found.</p>}
          {!loading && filtered.length > 0 && (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '.875rem' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--border)' }}>
                  {['User', 'Slug', 'Domain', 'Status', 'Access', 'Actions'].map(h => (
                    <th key={h} style={{ padding: '.5rem .75rem', textAlign: 'left', fontSize: '.78rem', color: 'var(--text-muted)', fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(u => {
                  const domainRec = domains.find(d => d.user_id === u.id)
                  return (
                    <tr key={u.id} style={{ borderBottom: '1px solid var(--border)', transition: 'background .15s' }}
                      onMouseEnter={e => e.currentTarget.style.background = 'var(--surface2)'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                      <td style={{ padding: '.6rem .75rem' }}>
                        <div style={{ fontWeight: 500 }}>{u.email}</div>
                        <div style={{ fontSize: '.75rem', opacity: .5 }}>ID #{u.id}</div>
                      </td>
                      <td style={{ padding: '.6rem .75rem', fontFamily: 'monospace', fontSize: '.82rem', opacity: .8 }}>
                        {u.custom_slug ? `@${u.custom_slug}` : <span style={{ opacity: .4 }}>—</span>}
                      </td>
                      <td style={{ padding: '.6rem .75rem' }}>
                        {domainRec ? (
                          <div>
                            <div style={{ fontFamily: 'monospace', fontSize: '.82rem' }}>{domainRec.domain}</div>
                            {domainRec.root_redirect && <div style={{ fontSize: '.72rem', opacity: .5 }}>↳ {domainRec.root_redirect}</div>}
                          </div>
                        ) : (
                          <span style={{ fontSize: '.8rem', opacity: .35 }}>Not set</span>
                        )}
                      </td>
                      <td style={{ padding: '.6rem .75rem' }}>
                        {domainRec ? (
                          <span style={{ padding: '2px 8px', borderRadius: 99, fontSize: '.75rem', fontWeight: 600,
                            background: domainRec.is_verified ? '#10b98120' : '#f59e0b20',
                            color: domainRec.is_verified ? '#10b981' : '#f59e0b' }}>
                            {domainRec.is_verified ? '✅ Verified' : '⏳ Pending DNS'}
                          </span>
                        ) : (
                          <span style={{ fontSize: '.78rem', opacity: .35 }}>—</span>
                        )}
                      </td>
                      <td style={{ padding: '.6rem .75rem' }}>
                        <span style={{ padding: '2px 8px', borderRadius: 99, fontSize: '.75rem', fontWeight: 600,
                          background: u.can_use_custom_domain ? '#6366f120' : 'var(--surface2)',
                          color: u.can_use_custom_domain ? 'var(--primary)' : 'var(--text-muted)' }}>
                          {u.can_use_custom_domain ? '🔓 Enabled' : '🔒 Disabled'}
                        </span>
                      </td>
                      <td style={{ padding: '.6rem .75rem' }}>
                        <div style={{ display: 'flex', gap: '.4rem', flexWrap: 'wrap' }}>
                          {u.can_use_custom_domain ? (
                            <button onClick={() => revoke(u.id)}
                              style={{ padding: '.25rem .65rem', borderRadius: 6, border: '1px solid var(--border)', background: 'transparent', color: 'inherit', cursor: 'pointer', fontSize: '.78rem' }}>
                              Revoke
                            </button>
                          ) : (
                            <button onClick={() => grant(u.id)}
                              style={{ padding: '.25rem .65rem', borderRadius: 6, border: 'none', background: 'var(--primary)', color: '#fff', cursor: 'pointer', fontSize: '.78rem' }}>
                              Grant
                            </button>
                          )}
                          {domainRec && (
                            <button onClick={() => deleteDomain(domainRec.id)}
                              style={{ padding: '.25rem .65rem', borderRadius: 6, border: 'none', background: '#ef444420', color: '#ef4444', cursor: 'pointer', fontSize: '.78rem' }}>
                              🗑 Domain
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* DNS Instructions */}
        <div className="glass" style={{ padding: '1.5rem', borderRadius: 12 }}>
          <h3 style={{ margin: '0 0 .75rem' }}>📋 Server Setup Instructions</h3>
          <p style={{ opacity: .7, fontSize: '.875rem', lineHeight: 1.6 }}>
            For custom domains to work, your server must accept incoming connections on port 80/443 for any hostname.
            If you're using Nginx or a reverse proxy, ensure you have a wildcard <code>server_name _;</code> or catch-all vhost.
            Users must point their domain's <strong>A record</strong> to your server's public IP address.
          </p>
          <div style={{ marginTop: '1rem', padding: '.75rem 1rem', background: 'var(--surface2)', borderRadius: 8, fontFamily: 'monospace', fontSize: '.82rem', lineHeight: 2 }}>
            Type: A Record<br />
            Name: @ (root domain)<br />
            Value: {'<Your Server IP>'}<br />
            TTL: 3600
          </div>
        </div>
      </main>
    </div>
  )
}
JSXEOF

# ---------- frontend/src/pages/CustomDomain.jsx ----------
cat > frontend/src/pages/CustomDomain.jsx << 'JSXEOF'
import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import Navbar from '../components/Navbar'

export default function CustomDomain() {
  const API = import.meta.env.VITE_API_BASE_URL || ''
  const token = localStorage.getItem('token')
  const [record, setRecord] = useState(null)
  const [loading, setLoading] = useState(true)
  const [forbidden, setForbidden] = useState(false)
  const [saving, setSaving] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [toast, setToast] = useState(null)
  const [form, setForm] = useState({ domain: '', root_redirect: '', not_found_redirect: '' })

  const showToast = (msg, type = 'success') => { setToast({ msg, type }); setTimeout(() => setToast(null), 4000) }

  const load = () => {
    fetch(`${API}/api/domains/my`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => {
        if (r.status === 403) { setForbidden(true); setLoading(false); return null }
        return r.json()
      })
      .then(d => {
        if (!d) return
        setRecord(d)
        if (d && d.id) setForm({ domain: d.domain, root_redirect: d.root_redirect || '', not_found_redirect: d.not_found_redirect || '' })
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }
  useEffect(load, [])

  const save = () => {
    if (!form.domain.trim()) return showToast('Please enter a domain', 'error')
    setSaving(true)
    const method = record ? 'PUT' : 'POST'
    const url = `${API}/api/domains/my`
    const body = record
      ? { root_redirect: form.root_redirect, not_found_redirect: form.not_found_redirect }
      : { domain: form.domain, root_redirect: form.root_redirect, not_found_redirect: form.not_found_redirect }
    fetch(url, {
      method,
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).then(async r => {
      setSaving(false)
      if (!r.ok) { const e = await r.json(); return showToast(e.detail || 'Error saving', 'error') }
      showToast('✅ Domain saved!')
      load()
    })
  }

  const verify = () => {
    setVerifying(true)
    fetch(`${API}/api/domains/my/verify`, { method: 'POST', headers: { Authorization: `Bearer ${token}` } })
      .then(async r => {
        setVerifying(false)
        if (!r.ok) { const e = await r.json(); return showToast(e.detail || 'Verification failed', 'error') }
        showToast('✅ Domain verified!')
        load()
      })
  }

  const remove = () => {
    if (!confirm('Remove your custom domain?')) return
    fetch(`${API}/api/domains/my`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } })
      .then(() => { setRecord(null); setForm({ domain: '', root_redirect: '', not_found_redirect: '' }); showToast('Domain removed') })
  }

  const pill = (verified) => (
    <span style={{ padding: '2px 10px', borderRadius: 99, fontSize: '.75rem', fontWeight: 600,
      background: verified ? '#10b98120' : '#f59e0b20',
      color: verified ? '#10b981' : '#f59e0b' }}>
      {verified ? '✅ Verified' : '⏳ Pending DNS'}
    </span>
  )

  return (
    <div>
      <Navbar />
      {toast && (
        <div style={{ position: 'fixed', top: 80, right: 20, zIndex: 9999, padding: '.75rem 1.25rem', borderRadius: 10,
          background: toast.type === 'error' ? '#ef4444' : 'var(--primary)', color: '#fff' }}>
          {toast.msg}
        </div>
      )}
      <main style={{ padding: '2rem', maxWidth: 900, margin: '0 auto', display: 'grid', gap: '1.5rem', gridTemplateColumns: '1fr 1fr' }}>
        <div style={{ gridColumn: '1 / -1', display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <Link to="/myaccount" style={{ color: 'var(--primary)' }}>← My Account</Link>
          <h2 style={{ margin: 0 }}>🌐 Custom Domain</h2>
          {record && pill(record.is_verified)}
        </div>

        {loading && <p style={{ gridColumn: '1 / -1' }}>Loading…</p>}

        {forbidden && (
          <div className="glass" style={{ gridColumn: '1 / -1', padding: '2rem', textAlign: 'center', borderRadius: 12 }}>
            <div style={{ fontSize: '2.5rem', marginBottom: '1rem' }}>🔒</div>
            <h3>Custom Domains Not Enabled</h3>
            <p style={{ opacity: .7, marginTop: '.5rem' }}>Contact an admin to enable custom domain support for your account.</p>
          </div>
        )}

        {!loading && !forbidden && (
          <>
            {/* Form */}
            <div className="glass" style={{ padding: '1.5rem', borderRadius: 12 }}>
              <h3 style={{ margin: '0 0 1.25rem' }}>{record ? 'Your Domain' : 'Add Custom Domain'}</h3>
              <div style={{ display: 'grid', gap: '1rem' }}>
                <div>
                  <label style={{ display: 'block', marginBottom: '.4rem', fontSize: '.875rem', fontWeight: 500 }}>Domain</label>
                  <input
                    className="input"
                    placeholder="yourdomain.com"
                    value={form.domain}
                    onChange={e => setForm({ ...form, domain: e.target.value })}
                    disabled={!!record}
                    style={{ opacity: record ? .6 : 1 }}
                  />
                  {record && <p style={{ fontSize: '.75rem', opacity: .5, marginTop: '.3rem' }}>Remove and re-add to change domain.</p>}
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: '.4rem', fontSize: '.875rem', fontWeight: 500 }}>Domain Root Redirect</label>
                  <input className="input" placeholder="https://yourdomain.com/my-profile" value={form.root_redirect} onChange={e => setForm({ ...form, root_redirect: e.target.value })} />
                  <p style={{ fontSize: '.75rem', opacity: .5, marginTop: '.3rem' }}>Where to send visitors who go to https://{form.domain || 'yourdomain.com'}</p>
                </div>
                <div>
                  <label style={{ display: 'block', marginBottom: '.4rem', fontSize: '.875rem', fontWeight: 500 }}>404 Redirect</label>
                  <input className="input" placeholder="https://yourdomain.com/not-found" value={form.not_found_redirect} onChange={e => setForm({ ...form, not_found_redirect: e.target.value })} />
                  <p style={{ fontSize: '.75rem', opacity: .5, marginTop: '.3rem' }}>Where to send visitors if a short link isn't found.</p>
                </div>
              </div>
              <div style={{ display: 'flex', gap: '.75rem', marginTop: '1.25rem', flexWrap: 'wrap' }}>
                <button className="btn" onClick={save} disabled={saving}>{saving ? 'Saving…' : record ? '💾 Update' : '➕ Add Domain'}</button>
                {record && !record.is_verified && <button className="btn btn-outline" onClick={verify} disabled={verifying}>{verifying ? 'Checking DNS…' : '🔍 Verify DNS'}</button>}
                {record && <button className="btn btn-outline" onClick={remove} style={{ color: '#ef4444', borderColor: '#ef4444' }}>🗑 Remove</button>}
              </div>
            </div>

            {/* DNS Instructions */}
            <div className="glass" style={{ padding: '1.5rem', borderRadius: 12 }}>
              <h3 style={{ margin: '0 0 1rem' }}>📋 DNS Setup Instructions</h3>
              <p style={{ fontSize: '.875rem', opacity: .8, lineHeight: 1.7, margin: '0 0 1rem' }}>
                Point your domain to this server by adding a DNS record at your domain registrar (Namecheap, Cloudflare, GoDaddy, etc):
              </p>
              <div style={{ display: 'grid', gap: '.5rem', marginBottom: '1.25rem' }}>
                {[
                  ['Type', 'A'],
                  ['Name / Host', '@ (root) or subdomain'],
                  ['Value / Points to', 'Your server IP address'],
                  ['TTL', '3600 (or Auto)'],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', gap: '.75rem', padding: '.5rem .75rem', background: 'var(--surface2)', borderRadius: 7 }}>
                    <span style={{ minWidth: 110, fontSize: '.82rem', opacity: .6 }}>{k}</span>
                    <span style={{ fontFamily: 'monospace', fontSize: '.85rem', fontWeight: 600 }}>{v}</span>
                  </div>
                ))}
              </div>
              <div style={{ padding: '.75rem 1rem', background: 'rgba(99,102,241,.08)', borderRadius: 8, borderLeft: '3px solid var(--primary)', fontSize: '.82rem', lineHeight: 1.6 }}>
                💡 DNS changes can take <strong>up to 48 hours</strong> to propagate. Once done, click <strong>Verify DNS</strong> to activate your domain. Short links on your domain will use <code>https://{form.domain || 'yourdomain.com'}/s/CODE</code>
              </div>
              <div style={{ marginTop: '1rem', padding: '.75rem 1rem', background: 'rgba(245,158,11,.08)', borderRadius: 8, borderLeft: '3px solid #f59e0b', fontSize: '.82rem', lineHeight: 1.6 }}>
                🔶 For HTTPS/SSL, ask your admin to configure a wildcard SSL certificate or use Cloudflare's proxy (orange cloud) which handles SSL automatically.
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  )
}
JSXEOF


# ---------- frontend/src/pages/Analytics.jsx ----------
cat > frontend/src/pages/Analytics.jsx << 'ANEOF'
import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

function StatCard({ label, value, icon, sub }) {
  return (
    <div className="glass" style={{ padding: '1.25rem', borderRadius: 12, textAlign: 'center' }}>
      <div style={{ fontSize: '1.8rem', marginBottom: '.25rem' }}>{icon}</div>
      <div style={{ fontSize: '2rem', fontWeight: 700, color: 'var(--primary)' }}>{value?.toLocaleString() ?? '—'}</div>
      <div style={{ fontSize: '.85rem', opacity: .7, marginTop: '.2rem' }}>{label}</div>
      {sub && <div style={{ fontSize: '.75rem', opacity: .5, marginTop: '.15rem' }}>{sub}</div>}
    </div>
  )
}

function TopList({ title, items, keyField, countField }) {
  if (!items || items.length === 0) return null
  const max = Math.max(...items.map(i => i[countField]))
  return (
    <div className="glass" style={{ padding: '1.25rem', borderRadius: 12 }}>
      <h3 style={{ marginBottom: '1rem', fontSize: '.95rem' }}>{title}</h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '.5rem' }}>
        {items.map((item, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '.75rem' }}>
            <div style={{ flex: 1, fontSize: '.85rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', opacity: .85 }}>
              {item[keyField] || 'Unknown'}
            </div>
            <div style={{ width: 120, background: 'var(--surface2)', borderRadius: 4, overflow: 'hidden' }}>
              <div style={{ height: 8, background: 'var(--primary)', borderRadius: 4, width: `${Math.round((item[countField] / max) * 100)}%` }} />
            </div>
            <div style={{ fontSize: '.8rem', fontWeight: 600, color: 'var(--primary)', minWidth: 30, textAlign: 'right' }}>{item[countField]}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

function DayChart({ data }) {
  if (!data || data.length === 0) return null
  const max = Math.max(...data.map(d => d.count), 1)
  return (
    <div className="glass" style={{ padding: '1.25rem', borderRadius: 12 }}>
      <h3 style={{ marginBottom: '1rem', fontSize: '.95rem' }}>📈 Clicks — Last 14 Days</h3>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: '4px', height: 80 }}>
        {data.map((d, i) => (
          <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
            <div title={`${d.day}: ${d.count}`}
              style={{ width: '100%', background: 'var(--primary)', borderRadius: '3px 3px 0 0',
                height: `${Math.max(4, Math.round((d.count / max) * 70))}px`, opacity: .85 }} />
            <div style={{ fontSize: '.55rem', opacity: .4, transform: 'rotate(-35deg)', transformOrigin: 'top center', whiteSpace: 'nowrap' }}>
              {d.day.slice(5)}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function Analytics() {
  const { linkId } = useParams()
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [toast, setToast] = useState(null)

  useEffect(() => {
    if (!linkId) return
    api.get(`/api/analytics/links/${linkId}`)
      .then(r => setStats(r.data))
      .catch(err => setToast({ message: err.response?.data?.detail || 'Failed to load stats', type: 'error' }))
      .finally(() => setLoading(false))
  }, [linkId])

  return (
    <div>
      <Navbar />
      <main style={{ padding: '2rem', maxWidth: 900, margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1.5rem', flexWrap: 'wrap' }}>
          <Link to="/dashboard" style={{ color: 'var(--primary)', textDecoration: 'none' }}>← Dashboard</Link>
          <h1 style={{ margin: 0 }}>📊 Link Analytics</h1>
        </div>

        {loading && <p style={{ opacity: .6 }}>Loading…</p>}
        {!loading && stats && (
          <div style={{ display: 'grid', gap: '1.25rem' }}>
            {/* Link info */}
            <div className="glass" style={{ padding: '1.25rem', borderRadius: 12 }}>
              <div style={{ fontSize: '.78rem', opacity: .5, marginBottom: '.25rem', fontFamily: 'monospace' }}>
                /s/{stats.short_code}
              </div>
              <div style={{ fontWeight: 600, fontSize: '1rem', marginBottom: '.25rem' }}>{stats.title || 'Untitled Link'}</div>
              <a href={stats.original_url} target="_blank" rel="noopener" style={{ fontSize: '.82rem', color: 'var(--primary)', wordBreak: 'break-all' }}>
                {stats.original_url}
              </a>
            </div>

            {/* Stat cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '1rem' }}>
              <StatCard icon="🖱️" label="Total Clicks" value={stats.total_clicks} />
              <StatCard icon="👥" label="Unique Visitors" value={stats.unique_ips} />
            </div>

            {/* Day chart */}
            <DayChart data={stats.clicks_by_day} />

            {/* Top lists */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '1rem' }}>
              <TopList title="🌍 Top Countries" items={stats.top_countries} keyField="country" countField="count" />
              <TopList title="💻 Top Devices" items={stats.top_devices} keyField="device" countField="count" />
              <TopList title="🔗 Top Referers" items={stats.top_referers} keyField="referer" countField="count" />
            </div>
          </div>
        )}
        {!loading && !stats && !toast && (
          <div className="empty glass"><div className="empty-icon">📊</div><h3>No analytics data yet</h3></div>
        )}
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
ANEOF

# ---------- frontend/src/App.jsx (updated with AdminSmtp route) ----------
cat > frontend/src/App.jsx << 'JSXEOF'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from './context/ThemeContext'
import { AuthProvider } from './context/AuthContext'
import Home       from './pages/Home'
import Login      from './pages/Login'
import Signup     from './pages/Signup'
import ForgotPassword from './pages/ForgotPassword'
import ResetPassword from './pages/ResetPassword'
import Dashboard  from './pages/Dashboard'
import Create     from './pages/Create'
import EditLink   from './pages/EditLink'
import MyAccount  from './pages/MyAccount'
import BioProfile from './pages/BioProfile'
import Messages   from './pages/Messages'
import TwoFA      from './pages/TwoFA'
import Admin      from './pages/Admin'
import AdminNav   from './pages/AdminNav'
import AdminPages from './pages/AdminPages'
import AdminEmailTemplates from './pages/AdminEmailTemplates'
import AdminSmtp  from './pages/AdminSmtp'
import AdminStats  from './pages/AdminStats'
import AdminReports from './pages/AdminReports'
import AdminFiles  from './pages/AdminFiles'
import AdminDomains from './pages/AdminDomains'
import CustomDomain from './pages/CustomDomain'
import CustomPage from './pages/CustomPage'
import Report     from './pages/Report'
import Analytics  from './pages/Analytics'

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/"            element={<Home />} />
            <Route path="/login"       element={<Login />} />
            <Route path="/signup"      element={<Signup />} />
            <Route path="/forgot-password" element={<ForgotPassword />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route path="/dashboard"   element={<Dashboard />} />
            <Route path="/create"      element={<Create />} />
            <Route path="/edit/:id"    element={<EditLink />} />
            <Route path="/myaccount"   element={<MyAccount />} />
            <Route path="/bio"         element={<BioProfile />} />
            <Route path="/messages"    element={<Messages />} />
            <Route path="/2fa"         element={<TwoFA />} />
            <Route path="/admin"       element={<Admin />} />
            <Route path="/admin/nav"   element={<AdminNav />} />
            <Route path="/admin/pages" element={<AdminPages />} />
            <Route path="/admin/email-templates" element={<AdminEmailTemplates />} />
            <Route path="/admin/smtp"  element={<AdminSmtp />} />
            <Route path="/admin/stats" element={<AdminStats />} />
            <Route path="/admin/reports" element={<AdminReports />} />
            <Route path="/admin/files" element={<AdminFiles />} />
            <Route path="/admin/domains" element={<AdminDomains />} />
            <Route path="/custom-domain" element={<CustomDomain />} />
            <Route path="/p/:slug"     element={<CustomPage />} />
            <Route path="/report"      element={<Report />} />
            <Route path="/analytics/:linkId" element={<Analytics />} />
            <Route path="*"            element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  )
}
JSXEOF

# ---------- frontend/src/vite-env.d.ts ----------
cat > frontend/src/vite-env.d.ts << 'EOF'
/// <reference types="vite/client" />
EOF


# ============================================================================
# NGINX CONFIG — security headers + reverse proxy + rate limiting
# ============================================================================
echo "🌐 Creating NGINX config..."

cat > nginx/nginx.conf << 'NGINX_EOF'
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /tmp/nginx.pid;
events { worker_connections 1024; }

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    keepalive_timeout 65;
    client_max_body_size 20M;
    server_tokens off;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

    limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;
    limit_req_zone $binary_remote_addr zone=redirect:10m rate=60r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/m;

    upstream backend  { server backend:8000; }
    upstream frontend { server frontend:3000; }

    server {
        listen 80;
        server_name _;

        location ~ ^/api/auth/(login|register|forgot-password) {
            limit_req zone=auth burst=5 nodelay;
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location ~ ^/[sl]/ {
            limit_req zone=redirect burst=30 nodelay;
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /api/ {
            limit_req zone=api burst=50 nodelay;
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_read_timeout 60s;
            # Follow backend redirects (e.g. /api/public/nav → /api/public/nav/)
            proxy_redirect off;
        }

        location /uploads/ {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        location ~ ^/(docs|redoc|openapi.json) {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        location /p/ {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        # Vite dev HMR paths — must come BEFORE the @slug rule.
        # These paths start with /@ but belong to the frontend dev server.
        location ~ ^/@(vite|react-refresh|id|fs) {
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }

        # Vite dep cache and source files — never let browsers cache stale
        # chunks; mismatched React versions cause useState null crashes.
        location ~ ^/(node_modules|src)/ {
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            add_header Cache-Control "no-store, no-cache, must-revalidate" always;
            add_header Pragma "no-cache" always;
        }

        # Profile @slug pages — only alphanumeric slug chars after @.
        # Because /@vite/ and /@react-refresh/ are matched above first,
        # this location only receives real profile slugs.
        location ~ ^/@[a-zA-Z0-9._-] {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Everything else to frontend (Vite SPA + HMR)
        location / {
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
NGINX_EOF

# ── Patch NGINX server_name with deploy domain ────────────────────────────────
if [ -n "$DEPLOY_DOMAIN" ]; then
  sed -i "s|server_name _;|server_name _ ${DEPLOY_DOMAIN} www.${DEPLOY_DOMAIN};|" nginx/nginx.conf
  echo "✅ NGINX server_name set to: _ ${DEPLOY_DOMAIN} www.${DEPLOY_DOMAIN}"
fi
# ─────────────────────────────────────────────────────────────────────────────

echo "✅ NGINX config created"

# ============================================================================
# PROJECT-LEVEL .env  (docker-compose loads this automatically)
# ============================================================================
cat > .env << PROJENV_EOF
SITE_NAME=${SITE_NAME}
SITE_VERSION=${SITE_VERSION}
BACKEND_PORT=${BACKEND_PORT}
FRONTEND_PORT=${FRONTEND_PORT}
BACKEND_URL=${BACKEND_URL}
FRONTEND_URL=${FRONTEND_URL}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
NGINX_PORT=80
REDIS_URL=redis://redis:6379/0
CLICK_RETENTION_DAYS=90
PROJENV_EOF

echo "✅ Project .env created"

# ── Add REDIS_URL to backend .env ─────────────────────────────────────────────
echo "REDIS_URL=redis://redis:6379/0" >> backend/.env

# ============================================================================
# BACKUP SCRIPT
# ============================================================================chmod +x backup.sh
echo "✅ backup.sh created"

# ============================================================================
# CLI TOOL
# ============================================================================

cat > backup.sh << 'BACKUP_EOF'
#!/bin/bash
set -e
DATE=$(date +%Y%m%d_%H%M%S)
DIR="$HOME/link-platform-backups"
mkdir -p "$DIR"

if command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"
else DC="docker compose"; fi

echo "📦 Backing up database..."
$DC exec -T db pg_dump -U user linkplatform > "$DIR/db_$DATE.sql"
echo "✅ Backup: $DIR/db_$DATE.sql"

# Keep only last 10
ls -t "$DIR"/db_*.sql 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true
echo "🗂  Old backups pruned (kept 10)"
BACKUP_EOF
chmod +x backup.sh
echo "✅ backup.sh created"

cat > linkplatform << 'CLI_EOF'
#!/bin/bash
INSTALL_DIR="$HOME/link-platform"
cd "$INSTALL_DIR" 2>/dev/null || { echo "❌ Not installed at $INSTALL_DIR"; exit 1; }
if command -v docker-compose >/dev/null 2>&1; then DC="docker-compose"; else DC="docker compose"; fi
case "$1" in
  start)    echo "🚀 Starting..."; $DC up -d ;;
  stop)     echo "🛑 Stopping..."; $DC down ;;
  restart)  echo "🔄 Restarting..."; $DC restart ;;
  logs)     $DC logs -f ${2:-backend} ;;
  status)   $DC ps ;;
  backup)   bash "$INSTALL_DIR/backup.sh" ;;
  update)
    echo "🔄 Rebuilding containers..."; $DC up -d --build
    echo "✅ Update complete" ;;
  shell)    $DC exec backend /bin/bash ;;
  worker)   $DC logs -f worker ;;
  db)       $DC exec db psql -U user linkplatform ;;
  redis)    $DC exec redis redis-cli ;;
  *)
    echo "LinkPlatform CLI v${SITE_VERSION}"
    echo ""
    echo "  start      Start all services"
    echo "  stop       Stop all services"
    echo "  restart    Restart all services"
    echo "  logs       Tail logs [service]"
    echo "  status     Container status"
    echo "  backup     Backup database"
    echo "  update     Rebuild and restart"
    echo "  shell      Backend bash shell"
    echo "  worker     Tail click worker logs"
    echo "  db         Open psql shell"
    echo "  redis      Open redis-cli"
    ;;
esac
CLI_EOF
chmod +x linkplatform

if [ -w /usr/local/bin ]; then
  cp linkplatform /usr/local/bin/linkplatform
  echo "✅ CLI installed globally — run: linkplatform help"
elif sudo -n cp linkplatform /usr/local/bin/linkplatform 2>/dev/null; then
  echo "✅ CLI installed globally — run: linkplatform help"
else
  echo "ℹ️  CLI available locally: ./linkplatform help"
fi


# ============================================================================
# DOCKER COMPOSE
# ============================================================================
cat > docker-compose.yml << 'COMPOSE_EOF'
services:

  db:
    image: postgres:15-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: user
      POSTGRES_PASSWORD: pass
      POSTGRES_DB: linkplatform
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user -d linkplatform"]
      interval: 5s
      timeout: 5s
      retries: 10
    networks:
      - linkplatform

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - linkplatform

  backend:
    build: ./backend
    restart: unless-stopped
    env_file: ./backend/.env
    ports:
      - "${BACKEND_PORT:-8000}:8000"
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - ./backend:/app
      - uploads_data:/app/app/uploads
    environment:
      - PYTHONUNBUFFERED=1
      - REDIS_URL=redis://redis:6379/0
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/api')"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 30s
    networks:
      - linkplatform
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  worker:
    build: ./backend
    restart: unless-stopped
    command: python -m app.workers.click_processor
    env_file: ./backend/.env
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - ./backend:/app
    environment:
      - PYTHONUNBUFFERED=1
      - REDIS_URL=redis://redis:6379/0
    networks:
      - linkplatform
    logging:
      driver: "json-file"
      options:
        max-size: "5m"
        max-file: "2"

  cleanup:
    build: ./backend
    restart: unless-stopped
    command: python -m app.workers.cleanup_worker
    env_file: ./backend/.env
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - ./backend:/app
    environment:
      - PYTHONUNBUFFERED=1
      - CLICK_RETENTION_DAYS=90
    networks:
      - linkplatform

  frontend:
    build: ./frontend
    restart: unless-stopped
    ports:
      - "${FRONTEND_PORT:-3000}:3000"
    volumes:
      - ./frontend:/app
      - /app/node_modules
      - /app/node_modules/.vite
    depends_on:
      - backend
    environment:
      - VITE_API_BASE_URL=
    networks:
      - linkplatform

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "${NGINX_PORT:-80}:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - backend
      - frontend
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost/api"]
      interval: 30s
      timeout: 10s
      retries: 5
    networks:
      - linkplatform
    logging:
      driver: "json-file"
      options:
        max-size: "5m"
        max-file: "2"

networks:
  linkplatform:
    driver: bridge

volumes:
  postgres_data:
  uploads_data:
COMPOSE_EOF

# ---------- Generate SECRET_KEY ----------
echo "🔐 Generating SECRET_KEY..."
SK=$(openssl rand -hex 32)
sed -i.bak "s/^SECRET_KEY=.*/SECRET_KEY=$SK/" backend/.env && rm -f backend/.env.bak

# ============================================================================
# START CONTAINERS (fresh install, no backup/restore)
# ============================================================================
echo "🐳 Building and starting containers..."
$DOCKER_COMPOSE up -d db redis
echo "⏳ Waiting for database and Redis to be ready..."
sleep 15

$DOCKER_COMPOSE up -d --build

echo "⏳ Waiting 80s for all services to start..."
sleep 80

# ---------- Health checks ----------
BACKEND_OK=0; FRONTEND_OK=0; NGINX_OK=0; WORKER_OK=0
curl -sf "${INTERNAL_BACKEND_URL}/api" >/dev/null 2>&1 && { echo "✅ Backend OK";  BACKEND_OK=1;  } || { echo "⚠️  Backend not ready"; $DOCKER_COMPOSE logs --tail=20 backend; }
curl -sf "http://localhost:${FRONTEND_PORT}/"   >/dev/null 2>&1 && { echo "✅ Frontend OK"; FRONTEND_OK=1; } || echo "⚠️  Frontend not ready"
curl -sf "http://localhost:80/api" >/dev/null 2>&1 && { echo "✅ NGINX OK"; NGINX_OK=1; } || echo "⚠️  NGINX not ready (check: $DOCKER_COMPOSE logs nginx)"
$DOCKER_COMPOSE ps worker | grep -q "Up" && { echo "✅ Click Worker running"; WORKER_OK=1; } || echo "⚠️  Worker status: $($DOCKER_COMPOSE ps worker | tail -1)"

cat << FINALMSG
🎉 === ${SITE_NAME} V${SITE_VERSION} Ready! ===

✅ NEW in v11.8.3 — Deploy Domain support + critical bug fixes:
  🌐 DEPLOY_DOMAIN — set once at top of script, works across localhost/IP/domain
  🔒 CORS fix — relative API URLs (no origin mismatch regardless of access method)
  🏷️  NGINX server_name — auto-patched to include your domain on deploy
  ⚡ Vite allowedHosts — auto-patched so domain isn't blocked by Vite dev server
  🐛 FIXED: 503 on dashboard load — NGINX api rate limit was 30r/m (way too low); now 30r/s with burst=50
  🐛 FIXED: Blank page on domain — NGINX now sends no-cache for /src/ and /node_modules/ so browser never serves stale React chunks
  🐛 FIXED: useState null / duplicate React — Vite dep cache busted with --force on startup
  🐛 FIXED: Stale Vite cache across rebuilds — .vite dir excluded from bind mount volume
  🐛 FIXED: Nav items missing — /api/public/nav trailing slash 307 redirect now avoided
  🩺 Health checks — use internal localhost URLs (no DNS dependency during startup)

✅ Carried from v11.8.0 — Blueprint Edition:
  🔴 Redis queue — click events processed asynchronously (no redirect slowdown)
  ⚙️  Click worker — background processor writes analytics to PostgreSQL
  🧹 Cleanup worker — prunes click data older than 90 days (configurable)
  📊 Analytics system — per-link: clicks/day chart, top countries, devices, referers
  📊 Analytics page — accessible via 📊 button on every link in dashboard
  🌐 NGINX reverse proxy — security headers, rate limiting (auth/api/redirect zones)
  🐋 Health checks on all 6 services (db, redis, backend, worker, nginx)
  💾 Named Docker volume — uploads persist across container rebuilds
  🔒 Upgrade-safe installer — database + uploads survive re-runs
  📦 backup.sh — one-command DB backup, keeps 10 newest
  🖥️  linkplatform CLI — start/stop/logs/backup/update/worker/db/redis
  🐳 Auto-install Docker on Debian/Ubuntu if missing
  🐛 FIXED: Admin Domains tab blank (React not imported — React.useState crash)
  🐛 FIXED: Message replies routing back to admin instead of original sender
  🐛 FIXED: Guest/self-notification messages showed broken Reply button

✅ Carried forward from 11.7.9:
  🌐 Branded Domains — users add own domain, DNS A record → server IP
  🔑 Admin grants per-user access via Admin → Domains tab
  ⚡ Domain-aware short links — /s/CODE resolves per domain owner
  🏠 Root domain redirect & custom 404 redirect per domain
  🔍 DNS verification button — checks A record before activating
  📋 DNS setup instructions in user UI and admin panel
  🔒 All previous 11.7.8 fixes also included (DB migrations)
  📊 Admin Statistics Dashboard  — /admin/stats  (users, clicks, profile views, messages, reports)
  🚩 Admin Reports Dashboard     — /admin/reports (review/dismiss/delete profile reports)
  🗂️  Admin File Upload Manager   — /admin/files   (upload, copy URL, delete site assets)
  👁️  Profile View Tracking       — auto-increments on every @slug visit
  🔍 Page SEO Metadata           — meta title, meta description, category, language per page
  📌 Page Menu Visibility        — toggle pages in/out of nav independently of published status












🌐 URLs:
  Frontend:  ${FRONTEND_URL}
  Backend:   ${BACKEND_URL}
  API Docs:  ${BACKEND_URL}/docs
  Preview:   ${FRONTEND_URL}/@admin
  Contact:   ${FRONTEND_URL}/p/contact

🔑 Admin Login:
  Email:    ${ADMIN_EMAIL}
  Password: ${ADMIN_PASSWORD}
  Login at: ${FRONTEND_URL}/login

🎨 How to Change Themes:
  1. Go to Bio Profile → 🎨 Appearance section
  2. Click a theme card (May Flowers, Midnight Purple, Ocean Breeze…)
  3. Or pick ✏️ Custom and write your own CSS in the textarea below
  4. Click 💾 Save Profile

🖼️ Header Image Tips:
  • Half Banner — default, top strip with fade, minimal height impact
  • Full Banner  — taller strip, great for landscape shots
  • Cover        — image fills entire header card; opacity controls text overlay darkness

🛠️ CLI Commands:
  linkplatform start        Start all 6 services
  linkplatform stop         Stop all services
  linkplatform restart      Restart all services
  linkplatform logs         Tail backend logs
  linkplatform logs nginx   Tail NGINX logs
  linkplatform worker       Tail click worker logs
  linkplatform status       Container status
  linkplatform backup       Backup PostgreSQL
  linkplatform update       Rebuild with new code
  linkplatform shell        Backend bash shell
  linkplatform db           psql shell
  linkplatform redis        redis-cli

🌐 Access via:
   Local:     http://localhost:80
   Local IP:  http://$(hostname -I 2>/dev/null | awk '{print $1}')
$([ -n "${DEPLOY_DOMAIN}" ] && echo "   Domain:    http://${DEPLOY_DOMAIN}  ← admin login works here too")
   API docs:  ${BACKEND_URL}/docs

🔄 Full reset (DESTROYS data):
  $DOCKER_COMPOSE down -v && bash v11.8.0.sh

FINALMSG

[ $BACKEND_OK -eq 0 ] && echo "⏳ Backend not ready — run: $DOCKER_COMPOSE logs backend"
[ $FRONTEND_OK -eq 0 ] && echo "⏳ Frontend not ready — run: $DOCKER_COMPOSE logs frontend"
[ $NGINX_OK -eq 0 ] && echo "⏳ NGINX not ready — run: $DOCKER_COMPOSE logs nginx"
echo ""
echo "🐳 All containers: $DOCKER_COMPOSE ps"
echo "📊 Click worker:   $DOCKER_COMPOSE logs -f worker"
echo "📖 API docs:       ${BACKEND_URL}/docs"
echo "🌐 Via NGINX:      http://localhost:80"
[ -n "$DEPLOY_DOMAIN" ] && echo "🌐 Via Domain:     http://${DEPLOY_DOMAIN}"
echo ""
echo "✨ LinkPlatform v${SITE_VERSION} installation complete!"
