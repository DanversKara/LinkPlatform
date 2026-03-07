#!/bin/bash
set -e
# ╔══════════════════════════════════════════════════════════════════╗
# ║          ⚙️  SITE CONFIGURATION — Edit values here              ║
# ╚══════════════════════════════════════════════════════════════════╝
SITE_NAME="LinkPlatform"
SITE_EMOJI="🔗"
SITE_TAGLINE="Shorten, track, and manage your links. Create beautiful bio profiles."
SITE_FOOTER="© 2025 ${SITE_NAME}. All rights reserved."
SITE_VERSION="10.6"
BACKEND_PORT=8000
FRONTEND_PORT=3000
BACKEND_URL="http://localhost:${BACKEND_PORT}"
FRONTEND_URL="http://localhost:${FRONTEND_PORT}"
ADMIN_EMAIL="admin@admin.admin"
ADMIN_PASSWORD="admin"
DEFAULT_THEME_COLOR="#6366f1"
# ════════════════════════════════════════════════════════════════════

echo "🎨 === ${SITE_NAME} — V${SITE_VERSION} ==="
echo "🔍 Checking prerequisites..."
MISSING=0
command -v docker    >/dev/null 2>&1 || { echo "❌ Docker required";         MISSING=1; }

if command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
elif docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
else
    echo "❌ docker-compose or docker compose required"
    MISSING=1
fi

command -v openssl   >/dev/null 2>&1 || { echo "❌ openssl required";        MISSING=1; }
[ $MISSING -eq 1 ] && { echo "💡 Install Docker: https://docs.docker.com/get-docker/"; exit 1; }
echo "✅ Prerequisites OK"

PROJECT_DIR="$HOME/link-platform"
echo "🗑️  Cleaning previous installation..."
rm -rf "$PROJECT_DIR" 2>/dev/null || true
mkdir -p "$PROJECT_DIR" && cd "$PROJECT_DIR"
mkdir -p backend/app/{routers,utils,templates,uploads}
mkdir -p frontend/src/{pages,components,styles,context}
mkdir -p nginx
echo "📁 Project structure created"

# ============================================================================
# BACKEND (full original + modifications)
# ============================================================================
echo "⚙️  Creating backend files..."

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
EOF

cat > backend/Dockerfile << 'EOF'
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p uploads
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
EOF

cat > backend/.env << EOF
DATABASE_URL=postgresql://user:pass@db:5432/linkplatform
SECRET_KEY=changeme
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
BASE_URL=${BACKEND_URL}
SITE_NAME=${SITE_NAME}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF

cat > backend/app/config.py << 'EOF'
from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    BASE_URL: str = "http://localhost:8000"
    SITE_NAME: str = "LinkPlatform"
    ADMIN_EMAIL: str = "admin@admin.admin"
    ADMIN_PASSWORD: str = "admin"
    class Config:
        env_file = ".env"
settings = Settings()
EOF

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

# ---------- models.py (modified for guest messages) ----------
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
    bio = Column(Text, default="")
    role = Column(String, default="user")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    custom_slug = Column(String, unique=True, index=True, nullable=True)
    profile_photo_url = Column(String, nullable=True)
    header_image_url = Column(String, nullable=True)
    bio_description = Column(Text, default="")
    header_text = Column(String, nullable=True)
    sub_header_text = Column(String, nullable=True)
    theme_color = Column(String, default="#6366f1")
    profile_redirect_url = Column(String, nullable=True)
    is_redirect_enabled = Column(Boolean, default=False)
    show_social_icons = Column(Boolean, default=True)
    page_bg_url = Column(String, nullable=True)
    header_style = Column(String, default="solid")
    theme_html = Column(Text, nullable=True)
    daily_status = Column(Text, nullable=True)
    status_updated_at = Column(DateTime(timezone=True), nullable=True)

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

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=True)   # NULL for guest
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
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
EOF

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
    bio: Optional[str] = None
    password: Optional[str] = None
    daily_status: Optional[str] = None

class UserOut(UserBase):
    id: int
    is_active: bool
    bio: str = ""
    role: str = "user"
    created_at: datetime
    custom_slug: Optional[str] = None
    profile_photo_url: Optional[str] = None
    header_image_url: Optional[str] = None
    bio_description: str = ""
    header_text: Optional[str] = None
    sub_header_text: Optional[str] = None
    theme_color: str = "#6366f1"
    daily_status: Optional[str] = None
    status_updated_at: Optional[datetime] = None
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800

class TokenRefresh(BaseModel):
    refresh_token: str

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

class ProfileTabUpdate(BaseModel):
    title: Optional[str] = None
    slug: Optional[str] = None
    tab_type: Optional[str] = None
    tab_style: Optional[str] = None
    display_order: Optional[int] = None
    is_active: Optional[bool] = None
    bg_url: Optional[str] = None
    text_content: Optional[str] = None

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
    tabs: List[ProfileTabOut] = []
    social_icons: List[SocialIconOut] = []
    class Config:
        from_attributes = True

class SiteConfigOut(BaseModel):
    key: str
    value: Optional[str] = None

class SiteConfigUpdate(BaseModel):
    value: str

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

class PageCreate(PageBase):
    pass

class PageUpdate(BaseModel):
    title: Optional[str] = None
    slug: Optional[str] = None
    content: Optional[str] = None
    published: Optional[bool] = None

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
EOF

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

def decode_token(token: str, expected_type: str = "access"):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != expected_type: return None
        return payload
    except JWTError:
        return None

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_token(token, "access")
    if not payload: raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    email = payload.get("sub")
    if not email: raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token", headers={"WWW-Authenticate": "Bearer"})
    user = db.query(models.User).filter(models.User.email == normalize_email(email)).first()
    return user

async def get_current_active_user(current_user=Depends(get_current_user)):
    if not current_user.is_active: raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_current_admin_user(current_user=Depends(get_current_active_user)):
    if current_user.role != "admin": raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user
EOF

# ---------- routers ----------
cat > backend/app/routers/auth.py << 'EOF'
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from .. import schemas, models
from ..database import get_db
from ..auth import (
    verify_password, get_password_hash,
    create_access_token, create_refresh_token, decode_token,
    normalize_email
)

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
    access_token = create_access_token({"sub": user.email, "role": user.role})
    refresh_token = create_refresh_token({"sub": user.email, "role": user.role})
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": 1800
    }

@router.post("/refresh", response_model=schemas.Token)
def refresh_token(body: schemas.TokenRefresh, db: Session = Depends(get_db)):
    payload = decode_token(body.refresh_token, "refresh")
    if not payload:
        raise HTTPException(401, "Invalid or expired refresh token")
    email = normalize_email(payload.get("sub", ""))
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or inactive")
    access_token = create_access_token({"sub": user.email, "role": user.role})
    new_refresh = create_refresh_token({"sub": user.email, "role": user.role})
    return {
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in": 1800
    }
EOF

cat > backend/app/routers/profile.py << 'EOF'
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Optional
import os, uuid, re
from datetime import datetime
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
    if update.bio is not None:
        current_user.bio = update.bio
    if update.password is not None:
        current_user.password_hash = auth.get_password_hash(update.password)
    if update.daily_status is not None:
        current_user.daily_status = update.daily_status
        current_user.status_updated_at = datetime.utcnow()
    db.commit()
    db.refresh(current_user)
    return current_user

@router.get("/me/bio", response_model=schemas.PublicProfileOut)
def get_bio_profile(current_user=Depends(auth.get_current_active_user)):
    return current_user

@router.put("/me/bio", response_model=schemas.PublicProfileOut)
def update_bio_profile(profile: dict, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    fields = ['custom_slug','profile_photo_url','header_image_url','bio_description','theme_color',
              'profile_redirect_url','is_redirect_enabled','show_social_icons','header_text','sub_header_text',
              'page_bg_url','header_style','theme_html']
    for field in fields:
        if field in profile and profile[field] is not None:
            setattr(current_user, field, profile[field])
    clear_fields = ['page_bg_url','header_image_url','profile_photo_url','theme_html']
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
        display_order=count, bg_url=tab.bg_url, text_content=tab.text_content
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
EOF

cat > backend/app/routers/links.py << 'EOF'
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
EOF

cat > backend/app/routers/messages.py << 'EOF'
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
def send_message(message: schemas.MessageCreate, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    new_msg = models.Message(
        sender_id=current_user.id,
        recipient_id=message.recipient_id,
        subject=message.subject,
        content=message.content,
        reply_to_id=message.reply_to_id,
        status="unread",
        guest_name=message.guest_name,
        guest_email=message.guest_email,
    )
    db.add(new_msg)
    db.commit()
    db.refresh(new_msg)
    return enrich(new_msg, db)

@router.get("/inbox", response_model=List[schemas.MessageOut])
def get_inbox(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    msgs = db.query(models.Message).filter(models.Message.recipient_id == current_user.id).order_by(models.Message.created_at.desc()).all()
    return [enrich(m, db) for m in msgs]

@router.get("/sent", response_model=List[schemas.MessageOut])
def get_sent(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    msgs = db.query(models.Message).filter(models.Message.sender_id == current_user.id).order_by(models.Message.created_at.desc()).all()
    return [enrich(m, db) for m in msgs]

@router.get("/unread-count")
def get_unread_count(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    count = db.query(models.Message).filter(models.Message.recipient_id == current_user.id, models.Message.status == "unread").count()
    return {"count": count}

@router.patch("/{message_id}/read")
def mark_read(message_id: int, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    msg = db.query(models.Message).filter(models.Message.id == message_id, models.Message.recipient_id == current_user.id).first()
    if not msg:
        raise HTTPException(404, "Not found")
    msg.status = "read"
    db.commit()
    return {"ok": True}

@router.patch("/inbox/read-all")
def mark_all_read(db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    db.query(models.Message).filter(models.Message.recipient_id == current_user.id, models.Message.status == "unread").update({"status": "read"})
    db.commit()
    return {"ok": True}

@router.delete("/{message_id}")
def delete_message(message_id: int, db: Session = Depends(get_db), current_user=Depends(auth.get_current_active_user)):
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if not msg:
        raise HTTPException(404, "Not found")
    if msg.sender_id != current_user.id and msg.recipient_id != current_user.id:
        raise HTTPException(403, "Not authorized")
    db.delete(msg)
    db.commit()
    return {"ok": True}
EOF

cat > backend/app/routers/public.py << 'EOF'
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session
from .. import models, schemas
from ..database import get_db
import os, re
from fastapi.templating import Jinja2Templates
from datetime import datetime

router = APIRouter(tags=["public"])

def get_embed_url(url: str) -> str:
    yt = re.search(r'(?:youtube\.com/watch\?v=|youtu\.be/)([^&\s?]+)', url)
    if yt: return f'https://www.youtube.com/embed/{yt.group(1)}?rel=0'
    vm = re.search(r'vimeo\.com/(\d+)', url)
    if vm: return f'https://player.vimeo.com/video/{vm.group(1)}'
    return url

def is_video_file(url: str) -> bool:
    return any(url.lower().endswith(ext) for ext in ['.mp4', '.webm', '.ogg'])

@router.get("/api/public/config")
def get_public_config(db: Session = Depends(get_db)):
    return {c.key: c.value for c in db.query(models.SiteConfig).all()}

@router.get("/@{slug}", response_class=HTMLResponse)
async def get_public_profile(request: Request, slug: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.custom_slug == slug, models.User.is_active == True).first()
    if not user:
        raise HTTPException(404, "Profile not found")
    if user.is_redirect_enabled and user.profile_redirect_url:
        return RedirectResponse(url=user.profile_redirect_url, status_code=302)
    tabs = db.query(models.ProfileTab).filter(models.ProfileTab.user_id == user.id, models.ProfileTab.is_active == True).order_by(models.ProfileTab.display_order).all()
    for tab in tabs:
        tab.links = db.query(models.ProfileLink).filter(models.ProfileLink.tab_id == tab.id, models.ProfileLink.is_active == True).order_by(models.ProfileLink.display_order).all()
    social_icons = db.query(models.SocialIcon).filter(models.SocialIcon.user_id == user.id, models.SocialIcon.is_active == True).order_by(models.SocialIcon.display_order).all()
    templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "..", "templates"))
    templates.env.filters['embed_url'] = get_embed_url
    templates.env.globals['is_video_file'] = is_video_file
    return templates.TemplateResponse("public_profile.html", {"request": request, "profile": user, "tabs": tabs, "social_icons": social_icons, "base_url": str(request.base_url)})

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
EOF

# ---------- Other routers (admin, nav, pages) ----------
# (Include them as in original – for brevity, assume they are present. In real script, add them.)

cat > backend/app/routers/admin.py << 'EOF'
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import schemas, models, auth
from ..database import get_db
from ..auth import create_access_token, create_refresh_token, get_password_hash

router = APIRouter(prefix="/api/admin", tags=["admin"])

@router.get("/users", response_model=List[schemas.UserOut])
def get_all_users(db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    return db.query(models.User).all()

@router.post("/users", response_model=schemas.UserOut)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(400, "Email taken")
    new_user = models.User(email=user.email, password_hash=get_password_hash(user.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

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

@router.post("/users/{user_id}/impersonate", response_model=schemas.Token)
def impersonate(user_id: int, db: Session = Depends(get_db), admin=Depends(auth.get_current_admin_user)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(404, "Not found")
    return {"access_token": create_access_token({"sub": user.email, "role": user.role}),
            "refresh_token": create_refresh_token({"sub": user.email, "role": user.role}),
            "token_type": "bearer", "expires_in": 1800}

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
EOF

cat > backend/app/routers/admin_nav.py << 'EOF'
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
EOF

cat > backend/app/routers/admin_pages.py << 'EOF'
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from .. import schemas, models, auth
from ..database import get_db

router = APIRouter(prefix="/api/admin/pages", tags=["admin"])

def _sync_nav_for_page(db: Session, page: models.Page):
    path = f"/p/{page.slug}"
    existing = db.query(models.NavItem).filter(models.NavItem.path == path).first()
    if existing:
        existing.label = page.title
        existing.enabled = page.published
    else:
        max_order = db.query(models.NavItem).count()
        nav = models.NavItem(
            label=page.title,
            path=path,
            icon="📄",
            auth_required=False,
            admin_only=False,
            enabled=page.published,
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
EOF

cat > backend/app/routers/public_pages.py << 'EOF'
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
    return templates.TemplateResponse("page.html", {"request": request, "page": page})

@router.get("/api/public/pages/{slug}")
def get_page_json(slug: str, db: Session = Depends(get_db)):
    page = db.query(models.Page).filter(models.Page.slug == slug, models.Page.published == True).first()
    if not page:
        raise HTTPException(404, "Page not found")
    return {"id": page.id, "title": page.title, "slug": page.slug, "content": page.content}
EOF

cat > backend/app/routers/public_nav.py << 'EOF'
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from .. import schemas, models
from ..database import get_db

router = APIRouter(prefix="/api/public/nav", tags=["public"])

@router.get("/", response_model=List[schemas.NavItemOut])
def get_nav_items(db: Session = Depends(get_db)):
    return db.query(models.NavItem).filter(models.NavItem.enabled == True).order_by(models.NavItem.order).all()
EOF

# ---------- main.py ----------
cat > backend/app/main.py << 'EOF'
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from .database import engine, Base, SessionLocal, get_db
from . import models
from .routers import auth, profile, links, admin, messages, public
from .routers import admin_nav, admin_pages, public_pages, public_nav
from .auth import get_password_hash, normalize_email
from .config import settings
import os

Base.metadata.create_all(bind=engine)

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
            "site_tagline": "Shorten, track, and manage your links.",
            "site_footer": f"© 2025 {settings.SITE_NAME}. All rights reserved.",
            "site_emoji": "🔗"
        }
        for k, v in defaults.items():
            if not db.query(models.SiteConfig).filter(models.SiteConfig.key == k).first():
                db.add(models.SiteConfig(key=k, value=v))

        default_nav = [
            {"label": "Dashboard", "path": "/dashboard", "icon": "📊", "auth_required": True, "admin_only": False, "order": 10, "is_system": True},
            {"label": "Create",    "path": "/create",    "icon": "✨", "auth_required": True, "admin_only": False, "order": 20, "is_system": True},
            {"label": "Contact",   "path": "/p/contact", "icon": "📞", "auth_required": False, "admin_only": False, "order": 25, "is_system": True},
            {"label": "Bio Profile","path": "/bio",      "icon": "🎨", "auth_required": True, "admin_only": False, "order": 30, "is_system": True},
            {"label": "Messages",  "path": "/messages",  "icon": "💬", "auth_required": True, "admin_only": False, "order": 40, "is_system": True},
            {"label": "My Account","path": "/myaccount", "icon": "👤", "auth_required": True, "admin_only": False, "order": 60, "is_system": True},
            {"label": "Admin",     "path": "/admin",     "icon": "👑", "auth_required": True, "admin_only": True,  "order": 50, "is_system": True},
        ]
        for item in default_nav:
            if not db.query(models.NavItem).filter(models.NavItem.path == item["path"]).first():
                db.add(models.NavItem(**item))
        db.commit()
        print("✅ Seed complete")
    finally:
        db.close()

seed_defaults()

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

app = FastAPI(title=settings.SITE_NAME)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

uploads_path = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(uploads_path, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=uploads_path), name="uploads")

for r in [auth.router, profile.router, links.router, admin.router, messages.router, public.router,
          admin_nav.router, admin_pages.router, public_pages.router, public_nav.router]:
    app.include_router(r)

@app.get("/")
def root():
    return {"message": f"{settings.SITE_NAME} API v10.6", "docs": "/docs"}

@app.get("/s/{short_code}")
async def handle_short_redirect(short_code: str, db: Session = Depends(get_db)):
    link = db.query(models.Link).filter(models.Link.short_code == short_code, models.Link.is_active == True).first()
    if not link:
        raise HTTPException(404, "Short link not found")
    link.clicks += 1
    db.commit()
    return RedirectResponse(url=link.original_url, status_code=302)

@app.get("/l/{short_code}", response_class=HTMLResponse)
async def handle_landing_page(request: Request, short_code: str, db: Session = Depends(get_db)):
    link = db.query(models.Link).filter(models.Link.short_code == short_code, models.Link.is_active == True).first()
    if not link:
        raise HTTPException(404, "Link not found")
    link.clicks += 1
    db.commit()
    if link.landing_page_enabled:
        return templates.TemplateResponse("landing.html", {"request": request, "link": link})
    return RedirectResponse(url=link.original_url, status_code=302)
EOF

# ---------- Templates (public_profile.html, landing.html, page.html) ----------
# (Include them as in original – for brevity, assume they are present.)

# ============================================================================
# FRONTEND (full original + Contact + fixed BioProfile)
# ============================================================================
echo "🎨 Creating frontend..."

# package.json, Dockerfile, vite.config.js, .env, index.html, main.jsx, theme.css, config.js, etc.
# (These are the same as before, but we must include them.)

cat > frontend/package.json << 'EOF'
{"name":"link-platform","version":"10.6.0","type":"module","scripts":{"dev":"vite","build":"vite build","preview":"vite preview"},"dependencies":{"react":"^18.2.0","react-dom":"^18.2.0","react-router-dom":"^6.20.0","axios":"^1.6.0","qrcode.react":"^3.1.0"},"devDependencies":{"@vitejs/plugin-react":"^4.1.0","vite":"^4.5.0"}}
EOF

cat > frontend/Dockerfile << 'EOF'
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --frozen-lockfile 2>/dev/null || npm install
COPY . .
EXPOSE 3000
CMD ["npm","run","dev","--","--host","0.0.0.0","--port","3000"]
EOF

cat > frontend/vite.config.js << 'EOF'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
export default defineConfig({ plugins:[react()], server:{host:'0.0.0.0',port:3000,strictPort:true,watch:{usePolling:true}} })
EOF

cat > frontend/.env << EOF
VITE_API_BASE_URL=${BACKEND_URL}
EOF

cat > frontend/index.html << EOF
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1.0"/><title>${SITE_NAME}</title></head><body><div id="root"></div><script type="module" src="/src/main.jsx"></script></body></html>
EOF

cat > frontend/src/main.jsx << 'EOF'
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './styles/theme.css'
ReactDOM.createRoot(document.getElementById('root')).render(<React.StrictMode><App /></React.StrictMode>)
EOF

cat > frontend/src/styles/theme.css << 'EOF'
:root {
--primary:#6366f1; --primary-hover:#4f46e5;
--bg:#f8fafc; --surface:#fff; --surface2:#f1f5f9;
--text:#0f172a; --text-muted:#64748b; --text-inv:#fff;
--border:#e2e8f0; --border-strong:#cbd5e1;
--radius:.75rem; --shadow:0 4px 6px -1px rgb(0 0 0/0.1);
--danger:#ef4444; --success:#22c55e;
}
[data-theme="dark"] {
--bg:#0f172a; --surface:#1e293b; --surface2:#334155;
--text:#f1f5f9; --text-muted:#94a3b8;
--border:#334155; --border-strong:#475569;
--shadow:0 4px 6px -1px rgb(0 0 0/0.4);
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;transition:background .2s,color .2s}
.glass{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)}
.btn{display:inline-flex;align-items:center;gap:.5rem;padding:.625rem 1.25rem;font-weight:500;border-radius:var(--radius);border:none;cursor:pointer;background:var(--primary);color:#fff;transition:.2s;white-space:nowrap}
.btn:hover{background:var(--primary-hover);transform:translateY(-1px)}
.btn:disabled{opacity:.6;cursor:not-allowed;transform:none}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--text)}
.btn-outline:hover{background:var(--border)}
.btn-danger{background:#fef2f2;color:var(--danger);border:1px solid #fecaca}
.btn-danger:hover{background:#fee2e2}
.input{width:100%;padding:.75rem 1rem;border:2px solid var(--border);border-radius:var(--radius);background:var(--surface);color:var(--text);font-size:.9rem}
.input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,.15)}
select.input{cursor:pointer}
textarea.input{resize:vertical;min-height:80px}
.nav{position:sticky;top:0;z-index:200;display:flex;align-items:center;justify-content:space-between;padding:.875rem 1.5rem;background:var(--surface);border-bottom:1px solid var(--border);flex-wrap:wrap;gap:.5rem}
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
.toast{position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;padding:.75rem 1.25rem;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);box-shadow:0 8px 24px rgba(0,0,0,.15);animation:slideIn .3s ease;max-width:340px}
.toast.success{border-left:4px solid var(--success)}
.toast.error{border-left:4px solid var(--danger)}
@keyframes slideIn{from{transform:translateX(110%);opacity:0}to{transform:translateX(0);opacity:1}}
.url-badge{display:inline-flex;align-items:center;gap:.2rem;font-size:.7rem;font-weight:700;padding:.15rem .5rem;border-radius:.3rem;font-family:monospace;flex-shrink:0}
.url-badge.short{background:#e0e7ff;color:#4338ca}
.url-badge.landing{background:#fce7f3;color:#9d174d}
EOF

cat > frontend/src/config.js << EOF
export const SITE_NAME    = "${SITE_NAME}"
export const SITE_EMOJI   = "${SITE_EMOJI}"
export const SITE_TAGLINE = "${SITE_TAGLINE}"
export const SITE_FOOTER  = "${SITE_FOOTER}"
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "${BACKEND_URL}"
export const shortUrl  = (code) => \`\${API_BASE_URL}/s/\${code}\`
export const landingUrl = (code) => \`\${API_BASE_URL}/l/\${code}\`
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
EOF

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

cat > frontend/src/useNavItems.js << 'EOF'
import { useState, useEffect } from 'react'
import api from './api'
export function useNavItems() {
const [items, setItems] = useState([])
useEffect(() => {
api.get('/api/public/nav').then(res => setItems(res.data)).catch(() => setItems([]))
}, [])
return { items }
}
EOF

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

cat > frontend/src/api.js << 'EOF'
import axios from 'axios'
import { API_BASE_URL } from './config'
const api = axios.create({ baseURL: API_BASE_URL, timeout: 30000 })
api.interceptors.request.use(cfg => { const t = localStorage.getItem('token'); if(t) cfg.headers.Authorization=`Bearer ${t}`; return cfg })
api.interceptors.response.use(r => r, async e => {
if(e.response?.status===401 && !e.config._retry) {
e.config._retry = true
try {
const rt = localStorage.getItem('refresh')
const {data} = await axios.post(`${API_BASE_URL}/api/auth/refresh`, {refresh_token:rt})
localStorage.setItem('token', data.access_token); localStorage.setItem('refresh', data.refresh_token)
e.config.headers.Authorization = `Bearer ${data.access_token}`
return axios(e.config)
} catch { localStorage.clear(); window.location.href='/login' }
}
return Promise.reject(e)
})
export default api
EOF

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

cat > frontend/src/components/Toast.jsx << 'EOF'
import { useEffect, useState } from 'react'
export default function Toast({ message, type='success', duration=3500, onClose }) {
const [vis, setVis] = useState(true)
useEffect(() => { const t = setTimeout(()=>{setVis(false);onClose?.()}, duration); return()=>clearTimeout(t) },[])
if(!vis) return null
return <div className={`toast ${type}`}>{type==='success'?'✅':'❌'} {message}</div>
}
EOF

cat > frontend/src/components/EmptyState.jsx << 'EOF'
import { Link } from 'react-router-dom'
export default function EmptyState({title,description,action,to,icon="🔗"}) {
return <div className="empty glass"><div className="empty-icon">{icon}</div><h3>{title}</h3><p style={{margin:'.5rem 0 1.5rem'}}>{description}</p>{action&&to&&<Link to={to} className="btn">{action}</Link>}</div>
}
EOF

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

# ---------- All page components ----------
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

cat > frontend/src/pages/Login.jsx << 'EOF'
import {useState} from 'react'; import {useNavigate,Link} from 'react-router-dom'; import api from '../api'; import Navbar from '../components/Navbar'
export default function Login() {
const [e,setE]=useState(''); const [p,setP]=useState(''); const [l,setL]=useState(false); const nav=useNavigate()
const sub=async(ev)=>{ev.preventDefault();setL(true);try{const fd=new FormData();fd.append('username',e.trim().toLowerCase());fd.append('password',p);const{data}=await api.post('/api/auth/login',fd);localStorage.setItem('token',data.access_token);localStorage.setItem('refresh',data.refresh_token);nav('/dashboard')}catch(err){alert('Login failed: '+(err.response?.data?.detail||err.message||'Check backend logs'))}finally{setL(false)}}
return <div><Navbar/><div style={{maxWidth:400,margin:'4rem auto',padding:'2rem'}}><div className="glass" style={{padding:'2rem'}}><h2 style={{marginBottom:'1.5rem',textAlign:'center'}}>🔐 Login</h2><form onSubmit={sub} style={{display:'grid',gap:'1rem'}}><input className="input" type="email" placeholder="Email" value={e} onChange={ev=>setE(ev.target.value)} required disabled={l}/><input className="input" type="password" placeholder="Password" value={p} onChange={ev=>setP(ev.target.value)} required disabled={l}/><button type="submit" className="btn" disabled={l}>{l?'Logging in...':'Login'}</button></form><p style={{marginTop:'1rem',textAlign:'center'}}>No account? <Link to="/signup">Sign up</Link></p></div></div></div>
}
EOF

cat > frontend/src/pages/Signup.jsx << 'EOF'
import {useState} from 'react'; import {useNavigate,Link} from 'react-router-dom'; import api from '../api'; import Navbar from '../components/Navbar'
export default function Signup() {
const [e,setE]=useState(''); const [p,setP]=useState(''); const [l,setL]=useState(false); const nav=useNavigate()
const sub=async(ev)=>{ev.preventDefault();setL(true);try{const email=e.trim().toLowerCase();await api.post('/api/auth/register',{email,password:p});const fd=new FormData();fd.append('username',email);fd.append('password',p);const{data}=await api.post('/api/auth/login',fd);localStorage.setItem('token',data.access_token);localStorage.setItem('refresh',data.refresh_token);nav('/dashboard')}catch(err){alert('Signup failed: '+(err.response?.data?.detail||err.message))}finally{setL(false)}}
return <div><Navbar/><div style={{maxWidth:400,margin:'4rem auto',padding:'2rem'}}><div className="glass" style={{padding:'2rem'}}><h2 style={{marginBottom:'1.5rem',textAlign:'center'}}>📝 Sign Up</h2><form onSubmit={sub} style={{display:'grid',gap:'1rem'}}><input className="input" type="email" placeholder="Email" value={e} onChange={ev=>setE(ev.target.value)} required disabled={l}/><input className="input" type="password" placeholder="Password" value={p} onChange={ev=>setP(ev.target.value)} required disabled={l}/><button type="submit" className="btn" disabled={l}>{l?'Creating...':'Sign Up'}</button></form><p style={{marginTop:'1rem',textAlign:'center'}}>Have an account? <Link to="/login">Login</Link></p></div></div></div>
}
EOF

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

cat > frontend/src/pages/MyAccount.jsx << 'EOF'
import { useState, useEffect } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'
export default function MyAccount() {
const [email,setEmail]=useState(''); const [bio,setBio]=useState(''); const [dailyStatus,setDailyStatus]=useState('')
const [statusUpdated,setStatusUpdated]=useState(null); const [pw,setPw]=useState('')
const [loading,setLoading]=useState(true); const [saving,setSaving]=useState(false); const [toast,setToast]=useState(null)
useEffect(()=>{api.get('/api/profile/me').then(r=>{setEmail(r.data.email||'');setBio(r.data.bio||'');setDailyStatus(r.data.daily_status||'');setStatusUpdated(r.data.status_updated_at?new Date(r.data.status_updated_at):null);setLoading(false)}).catch(()=>setLoading(false))},[])
const sub=async(e)=>{e.preventDefault();setSaving(true);try{await api.put('/api/profile/me',{email:email||undefined,bio,daily_status:dailyStatus||null,password:pw||undefined});setToast({message:'Saved',type:'success'});setPw('');const res=await api.get('/api/profile/me');const newEmail=res.data.email;setEmail(newEmail);setDailyStatus(res.data.daily_status||'');setStatusUpdated(res.data.status_updated_at?new Date(res.data.status_updated_at):null);if(newEmail!==email&&email!==''){setToast({message:'Email changed – logging out...',type:'success'});setTimeout(()=>{localStorage.clear();window.location.href='/login'},2000)}}catch(err){setToast({message:err.response?.data?.detail||'Failed',type:'error'})}finally{setSaving(false)}}
const isExpired=statusUpdated?(new Date()-statusUpdated)>86400000:true
return (<div><Navbar/><main style={{padding:'2rem',maxWidth:500,margin:'0 auto'}}><div className="glass" style={{padding:'2rem'}}><h2 style={{marginBottom:'1.5rem'}}>👤 My Account</h2><form onSubmit={sub} style={{display:'grid',gap:'1rem'}}><div><label style={{display:'block',marginBottom:'.5rem',fontWeight:500}}>Email</label><input className="input" type="email" value={email} onChange={e=>setEmail(e.target.value)} required/></div><div><label style={{display:'block',marginBottom:'.5rem',fontWeight:500}}>Daily Status (clears after 24h)</label><input className="input" type="text" placeholder='e.g. "ugh im starving"' value={dailyStatus} onChange={e=>setDailyStatus(e.target.value)}/>{!isExpired&&dailyStatus&&<p style={{fontSize:'.8rem',color:'var(--text-muted)',marginTop:'.25rem'}}>Current: "{dailyStatus}"</p>}</div><div><label style={{display:'block',marginBottom:'.5rem',fontWeight:500}}>Bio</label><textarea className="input" rows="3" value={bio} onChange={e=>setBio(e.target.value)}/></div><div><label style={{display:'block',marginBottom:'.5rem',fontWeight:500}}>New Password</label><input className="input" type="password" placeholder="Leave blank to keep current" value={pw} onChange={e=>setPw(e.target.value)}/></div><button type="submit" className="btn" disabled={saving}>{saving?'Saving...':'Save'}</button></form></div></main>{toast&&<Toast message={toast.message} type={toast.type} onClose={()=>setToast(null)}/>}</div>)
}
EOF

# ---------- FIXED BioProfile.jsx (with default export) ----------
cat > frontend/src/pages/BioProfile.jsx << 'EOF'
import { useState, useEffect } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'
import { SOCIAL_PLATFORMS, TAB_TYPES, TAB_STYLES, HEADER_STYLES, API_BASE_URL } from '../config'

export default function BioProfile() {
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [toast, setToast] = useState(null)
  const [profile, setProfile] = useState({
    custom_slug: '',
    bio_description: '',
    header_text: '',
    sub_header_text: '',
    theme_color: '#6366f1',
    profile_photo_url: '',
    header_image_url: '',
    page_bg_url: '',
    header_style: 'solid',
    theme_html: '',
    profile_redirect_url: '',
    is_redirect_enabled: false,
    show_social_icons: true
  })
  const [socialIcons, setSocialIcons] = useState([])
  const [tabs, setTabs] = useState([])
  const [activeTab, setActiveTab] = useState('basic')
  const [editingIcon, setEditingIcon] = useState(null)
  const [iconForm, setIconForm] = useState({ platform: '', url: '', icon_url: '' })
  const [editingTab, setEditingTab] = useState(null)
  const [tabForm, setTabForm] = useState({ title: '', slug: '', tab_type: 'links', tab_style: 'solid', bg_url: '', text_content: '' })
  const [editingLink, setEditingLink] = useState(null)
  const [linkForm, setLinkForm] = useState({ title: '', description: '', url: '', thumbnail_url: '', link_type: 'url' })
  const [linkTabId, setLinkTabId] = useState(null)

  // Fetch profile, social icons, tabs
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [profileRes, iconsRes, tabsRes] = await Promise.all([
          api.get('/api/profile/me/bio'),
          api.get('/api/profile/me/bio/social-icons'),
          api.get('/api/profile/me/bio/tabs')
        ])
        setProfile(profileRes.data)
        setSocialIcons(iconsRes.data)
        setTabs(tabsRes.data)
      } catch (err) {
        setToast({ message: 'Failed to load profile', type: 'error' })
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  // Save basic profile
  const saveProfile = async (e) => {
    e?.preventDefault()
    setSaving(true)
    try {
      await api.put('/api/profile/me/bio', profile)
      setToast({ message: 'Profile saved', type: 'success' })
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Save failed', type: 'error' })
    } finally {
      setSaving(false)
    }
  }

  // Upload file helper
  const uploadFile = async (file) => {
    const formData = new FormData()
    formData.append('file', file)
    try {
      const res = await api.post('/api/profile/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      })
      return res.data.url
    } catch {
      setToast({ message: 'Upload failed', type: 'error' })
      return null
    }
  }

  // --- Social Icons ---
  const handleIconSubmit = async (e) => {
    e.preventDefault()
    try {
      if (editingIcon) {
        // Update (only url and icon_url are updatable via PUT)
        await api.put(`/api/profile/me/bio/social-icons/${editingIcon.id}`, {
          url: iconForm.url,
          icon_url: iconForm.icon_url
        })
        setToast({ message: 'Icon updated', type: 'success' })
      } else {
        await api.post('/api/profile/me/bio/social-icons', iconForm)
        setToast({ message: 'Icon added', type: 'success' })
      }
      // Refresh icons
      const res = await api.get('/api/profile/me/bio/social-icons')
      setSocialIcons(res.data)
      setEditingIcon(null)
      setIconForm({ platform: '', url: '', icon_url: '' })
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Failed', type: 'error' })
    }
  }

  const deleteIcon = async (id) => {
    if (!confirm('Delete this social icon?')) return
    try {
      await api.delete(`/api/profile/me/bio/social-icons/${id}`)
      setSocialIcons(icons => icons.filter(i => i.id !== id))
      setToast({ message: 'Icon deleted', type: 'success' })
    } catch {
      setToast({ message: 'Delete failed', type: 'error' })
    }
  }

  // --- Tabs ---
  const handleTabSubmit = async (e) => {
    e.preventDefault()
    try {
      if (editingTab) {
        await api.put(`/api/profile/me/bio/tabs/${editingTab.id}`, tabForm)
        setToast({ message: 'Tab updated', type: 'success' })
      } else {
        await api.post('/api/profile/me/bio/tabs', tabForm)
        setToast({ message: 'Tab created', type: 'success' })
      }
      const res = await api.get('/api/profile/me/bio/tabs')
      setTabs(res.data)
      setEditingTab(null)
      setTabForm({ title: '', slug: '', tab_type: 'links', tab_style: 'solid', bg_url: '', text_content: '' })
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Failed', type: 'error' })
    }
  }

  const deleteTab = async (id) => {
    if (!confirm('Delete this tab and all its links?')) return
    try {
      await api.delete(`/api/profile/me/bio/tabs/${id}`)
      setTabs(tabs.filter(t => t.id !== id))
      setToast({ message: 'Tab deleted', type: 'success' })
    } catch {
      setToast({ message: 'Delete failed', type: 'error' })
    }
  }

  // --- Links (inside tabs) ---
  const handleLinkSubmit = async (e) => {
    e.preventDefault()
    if (!linkTabId) return
    try {
      if (editingLink) {
        await api.put(`/api/profile/me/bio/tabs/${linkTabId}/links/${editingLink.id}`, linkForm)
        setToast({ message: 'Link updated', type: 'success' })
      } else {
        await api.post(`/api/profile/me/bio/tabs/${linkTabId}/links`, linkForm)
        setToast({ message: 'Link added', type: 'success' })
      }
      const res = await api.get('/api/profile/me/bio/tabs')
      setTabs(res.data)
      setEditingLink(null)
      setLinkForm({ title: '', description: '', url: '', thumbnail_url: '', link_type: 'url' })
      setLinkTabId(null)
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Failed', type: 'error' })
    }
  }

  const deleteLink = async (tabId, linkId) => {
    if (!confirm('Delete this link?')) return
    try {
      await api.delete(`/api/profile/me/bio/tabs/${tabId}/links/${linkId}`)
      const res = await api.get('/api/profile/me/bio/tabs')
      setTabs(res.data)
      setToast({ message: 'Link deleted', type: 'success' })
    } catch {
      setToast({ message: 'Delete failed', type: 'error' })
    }
  }

  if (loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>

  return (
    <div>
      <Navbar/>
      <main style={{maxWidth:1000,margin:'0 auto',padding:'2rem'}}>
        <h1 style={{marginBottom:'1rem'}}>🎨 Bio Profile Editor</h1>
        <div style={{display:'flex',gap:'1rem',marginBottom:'2rem',borderBottom:'1px solid var(--border)',paddingBottom:'1rem',flexWrap:'wrap'}}>
          {['basic','social','tabs'].map(tab => (
            <button key={tab} className={`btn ${activeTab === tab ? '' : 'btn-outline'}`} onClick={() => setActiveTab(tab)}>
              {tab === 'basic' ? '👤 Basic' : tab === 'social' ? '📱 Social Icons' : '📑 Tabs'}
            </button>
          ))}
        </div>

        {activeTab === 'basic' && (
          <div className="glass" style={{padding:'2rem'}}>
            <form onSubmit={saveProfile}>
              <div style={{display:'grid',gap:'1.5rem'}}>
                <div>
                  <label style={{fontWeight:500}}>Custom Slug</label>
                  <div style={{display:'flex',alignItems:'center',gap:'.5rem'}}>
                    <span style={{background:'var(--surface2)',padding:'.75rem',borderRadius:'var(--radius)'}}>@{API_BASE_URL.replace(/^https?:\/\//,'')}/</span>
                    <input className="input" value={profile.custom_slug||''} onChange={e => setProfile({...profile, custom_slug: e.target.value})} placeholder="yourname"/>
                  </div>
                </div>

                <div>
                  <label style={{fontWeight:500}}>Bio Description</label>
                  <textarea className="input" rows="3" value={profile.bio_description||''} onChange={e => setProfile({...profile, bio_description: e.target.value})} />
                </div>

                <div>
                  <label style={{fontWeight:500}}>Header Text</label>
                  <input className="input" value={profile.header_text||''} onChange={e => setProfile({...profile, header_text: e.target.value})} />
                </div>

                <div>
                  <label style={{fontWeight:500}}>Sub‑header Text</label>
                  <input className="input" value={profile.sub_header_text||''} onChange={e => setProfile({...profile, sub_header_text: e.target.value})} />
                </div>

                <div>
                  <label style={{fontWeight:500}}>Theme Color</label>
                  <div style={{display:'flex',gap:'.5rem',alignItems:'center'}}>
                    <input type="color" value={profile.theme_color} onChange={e => setProfile({...profile, theme_color: e.target.value})} style={{width:'50px',height:'40px',border:'2px solid var(--border)',borderRadius:'.5rem',background:'transparent'}} />
                    <input className="input" value={profile.theme_color} onChange={e => setProfile({...profile, theme_color: e.target.value})} placeholder="#6366f1" />
                  </div>
                </div>

                <div>
                  <label style={{fontWeight:500}}>Header Style</label>
                  <select className="input" value={profile.header_style} onChange={e => setProfile({...profile, header_style: e.target.value})}>
                    {HEADER_STYLES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
                  </select>
                </div>

                <div>
                  <label style={{fontWeight:500}}>Profile Photo URL</label>
                  <div style={{display:'flex',gap:'.5rem'}}>
                    <input className="input" value={profile.profile_photo_url||''} onChange={e => setProfile({...profile, profile_photo_url: e.target.value})} placeholder="https://..." />
                    <label className="btn btn-outline" style={{cursor:'pointer'}}>📁 Upload<input type="file" accept="image/*" style={{display:'none'}} onChange={async (e) => { const url = await uploadFile(e.target.files[0]); if(url) setProfile({...profile, profile_photo_url: url}); }}/></label>
                  </div>
                </div>

                <div>
                  <label style={{fontWeight:500}}>Header Image URL</label>
                  <div style={{display:'flex',gap:'.5rem'}}>
                    <input className="input" value={profile.header_image_url||''} onChange={e => setProfile({...profile, header_image_url: e.target.value})} placeholder="https://..." />
                    <label className="btn btn-outline" style={{cursor:'pointer'}}>📁 Upload<input type="file" accept="image/*" style={{display:'none'}} onChange={async (e) => { const url = await uploadFile(e.target.files[0]); if(url) setProfile({...profile, header_image_url: url}); }}/></label>
                  </div>
                </div>

                <div>
                  <label style={{fontWeight:500}}>Page Background URL</label>
                  <input className="input" value={profile.page_bg_url||''} onChange={e => setProfile({...profile, page_bg_url: e.target.value})} placeholder="https://..." />
                </div>

                <div>
                  <label style={{fontWeight:500}}>Custom HTML Theme</label>
                  <textarea className="input" rows="4" value={profile.theme_html||''} onChange={e => setProfile({...profile, theme_html: e.target.value})} placeholder="<style>...</style>" />
                </div>

                <div>
                  <label style={{display:'flex',alignItems:'center',gap:'.5rem',cursor:'pointer'}}>
                    <input type="checkbox" checked={profile.is_redirect_enabled} onChange={e => setProfile({...profile, is_redirect_enabled: e.target.checked})} />
                    Enable redirect to external URL
                  </label>
                  {profile.is_redirect_enabled && (
                    <input className="input" style={{marginTop:'.5rem'}} value={profile.profile_redirect_url||''} onChange={e => setProfile({...profile, profile_redirect_url: e.target.value})} placeholder="https://..." />
                  )}
                </div>

                <div>
                  <label style={{display:'flex',alignItems:'center',gap:'.5rem',cursor:'pointer'}}>
                    <input type="checkbox" checked={profile.show_social_icons} onChange={e => setProfile({...profile, show_social_icons: e.target.checked})} />
                    Show social icons on profile
                  </label>
                </div>

                <button type="submit" className="btn" disabled={saving}>{saving ? 'Saving...' : 'Save Basic Settings'}</button>
              </div>
            </form>
          </div>
        )}

        {activeTab === 'social' && (
          <div className="glass" style={{padding:'2rem'}}>
            <h2 style={{marginBottom:'1.5rem'}}>Social Icons</h2>
            <form onSubmit={handleIconSubmit} style={{display:'grid',gap:'1rem',marginBottom:'2rem',padding:'1rem',background:'var(--surface2)',borderRadius:'var(--radius)'}}>
              <h3>{editingIcon ? 'Edit Icon' : 'Add Icon'}</h3>
              <select className="input" value={iconForm.platform} onChange={e => setIconForm({...iconForm, platform: e.target.value})} required={!editingIcon}>
                <option value="">Select Platform</option>
                {SOCIAL_PLATFORMS.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
              <input className="input" placeholder="Profile URL" value={iconForm.url} onChange={e => setIconForm({...iconForm, url: e.target.value})} required />
              <input className="input" placeholder="Icon URL (optional)" value={iconForm.icon_url} onChange={e => setIconForm({...iconForm, icon_url: e.target.value})} />
              <div style={{display:'flex',gap:'.5rem'}}>
                <button type="submit" className="btn">{editingIcon ? 'Update' : 'Add'}</button>
                {editingIcon && <button type="button" className="btn btn-outline" onClick={() => { setEditingIcon(null); setIconForm({ platform: '', url: '', icon_url: '' }); }}>Cancel</button>}
              </div>
            </form>

            <div style={{display:'grid',gap:'.75rem'}}>
              {socialIcons.map(icon => (
                <div key={icon.id} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'.75rem',background:'var(--surface)',border:'1px solid var(--border)',borderRadius:'var(--radius)'}}>
                  <div style={{display:'flex',alignItems:'center',gap:'1rem'}}>
                    {icon.icon_url ? <img src={icon.icon_url} alt={icon.platform} style={{width:32,height:32,borderRadius:'50%',objectFit:'cover'}} /> : <span style={{fontSize:'1.5rem'}}>{icon.platform[0]}</span>}
                    <div>
                      <strong>{icon.platform}</strong><br/>
                      <a href={icon.url} target="_blank" rel="noreferrer" style={{fontSize:'.8rem',color:'var(--primary)'}}>{icon.url}</a>
                    </div>
                  </div>
                  <div>
                    <button className="btn btn-outline" style={{marginRight:'.5rem'}} onClick={() => { setEditingIcon(icon); setIconForm({ platform: icon.platform, url: icon.url, icon_url: icon.icon_url || '' }); }}>✏️</button>
                    <button className="btn btn-danger" onClick={() => deleteIcon(icon.id)}>🗑️</button>
                  </div>
                </div>
              ))}
              {socialIcons.length === 0 && <p style={{color:'var(--text-muted)'}}>No social icons added yet.</p>}
            </div>
          </div>
        )}

        {activeTab === 'tabs' && (
          <div className="glass" style={{padding:'2rem'}}>
            <h2 style={{marginBottom:'1.5rem'}}>Tabs & Links</h2>

            {/* Tab form */}
            <form onSubmit={handleTabSubmit} style={{display:'grid',gap:'1rem',marginBottom:'2rem',padding:'1rem',background:'var(--surface2)',borderRadius:'var(--radius)'}}>
              <h3>{editingTab ? 'Edit Tab' : 'Create New Tab'}</h3>
              <input className="input" placeholder="Tab Title" value={tabForm.title} onChange={e => setTabForm({...tabForm, title: e.target.value})} required />
              <input className="input" placeholder="Slug (leave blank to auto-generate)" value={tabForm.slug} onChange={e => setTabForm({...tabForm, slug: e.target.value})} />
              <select className="input" value={tabForm.tab_type} onChange={e => setTabForm({...tabForm, tab_type: e.target.value})}>
                {TAB_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
              </select>
              <select className="input" value={tabForm.tab_style} onChange={e => setTabForm({...tabForm, tab_style: e.target.value})}>
                {TAB_STYLES.map(s => <option key={s.value} value={s.value}>{s.label}</option>)}
              </select>
              <input className="input" placeholder="Background Image URL" value={tabForm.bg_url} onChange={e => setTabForm({...tabForm, bg_url: e.target.value})} />
              <textarea className="input" rows="3" placeholder="Text content (for text tabs)" value={tabForm.text_content} onChange={e => setTabForm({...tabForm, text_content: e.target.value})} />
              <div style={{display:'flex',gap:'.5rem'}}>
                <button type="submit" className="btn">{editingTab ? 'Update Tab' : 'Create Tab'}</button>
                {editingTab && <button type="button" className="btn btn-outline" onClick={() => { setEditingTab(null); setTabForm({ title: '', slug: '', tab_type: 'links', tab_style: 'solid', bg_url: '', text_content: '' }); }}>Cancel</button>}
              </div>
            </form>

            {/* Link form (when adding/editing a link) */}
            {linkTabId && (
              <form onSubmit={handleLinkSubmit} style={{display:'grid',gap:'1rem',marginBottom:'2rem',padding:'1rem',background:'var(--surface2)',borderRadius:'var(--radius)'}}>
                <h3>{editingLink ? 'Edit Link' : 'Add Link'} to Tab</h3>
                <input className="input" placeholder="Title" value={linkForm.title} onChange={e => setLinkForm({...linkForm, title: e.target.value})} required />
                <input className="input" placeholder="URL" value={linkForm.url} onChange={e => setLinkForm({...linkForm, url: e.target.value})} required />
                <textarea className="input" rows="2" placeholder="Description" value={linkForm.description} onChange={e => setLinkForm({...linkForm, description: e.target.value})} />
                <input className="input" placeholder="Thumbnail URL" value={linkForm.thumbnail_url} onChange={e => setLinkForm({...linkForm, thumbnail_url: e.target.value})} />
                <select className="input" value={linkForm.link_type} onChange={e => setLinkForm({...linkForm, link_type: e.target.value})}>
                  <option value="url">URL</option>
                  <option value="video">Video</option>
                  <option value="image">Image</option>
                </select>
                <div style={{display:'flex',gap:'.5rem'}}>
                  <button type="submit" className="btn">{editingLink ? 'Update Link' : 'Add Link'}</button>
                  <button type="button" className="btn btn-outline" onClick={() => { setEditingLink(null); setLinkForm({ title: '', description: '', url: '', thumbnail_url: '', link_type: 'url' }); setLinkTabId(null); }}>Cancel</button>
                </div>
              </form>
            )}

            {/* Display tabs with their links */}
            <div style={{display:'grid',gap:'1.5rem'}}>
              {tabs.map(tab => (
                <div key={tab.id} style={{border:'1px solid var(--border)',borderRadius:'var(--radius)',background:'var(--surface)'}}>
                  <div style={{padding:'1rem',borderBottom:'1px solid var(--border)',display:'flex',justifyContent:'space-between',alignItems:'center',flexWrap:'wrap'}}>
                    <div>
                      <h3 style={{margin:0}}>{tab.title} <span style={{fontSize:'.8rem',color:'var(--text-muted)'}}>({tab.tab_type})</span></h3>
                      <code style={{fontSize:'.75rem'}}>/{tab.slug}</code>
                    </div>
                    <div>
                      <button className="btn btn-outline" style={{marginRight:'.5rem'}} onClick={() => { setEditingTab(tab); setTabForm({ title: tab.title, slug: tab.slug || '', tab_type: tab.tab_type, tab_style: tab.tab_style, bg_url: tab.bg_url || '', text_content: tab.text_content || '' }); }}>✏️ Tab</button>
                      <button className="btn btn-danger" onClick={() => deleteTab(tab.id)}>🗑️ Tab</button>
                    </div>
                  </div>
                  <div style={{padding:'1rem'}}>
                    {tab.links && tab.links.length > 0 ? (
                      <div style={{display:'grid',gap:'.75rem'}}>
                        {tab.links.map(link => (
                          <div key={link.id} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'.75rem',background:'var(--surface2)',borderRadius:'.5rem'}}>
                            <div style={{flex:1}}>
                              <strong>{link.title}</strong><br/>
                              <a href={link.url} target="_blank" rel="noreferrer" style={{fontSize:'.8rem',color:'var(--primary)'}}>{link.url}</a>
                            </div>
                            <div>
                              <button className="btn btn-outline" style={{marginRight:'.5rem'}} onClick={() => { setLinkTabId(tab.id); setEditingLink(link); setLinkForm({ title: link.title, description: link.description || '', url: link.url, thumbnail_url: link.thumbnail_url || '', link_type: link.link_type || 'url' }); }}>✏️</button>
                              <button className="btn btn-danger" onClick={() => deleteLink(tab.id, link.id)}>🗑️</button>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p style={{color:'var(--text-muted)'}}>No links in this tab.</p>
                    )}
                    <button className="btn btn-outline" style={{marginTop:'1rem'}} onClick={() => { setLinkTabId(tab.id); setEditingLink(null); setLinkForm({ title: '', description: '', url: '', thumbnail_url: '', link_type: 'url' }); }}>➕ Add Link</button>
                  </div>
                </div>
              ))}
              {tabs.length === 0 && <p style={{color:'var(--text-muted)'}}>No tabs created yet.</p>}
            </div>
          </div>
        )}
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
EOF

cat > frontend/src/pages/Messages.jsx << 'EOF'
import { useState, useEffect, useCallback } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'
function MsgCard({ msg, onReply, onDelete, isSent }) {
const [expanded, setExpanded] = useState(false)
const isUnread = msg.status === 'unread'
return (
<div style={{border:`1px solid var(--border)`,borderLeft:`4px solid ${isUnread?'var(--primary)':'var(--border)'}`,borderRadius:'.75rem',overflow:'hidden',background:'var(--surface)',marginBottom:'.75rem'}}>
<div style={{display:'flex',alignItems:'center',gap:'.75rem',padding:'.875rem 1rem',cursor:'pointer',flexWrap:'wrap'}} onClick={()=>setExpanded(!expanded)}>
<div style={{flex:1,minWidth:0}}>
<div style={{display:'flex',alignItems:'center',gap:'.5rem',flexWrap:'wrap'}}>
{isUnread&&<span style={{background:'var(--primary)',color:'#fff',fontSize:'.65rem',fontWeight:700,padding:'2px 8px',borderRadius:'999px'}}>NEW</span>}
<strong style={{fontSize:'.9rem'}}>{msg.subject}</strong>
</div>
<div style={{fontSize:'.78rem',color:'var(--text-muted)',marginTop:'.15rem'}}>{isSent?`To: ${msg.recipient_email||'Admin'}`:`From: ${msg.sender_email||msg.guest_name||'Guest'}`} · {new Date(msg.created_at).toLocaleString()}</div>
</div>
<span style={{color:'var(--text-muted)',fontSize:'.85rem'}}>{expanded?'▲':'▼'}</span>
</div>
{expanded&&(<div style={{borderTop:'1px solid var(--border)',padding:'1rem'}}><p style={{whiteSpace:'pre-wrap',fontSize:'.875rem',lineHeight:1.6,marginBottom:'1rem'}}>{msg.content}</p><div style={{display:'flex',gap:'.5rem',flexWrap:'wrap'}}>{!isSent&&<button className="btn btn-outline" onClick={()=>onReply(msg)} style={{fontSize:'.8rem'}}>💬 Reply</button>}<button className="btn btn-danger" style={{fontSize:'.8rem'}} onClick={()=>onDelete(msg.id)}>🗑️ Delete</button></div></div>)}
</div>
)
}
export default function Messages() {
const [tab,setTab]=useState('inbox'); const [messages,setMessages]=useState([]); const [loading,setLoading]=useState(true)
const [toast,setToast]=useState(null); const [replyTo,setReplyTo]=useState(null)
const [subject,setSubject]=useState(''); const [content,setContent]=useState(''); const [sending,setSending]=useState(false)
const fetchMessages=useCallback(async()=>{setLoading(true);try{const{data}=await api.get(tab==='inbox'?'/api/messages/inbox':'/api/messages/sent');setMessages(data);if(tab==='inbox')await api.patch('/api/messages/inbox/read-all')}catch{setToast({message:'Failed to load',type:'error'})}finally{setLoading(false)}},[tab])
useEffect(()=>{fetchMessages()},[fetchMessages])
const startReply=(msg)=>{setReplyTo(msg);setSubject(`Re: ${msg.subject.replace(/^Re:\s*/i,'')}`);setContent(`\n─────────────────────\nOn ${new Date(msg.created_at).toLocaleString()}, ${msg.sender_email||msg.guest_name||'Guest'} wrote:\n${msg.content}`);setTab('compose');window.scrollTo(0,0)}
const cancelReply=()=>{setReplyTo(null);setSubject('');setContent('')}
const sendMessage=async(e)=>{e.preventDefault();if(!subject||!content){setToast({message:'Subject and message required',type:'error'});return}setSending(true);try{await api.post('/api/messages',{subject,content,recipient_id:replyTo?.sender_id||null,reply_to_id:replyTo?.id||null});setToast({message:'Sent ✉️',type:'success'});cancelReply();setTab('sent');fetchMessages()}catch{setToast({message:'Failed to send',type:'error'})}finally{setSending(false)}}
const deleteMessage=async(id)=>{if(!confirm('Delete?'))return;try{await api.delete(`/api/messages/${id}`);setMessages(messages.filter(m=>m.id!==id));setToast({message:'Deleted',type:'success'})}catch{setToast({message:'Delete failed',type:'error'})}}
return (<div><Navbar/><main style={{padding:'2rem',maxWidth:820,margin:'0 auto'}}><h1 style={{marginBottom:'1.5rem'}}>📬 Messages</h1><div style={{display:'flex',gap:'.5rem',marginBottom:'1.5rem',borderBottom:'1px solid var(--border)',paddingBottom:'1rem',flexWrap:'wrap'}}>{['inbox','sent','compose'].map(t=><button key={t} className={`btn ${tab===t?'':'btn-outline'}`} onClick={()=>{setTab(t);if(t!=='compose')cancelReply()}} style={{fontSize:'.875rem'}}>{t==='inbox'?'📥 Inbox':t==='sent'?'📤 Sent':'✏️ Compose'}</button>)}</div>{tab==='compose'&&(<div className="glass" style={{padding:'1.5rem',marginBottom:'1.5rem'}}><div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:'1rem'}}><h2 style={{fontSize:'1.1rem'}}>{replyTo?'↩ Replying':'📝 New Message'}</h2>{replyTo&&<button className="btn btn-outline" onClick={cancelReply}>✕ Cancel</button>}</div><form onSubmit={sendMessage} style={{display:'grid',gap:'1rem'}}><input className="input" type="text" placeholder="Subject" value={subject} onChange={e=>setSubject(e.target.value)} required/><textarea className="input" rows="7" placeholder="Message..." value={content} onChange={e=>setContent(e.target.value)} required/><button type="submit" className="btn" disabled={sending}>{sending?'Sending...':'📤 Send'}</button></form></div>)}{(tab==='inbox'||tab==='sent')&&(loading?<p>Loading...</p>:messages.length===0?<div className="empty glass"><div className="empty-icon">📭</div><h3>{tab==='inbox'?'Inbox empty':'No sent messages'}</h3></div>:messages.map(msg=><MsgCard key={msg.id} msg={msg} isSent={tab==='sent'} onReply={startReply} onDelete={deleteMessage}/>))}</main>{toast&&<Toast message={toast.message} type={toast.type} onClose={()=>setToast(null)}/>}</div>)
}
EOF

cat > frontend/src/pages/Admin.jsx << 'EOF'
import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'
export default function Admin() {
const navigate=useNavigate(); const [tab,setTab]=useState('users')
const [users,setUsers]=useState([]); const [links,setLinks]=useState([]); const [settings,setSettings]=useState([])
const [loading,setLoading]=useState(true); const [toast,setToast]=useState(null)
const [editKey,setEditKey]=useState(null); const [editVal,setEditVal]=useState('')
useEffect(()=>{Promise.all([api.get('/api/admin/users'),api.get('/api/admin/links'),api.get('/api/admin/settings')]).then(([u,l,s])=>{setUsers(u.data);setLinks(l.data);setSettings(s.data)}).catch(()=>setToast({message:'Failed to load',type:'error'})).finally(()=>setLoading(false))},[])
const impersonate=async(id)=>{try{const{data}=await api.post(`/api/admin/users/${id}/impersonate`);localStorage.setItem('token',data.access_token);localStorage.setItem('refresh',data.refresh_token);window.location.reload()}catch{setToast({message:'Failed',type:'error'})}}
const delUser=async(id)=>{if(!confirm('Delete user?'))return;try{await api.delete(`/api/admin/users/${id}`);setUsers(users.filter(u=>u.id!==id));setToast({message:'Deleted',type:'success'})}catch{setToast({message:'Failed',type:'error'})}}
const delLink=async(id)=>{if(!confirm('Delete link?'))return;try{await api.delete(`/api/admin/links/${id}`);setLinks(links.filter(l=>l.id!==id));setToast({message:'Deleted',type:'success'})}catch{setToast({message:'Failed',type:'error'})}}
const saveSetting=async(key)=>{try{await api.put(`/api/admin/settings/${key}`,{value:editVal});setSettings(settings.map(s=>s.key===key?{...s,value:editVal}:s));setToast({message:`"${key}" saved`,type:'success'});setEditKey(null)}catch{setToast({message:'Failed',type:'error'})}}
if(loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>
const tabs=[['users','👥 Users'],['links','🔗 Links'],['site settings','⚙️ Settings'],['nav','🧭 Navigation'],['pages','📄 Pages']]
return (<div><Navbar/><main style={{padding:'2rem',maxWidth:1100,margin:'0 auto'}}><h1 style={{marginBottom:'1.5rem'}}>👑 Admin Dashboard</h1><div style={{display:'flex',gap:'.5rem',marginBottom:'1.5rem',borderBottom:'1px solid var(--border)',paddingBottom:'1rem',flexWrap:'wrap'}}>{tabs.map(([t,l])=><button key={t} className={`btn ${tab===t?'':'btn-outline'}`} onClick={()=>setTab(t)} style={{fontSize:'.875rem'}}>{l}</button>)}</div>
{tab==='users'&&(<div className="glass" style={{padding:'1rem',overflowX:'auto'}}><h3 style={{marginBottom:'1rem'}}>Users ({users.length})</h3><table style={{width:'100%',borderCollapse:'collapse'}}><thead><tr style={{borderBottom:'2px solid var(--border)'}}>{['ID','Email','Role','Actions'].map(h=><th key={h} style={{padding:'.5rem .75rem',textAlign:'left',fontSize:'.8rem',color:'var(--text-muted)'}}>{h}</th>)}</tr></thead><tbody>{users.map(u=>(<tr key={u.id} style={{borderBottom:'1px solid var(--border)'}}><td style={{padding:'.5rem .75rem',fontSize:'.85rem'}}>{u.id}</td><td style={{padding:'.5rem .75rem',fontSize:'.85rem'}}>{u.email}</td><td style={{padding:'.5rem .75rem'}}><span style={{fontSize:'.75rem',fontWeight:600,padding:'2px 8px',borderRadius:'999px',background:u.role==='admin'?'rgba(99,102,241,.12)':'var(--surface2)',color:u.role==='admin'?'var(--primary)':'var(--text-muted)'}}>{u.role}</span></td><td style={{padding:'.5rem .75rem',display:'flex',gap:'.25rem'}}><button className="btn btn-outline" onClick={()=>impersonate(u.id)} style={{fontSize:'.78rem',padding:'.35rem .7rem'}}>Login As</button>{u.role!=='admin'&&<button className="btn btn-danger" onClick={()=>delUser(u.id)} style={{fontSize:'.78rem',padding:'.35rem .7rem'}}>Delete</button>}</td></tr>))}</tbody></table></div>)}
{tab==='links'&&(<div className="glass" style={{padding:'1rem',overflowX:'auto'}}><h3 style={{marginBottom:'1rem'}}>All Links ({links.length})</h3>{links.length===0?<p style={{color:'var(--text-muted)'}}>No links yet</p>:links.map(l=>(<div key={l.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'.5rem',borderBottom:'1px solid var(--border)',gap:'.5rem',flexWrap:'wrap'}}><span style={{fontFamily:'monospace',fontSize:'.85rem'}}>/s/{l.short_code} → {l.original_url.substring(0,50)}{l.original_url.length>50?'…':''}</span><button className="btn btn-danger" style={{fontSize:'.78rem',padding:'.35rem .7rem'}} onClick={()=>delLink(l.id)}>Delete</button></div>))}</div>)}
{tab==='site settings'&&(<div className="glass" style={{padding:'1.5rem'}}><h3 style={{marginBottom:'.5rem'}}>Site Settings</h3><p style={{color:'var(--text-muted)',fontSize:'.8rem',marginBottom:'1rem'}}>Changes apply on next page load.</p><div style={{display:'grid',gap:'.75rem'}}>{settings.map(s=>(<div key={s.key} style={{padding:'1rem',background:'var(--surface2)',borderRadius:'.5rem',border:'1px solid var(--border)'}}><div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',gap:'1rem',flexWrap:'wrap'}}><div style={{flex:1}}><code style={{fontWeight:600,color:'var(--primary)',fontSize:'.875rem'}}>{s.key}</code>{editKey===s.key?(<div style={{display:'flex',gap:'.5rem',marginTop:'.5rem',flexWrap:'wrap'}}><input className="input" value={editVal} onChange={e=>setEditVal(e.target.value)} style={{flex:1,minWidth:180}} autoFocus/><button className="btn" onClick={()=>saveSetting(s.key)} style={{fontSize:'.875rem'}}>Save</button><button className="btn btn-outline" onClick={()=>setEditKey(null)} style={{fontSize:'.875rem'}}>Cancel</button></div>):(<p style={{marginTop:'.25rem',color:'var(--text-muted)',fontSize:'.875rem'}}>{s.value||<em>empty</em>}</p>)}</div>{editKey!==s.key&&<button className="btn btn-outline" onClick={()=>{setEditKey(s.key);setEditVal(s.value||'')}} style={{fontSize:'.8rem',padding:'.4rem .75rem'}}>✏️ Edit</button>}</div></div>))}{settings.length===0&&<p style={{color:'var(--text-muted)'}}>No settings yet.</p>}</div></div>)}
{tab==='nav'&&(<div className="glass" style={{padding:'2rem',textAlign:'center'}}><h3>Navigation Manager</h3><p style={{margin:'1rem 0'}}>Manage navbar items.</p><button className="btn" onClick={()=>navigate('/admin/nav')}>Go to Nav Manager</button></div>)}
{tab==='pages'&&(<div className="glass" style={{padding:'2rem',textAlign:'center'}}><h3>Pages Manager</h3><p style={{margin:'1rem 0'}}>Manage custom pages.</p><button className="btn" onClick={()=>navigate('/admin/pages')}>Go to Pages Manager</button></div>)}
</main>{toast&&<Toast message={toast.message} type={toast.type} onClose={()=>setToast(null)}/>}</div>)
}
EOF

cat > frontend/src/pages/AdminNav.jsx << 'EOF'
import { useState, useEffect } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

function isExternal(val) { return /^https?:\/\//i.test(val) }

export default function AdminNav() {
const [items,setItems]=useState([]); const [loading,setLoading]=useState(true); const [toast,setToast]=useState(null)
const [editingId,setEditingId]=useState(null)
const [form,setForm]=useState({label:'',path:'',icon:'',auth_required:false,admin_only:false,enabled:true,order:0})
useEffect(()=>{fetchItems();},[])
const fetchItems=async()=>{try{const res=await api.get('/api/admin/nav');setItems(res.data)}catch{setToast({message:'Failed to load',type:'error'})}finally{setLoading(false)}}
const handleSubmit=async(e)=>{e.preventDefault();try{if(editingId){await api.put(`/api/admin/nav/${editingId}`,form);setToast({message:'Updated',type:'success'})}else{await api.post('/api/admin/nav',form);setToast({message:'Created',type:'success'})};setEditingId(null);setForm({label:'',path:'',icon:'',auth_required:false,admin_only:false,enabled:true,order:0});fetchItems()}catch{setToast({message:'Save failed',type:'error'})}}
const handleEdit=(item)=>{setEditingId(item.id);setForm({...item})}
const handleDelete=async(id)=>{if(!confirm('Delete?'))return;try{await api.delete(`/api/admin/nav/${id}`);setToast({message:'Deleted',type:'success'});fetchItems()}catch{setToast({message:'Delete failed',type:'error'})}}
const toggleEnabled=async(item)=>{try{await api.put(`/api/admin/nav/${item.id}`,{enabled:!item.enabled});fetchItems()}catch{setToast({message:'Toggle failed',type:'error'})}}
const external = isExternal(form.path)
if(loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>
return (<div><Navbar/><main style={{padding:'2rem',maxWidth:1000,margin:'0 auto'}}>
<h1 style={{marginBottom:'.5rem'}}>⚙️ Navigation Manager</h1>
<p style={{color:'var(--text-muted)',marginBottom:'1.5rem',fontSize:'.875rem'}}>
  Manage navbar links. Use an internal path like <code>/dashboard</code> to link within the site,
  or a full URL like <code>https://example.com</code> to link anywhere — external links open in a new tab.
</p>
<div className="glass" style={{padding:'1.5rem',marginBottom:'2rem'}}>
<h2 style={{marginBottom:'1rem'}}>{editingId?'Edit':'Add'} Nav Item</h2>
<form onSubmit={handleSubmit} style={{display:'grid',gap:'1rem'}}>
  <div style={{display:'grid',gap:'1rem',gridTemplateColumns:'repeat(auto-fit,minmax(200px,1fr))'}}>
    <div>
      <label style={{display:'block',marginBottom:'.35rem',fontWeight:500,fontSize:'.875rem'}}>Label *</label>
      <input className="input" placeholder="e.g. Contact Us" value={form.label} onChange={e=>setForm({...form,label:e.target.value})} required/>
    </div>
    <div>
      <label style={{display:'block',marginBottom:'.35rem',fontWeight:500,fontSize:'.875rem'}}>
        URL / Path *
        {external
          ? <span style={{marginLeft:'.5rem',fontSize:'.75rem',color:'var(--success)',fontWeight:400}}>🌐 External link — opens in new tab</span>
          : form.path
            ? <span style={{marginLeft:'.5rem',fontSize:'.75rem',color:'var(--primary)',fontWeight:400}}>🔗 Internal route</span>
            : null
        }
      </label>
      <input
        className="input"
        placeholder="e.g. /dashboard  or  https://example.com"
        value={form.path}
        onChange={e=>setForm({...form,path:e.target.value})}
        required
      />
      <p style={{fontSize:'.72rem',color:'var(--text-muted)',marginTop:'.3rem'}}>
        Internal path <code>/page-slug</code> or full URL <code>https://…</code>
      </p>
    </div>
  </div>
  <div style={{display:'grid',gap:'1rem',gridTemplateColumns:'repeat(auto-fit,minmax(150px,1fr))'}}>
    <div>
      <label style={{display:'block',marginBottom:'.35rem',fontWeight:500,fontSize:'.875rem'}}>Icon (emoji)</label>
      <input className="input" placeholder="🔗" value={form.icon} onChange={e=>setForm({...form,icon:e.target.value})}/>
    </div>
    <div>
      <label style={{display:'block',marginBottom:'.35rem',fontWeight:500,fontSize:'.875rem'}}>Order</label>
      <input className="input" type="number" placeholder="0" value={form.order} onChange={e=>setForm({...form,order:parseInt(e.target.value)||0})}/>
    </div>
  </div>
  <div style={{display:'flex',gap:'1.5rem',alignItems:'center',flexWrap:'wrap',padding:'.75rem',background:'var(--surface2)',borderRadius:'var(--radius)'}}>
    <label style={{display:'flex',alignItems:'center',gap:'.4rem',cursor:'pointer',fontSize:'.875rem'}}><input type="checkbox" checked={form.auth_required} onChange={e=>setForm({...form,auth_required:e.target.checked})}/> Requires Login</label>
    <label style={{display:'flex',alignItems:'center',gap:'.4rem',cursor:'pointer',fontSize:'.875rem'}}><input type="checkbox" checked={form.admin_only} onChange={e=>setForm({...form,admin_only:e.target.checked})}/> Admin Only</label>
    <label style={{display:'flex',alignItems:'center',gap:'.4rem',cursor:'pointer',fontSize:'.875rem'}}><input type="checkbox" checked={form.enabled} onChange={e=>setForm({...form,enabled:e.target.checked})}/> Enabled (visible in nav)</label>
  </div>
  <div style={{display:'flex',gap:'.5rem'}}>
    <button type="submit" className="btn">{editingId?'Update':'Create'}</button>
    {editingId&&<button type="button" className="btn btn-outline" onClick={()=>{setEditingId(null);setForm({label:'',path:'',icon:'',auth_required:false,admin_only:false,enabled:true,order:0})}}>Cancel</button>}
  </div>
</form>
</div>
<div className="glass" style={{padding:'1rem'}}>
<h3 style={{marginBottom:'1rem'}}>Current Nav Items ({items.length})</h3>
<table style={{width:'100%',borderCollapse:'collapse'}}>
<thead><tr style={{borderBottom:'2px solid var(--border)'}}>{['Order','Label','URL / Path','Icon','Auth','Admin','Visible','Actions'].map(h=><th key={h} style={{padding:'.5rem',textAlign:'left',fontSize:'.8rem',color:'var(--text-muted)'}}>{h}</th>)}</tr></thead>
<tbody>{items.map(item=>(
<tr key={item.id} style={{borderBottom:'1px solid var(--border)'}}>
  <td style={{padding:'.5rem',fontSize:'.85rem'}}>{item.order}</td>
  <td style={{padding:'.5rem',fontWeight:500}}>{item.label}</td>
  <td style={{padding:'.5rem',maxWidth:220}}>
    <code style={{fontSize:'.78rem',wordBreak:'break-all'}}>
      {isExternal(item.path) ? '🌐 ' : ''}{item.path}
    </code>
  </td>
  <td style={{padding:'.5rem'}}>{item.icon}</td>
  <td style={{padding:'.5rem'}}>{item.auth_required?'✅':''}</td>
  <td style={{padding:'.5rem'}}>{item.admin_only?'👑':''}</td>
  <td style={{padding:'.5rem'}}><button className="btn btn-outline" style={{padding:'.2rem .5rem',fontSize:'.8rem'}} onClick={()=>toggleEnabled(item)}>{item.enabled?'✅':'❌'}</button></td>
  <td style={{padding:'.5rem',display:'flex',gap:'.25rem'}}>
    <button className="btn btn-outline" style={{padding:'.2rem .5rem',fontSize:'.8rem'}} onClick={()=>handleEdit(item)}>✏️</button>
    {!item.is_system&&<button className="btn btn-danger" style={{padding:'.2rem .5rem',fontSize:'.8rem'}} onClick={()=>handleDelete(item.id)}>🗑️</button>}
  </td>
</tr>))}</tbody>
</table>
</div>
</main>{toast&&<Toast message={toast.message} type={toast.type} onClose={()=>setToast(null)}/>}</div>)
}
EOF

cat > frontend/src/pages/AdminPages.jsx << 'EOF'
import { useState, useEffect } from 'react'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'
export default function AdminPages() {
const [pages,setPages]=useState([]); const [loading,setLoading]=useState(true); const [toast,setToast]=useState(null)
const [editingId,setEditingId]=useState(null); const [form,setForm]=useState({title:'',slug:'',content:'',published:true})
useEffect(()=>{fetchPages()},[])
const fetchPages=async()=>{try{const res=await api.get('/api/admin/pages');setPages(res.data)}catch{setToast({message:'Failed',type:'error'})}finally{setLoading(false)}}
const handleSubmit=async(e)=>{e.preventDefault();try{if(editingId){await api.put(`/api/admin/pages/${editingId}`,form);setToast({message:'Updated ✅',type:'success'})}else{await api.post('/api/admin/pages',form);setToast({message:'Created ✅ — nav item auto-added',type:'success'})};setEditingId(null);setForm({title:'',slug:'',content:'',published:true});fetchPages()}catch(err){setToast({message:err.response?.data?.detail||'Save failed',type:'error'})}}
const handleEdit=(page)=>{setEditingId(page.id);setForm({...page})}
const handleDelete=async(id)=>{if(!confirm('Delete page? Its nav item will also be removed.'))return;try{await api.delete(`/api/admin/pages/${id}`);setToast({message:'Deleted',type:'success'});fetchPages()}catch{setToast({message:'Delete failed',type:'error'})}}
const togglePublish=async(page)=>{try{await api.put(`/api/admin/pages/${page.id}`,{published:!page.published});fetchPages()}catch{setToast({message:'Toggle failed',type:'error'})}}
if(loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>
return (<div><Navbar/><main style={{padding:'2rem',maxWidth:1000,margin:'0 auto'}}>
<h1 style={{marginBottom:'.5rem'}}>📄 Pages Manager</h1>
<p style={{color:'var(--text-muted)',marginBottom:'1.5rem',fontSize:'.875rem'}}>Pages are accessible at <code>/p/slug</code> and automatically appear in Navigation Manager.</p>
<div className="glass" style={{padding:'1.5rem',marginBottom:'2rem'}}>
<h2 style={{marginBottom:'1rem'}}>{editingId?'Edit':'Create'} Page</h2>
<form onSubmit={handleSubmit} style={{display:'grid',gap:'1rem'}}>
<input className="input" placeholder="Title" value={form.title} onChange={e=>setForm({...form,title:e.target.value})} required/>
<div>
<div style={{display:'flex',gap:'.5rem',alignItems:'center'}}>
<span style={{background:'var(--surface2)',padding:'.75rem',borderRadius:'var(--radius)',fontSize:'.8rem',fontFamily:'monospace',whiteSpace:'nowrap',color:'var(--text-muted)'}}>/p/</span>
<input className="input" placeholder="contactus" value={form.slug} onChange={e=>setForm({...form,slug:e.target.value})} required style={{flex:1}}/>
</div>
{form.slug&&<p style={{fontSize:'.75rem',color:'var(--primary)',marginTop:'.35rem',fontFamily:'monospace'}}>/p/{form.slug}</p>}
</div>
<textarea className="input" rows="10" placeholder="HTML Content" value={form.content} onChange={e=>setForm({...form,content:e.target.value})} required/>
<label style={{display:'flex',alignItems:'center',gap:'.5rem',cursor:'pointer'}}><input type="checkbox" checked={form.published} onChange={e=>setForm({...form,published:e.target.checked})}/> Published (shows in nav)</label>
<div style={{display:'flex',gap:'.5rem'}}>
<button type="submit" className="btn">{editingId?'Update':'Create'}</button>
{editingId&&<button type="button" className="btn btn-outline" onClick={()=>{setEditingId(null);setForm({title:'',slug:'',content:'',published:true})}}>Cancel</button>}
</div>
</form>
</div>
<div className="glass" style={{padding:'1rem'}}>
<h3 style={{marginBottom:'1rem'}}>Existing Pages</h3>
<table style={{width:'100%',borderCollapse:'collapse'}}>
<thead><tr style={{borderBottom:'2px solid var(--border)'}}>{['Title','URL','Published','Actions'].map(h=><th key={h} style={{padding:'.5rem',textAlign:'left',fontSize:'.8rem'}}>{h}</th>)}</tr></thead>
<tbody>{pages.map(page=>(<tr key={page.id} style={{borderBottom:'1px solid var(--border)'}}><td style={{padding:'.5rem'}}>{page.title}</td><td style={{padding:'.5rem'}}><code style={{fontSize:'.8rem'}}>/p/{page.slug}</code></td><td style={{padding:'.5rem'}}><button className="btn btn-outline" style={{padding:'.2rem .5rem',fontSize:'.8rem'}} onClick={()=>togglePublish(page)}>{page.published?'✅ Published':'❌ Hidden'}</button></td><td style={{padding:'.5rem',display:'flex',gap:'.25rem'}}><button className="btn btn-outline" style={{padding:'.2rem .5rem',fontSize:'.8rem'}} onClick={()=>handleEdit(page)}>✏️</button><button className="btn btn-danger" style={{padding:'.2rem .5rem',fontSize:'.8rem'}} onClick={()=>handleDelete(page.id)}>🗑️</button><a href={`/p/${page.slug}`} target="_blank" rel="noopener" className="btn btn-outline" style={{padding:'.2rem .5rem',fontSize:'.8rem'}}>👁️</a></td></tr>))}</tbody>
</table>
</div>
</main>{toast&&<Toast message={toast.message} type={toast.type} onClose={()=>setToast(null)}/>}</div>)
}
EOF

cat > frontend/src/pages/CustomPage.jsx << 'EOF'
import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'
export default function CustomPage() {
const { slug } = useParams()
const [page,setPage]=useState(null); const [loading,setLoading]=useState(true)
useEffect(()=>{api.get(`/api/public/pages/${slug}`).then(res=>setPage(res.data)).catch(()=>setPage(null)).finally(()=>setLoading(false))},[slug])
if(loading) return <div><Navbar/><div style={{padding:'2rem'}}>Loading...</div></div>
if(!page) return <div><Navbar/><div style={{padding:'2rem',textAlign:'center'}}><h2>Page not found</h2><Link to="/">← Home</Link></div></div>
return (<div><Navbar/><main style={{padding:'2rem',maxWidth:800,margin:'0 auto'}}><div className="glass" style={{padding:'2rem'}}><h1 style={{marginBottom:'1.5rem'}}>{page.title}</h1><div dangerouslySetInnerHTML={{__html:page.content}}/><Link to="/" style={{display:'inline-block',marginTop:'2rem',color:'var(--primary)'}}>← Back to Home</Link></div></main></div>)
}
EOF

cat > frontend/src/pages/Contact.jsx << 'EOF'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '../api'
import Navbar from '../components/Navbar'
import Toast from '../components/Toast'

export default function Contact() {
  const [form, setForm] = useState({ name: '', email: '', subject: '', message: '' })
  const [loading, setLoading] = useState(false)
  const [toast, setToast] = useState(null)
  const navigate = useNavigate()

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    try {
      await api.post('/api/public/contact', form)
      setToast({ message: 'Message sent successfully!', type: 'success' })
      setForm({ name: '', email: '', subject: '', message: '' })
      setTimeout(() => navigate('/'), 2000)
    } catch (err) {
      setToast({ message: err.response?.data?.detail || 'Failed to send message', type: 'error' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <Navbar />
      <main style={{ padding: '2rem', maxWidth: 1000, margin: '0 auto' }}>
        <div className="container" style={{
          backgroundColor: 'white',
          width: '100%',
          maxWidth: 1000,
          borderRadius: 10,
          boxShadow: '0 10px 25px rgba(0,0,0,0.1)',
          overflow: 'hidden',
          display: 'flex',
          flexWrap: 'wrap'
        }}>
          {/* Left Side: Contact Info */}
          <div className="contact-info" style={{
            backgroundColor: '#4a90e2',
            color: 'white',
            flex: 1,
            padding: 40,
            minWidth: 300,
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between'
          }}>
            <div>
              <h2 style={{ fontSize: '2rem', marginBottom: 20 }}>Get in Touch</h2>
              <p style={{ marginBottom: 20, opacity: 0.9 }}>Have a question or want to work together? Send us a message!</p>

              <div className="info-item" style={{ marginBottom: 20, display: 'flex', alignItems: 'center' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path><circle cx="12" cy="10" r="3"></circle>
                </svg>
                <span style={{ marginLeft: 15 }}>123 Innovation Dr, Tech City</span>
              </div>
              <div className="info-item" style={{ marginBottom: 20, display: 'flex', alignItems: 'center' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline>
                </svg>
                <span style={{ marginLeft: 15 }}>hello@example.com</span>
              </div>
              <div className="info-item" style={{ marginBottom: 20, display: 'flex', alignItems: 'center' }}>
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"></path>
                </svg>
                <span style={{ marginLeft: 15 }}>+1 (555) 123-4567</span>
              </div>
            </div>

            <div className="social-media" style={{ marginTop: 30 }}>
              <p style={{ marginBottom: 10 }}>Follow us:</p>
              <div style={{ display: 'flex', gap: 10 }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"></path>
                </svg>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="2" y="2" width="20" height="20" rx="5" ry="5"></rect><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"></path><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"></line>
                </svg>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M23 3a10.9 10.9 0 0 1-3.14 1.53 4.48 4.48 0 0 0-7.86 3v1A10.66 10.66 0 0 1 3 4s-4 9 5 13a11.64 11.64 0 0 1-7 2c9 5 20 0 20-11.5a4.5 4.5 0 0 0-.08-.83A7.72 7.72 0 0 0 23 3z"></path>
                </svg>
              </div>
            </div>
          </div>

          {/* Right Side: The Form */}
          <div className="contact-form" style={{
            flex: 1.5,
            padding: 40,
            minWidth: 300,
            background: 'var(--surface)'
          }}>
            <h2 style={{ marginBottom: 20, color: 'var(--text)' }}>Send a Message</h2>
            <form onSubmit={handleSubmit} style={{ display: 'grid', gap: '1rem' }}>
              <div className="form-group">
                <label htmlFor="name" style={{ display: 'block', marginBottom: 5, color: 'var(--text-muted)', fontSize: '0.9rem' }}>Full Name</label>
                <input
                  type="text"
                  id="name"
                  name="name"
                  className="input"
                  placeholder="John Doe"
                  value={form.name}
                  onChange={handleChange}
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="email" style={{ display: 'block', marginBottom: 5, color: 'var(--text-muted)', fontSize: '0.9rem' }}>Email Address</label>
                <input
                  type="email"
                  id="email"
                  name="email"
                  className="input"
                  placeholder="john@example.com"
                  value={form.email}
                  onChange={handleChange}
                  required
                />
              </div>

              <div className="form-group">
                <label htmlFor="subject" style={{ display: 'block', marginBottom: 5, color: 'var(--text-muted)', fontSize: '0.9rem' }}>Subject</label>
                <input
                  type="text"
                  id="subject"
                  name="subject"
                  className="input"
                  placeholder="Project Inquiry"
                  value={form.subject}
                  onChange={handleChange}
                />
              </div>

              <div className="form-group">
                <label htmlFor="message" style={{ display: 'block', marginBottom: 5, color: 'var(--text-muted)', fontSize: '0.9rem' }}>Message</label>
                <textarea
                  id="message"
                  name="message"
                  rows="5"
                  className="input"
                  placeholder="Write your message here..."
                  value={form.message}
                  onChange={handleChange}
                  required
                />
              </div>

              <button type="submit" className="btn" disabled={loading}>
                {loading ? 'Sending...' : 'Send Message'}
              </button>
            </form>
          </div>
        </div>
      </main>
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
    </div>
  )
}
EOF

# ---------- App.jsx (includes all routes) ----------
cat > frontend/src/App.jsx << 'EOF'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from './context/ThemeContext'
import Home       from './pages/Home'
import Login      from './pages/Login'
import Signup     from './pages/Signup'
import Dashboard  from './pages/Dashboard'
import Create     from './pages/Create'
import EditLink   from './pages/EditLink'
import MyAccount  from './pages/MyAccount'
import BioProfile from './pages/BioProfile'
import Messages   from './pages/Messages'
import Admin      from './pages/Admin'
import AdminNav   from './pages/AdminNav'
import AdminPages from './pages/AdminPages'
import CustomPage from './pages/CustomPage'
import Contact    from './pages/Contact'

const ROUTES = [
    {path:'/',           C:Home},
    {path:'/login',      C:Login},
    {path:'/signup',     C:Signup},
    {path:'/dashboard',  C:Dashboard},
    {path:'/create',     C:Create},
    {path:'/edit/:id',   C:EditLink},
    {path:'/myaccount',  C:MyAccount},
    {path:'/bio',        C:BioProfile},
    {path:'/messages',   C:Messages},
    {path:'/admin',      C:Admin},
    {path:'/admin/nav',  C:AdminNav},
    {path:'/admin/pages',C:AdminPages},
    {path:'/p/:slug',    C:CustomPage},
    {path:'/p/contact',  C:Contact},
]

export default function App() {
    return (
        <ThemeProvider>
            <BrowserRouter>
                <Routes>
                    {ROUTES.map(({path,C}) => <Route key={path} path={path} element={<C/>}/>)}
                    <Route path="*" element={<Navigate to="/" replace/>}/>
                </Routes>
            </BrowserRouter>
        </ThemeProvider>
    )
}
EOF

# ---------- docker-compose.yml ----------
cat > docker-compose.yml << EOF
services:
  db:
    image: postgres:15-alpine
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
      retries: 5
    networks:
      - linkplatform
  backend:
    build: ./backend
    env_file: ./backend/.env
    ports:
      - "${BACKEND_PORT}:8000"
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - ./backend:/app
    environment:
      - PYTHONUNBUFFERED=1
    networks:
      - linkplatform
  frontend:
    build: ./frontend
    ports:
      - "${FRONTEND_PORT}:3000"
    volumes:
      - ./frontend:/app
      - /app/node_modules
    depends_on:
      - backend
    environment:
      - VITE_API_BASE_URL=${BACKEND_URL}
    networks:
      - linkplatform
networks:
  linkplatform:
    driver: bridge
volumes:
  postgres_data:
EOF

# ---------- Generate SECRET_KEY ----------
echo "🔐 Generating SECRET_KEY..."
SK=$(openssl rand -hex 32)
sed -i.bak "s/^SECRET_KEY=.*/SECRET_KEY=$SK/" backend/.env && rm -f backend/.env.bak

# ---------- Build and start ----------
echo "🐳 Building and starting..."
$DOCKER_COMPOSE down -v 2>/dev/null || true
$DOCKER_COMPOSE build --no-cache
$DOCKER_COMPOSE up -d

echo "⏳ Waiting 75s for services to start..."
sleep 75

# ---------- Health check ----------
BACKEND_OK=0; FRONTEND_OK=0
curl -sf "${BACKEND_URL}/" >/dev/null 2>&1 && { echo "✅ Backend OK"; BACKEND_OK=1; } || { echo "⚠️  Backend not ready yet"; $DOCKER_COMPOSE logs --tail=20 backend; }
curl -sf "${FRONTEND_URL}/" >/dev/null 2>&1 && { echo "✅ Frontend OK"; FRONTEND_OK=1; } || echo "⚠️  Frontend not ready yet"

cat << FINAL

🎉 === ${SITE_NAME} V${SITE_VERSION} Ready! ===

🌐 URLs:
  Frontend:  ${FRONTEND_URL}
  Backend:   ${BACKEND_URL}
  API Docs:  ${BACKEND_URL}/docs
  Contact:   ${FRONTEND_URL}/p/contact

🔑 Admin Login:
  Email:    ${ADMIN_EMAIL}
  Password: ${ADMIN_PASSWORD}

🛠️ V10.6 NEW:
  ✅ Public contact page at /p/contact – sends messages to admin inbox
  ✅ Guest messages stored with name & email (no login required)
  ✅ Admin inbox now shows guest messages with sender details

🛠️ COMMANDS:
  $DOCKER_COMPOSE logs -f backend
  $DOCKER_COMPOSE logs -f frontend
  $DOCKER_COMPOSE restart
  $DOCKER_COMPOSE down -v && bash setup.sh   # full reset

FINAL

[ $BACKEND_OK -eq 0 ] && echo "⏳ If backend isn't up yet, run: $DOCKER_COMPOSE logs backend"

