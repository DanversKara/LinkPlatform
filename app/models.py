"""SQLAlchemy ORM models.

All database access goes through these models using SQLAlchemy ``select()``
and ORM APIs. There is no raw SQL anywhere in the application.

Relationships are intentionally omitted: every query is explicit and the
async session never triggers lazy loading. Deletes cascade at the database
level via ``ondelete`` rules (SQLite enforces them through the
``PRAGMA foreign_keys=ON`` set in :mod:`app.db`).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, TypeDecorator
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class TZDateTime(TypeDecorator):
    """DateTime that stays timezone-aware on SQLite.

    SQLite drops tzinfo on storage, which makes naive-vs-aware comparisons
    raise ``TypeError``. This type normalizes naive values to UTC on write
    and re-attaches UTC on read so every datetime in the app is aware.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(80), default="")
    role: Mapped[str] = mapped_column(String(16), default="user")
    is_active: Mapped[bool] = mapped_column(default=True)
    slug: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    bio: Mapped[str] = mapped_column(Text, default="")
    avatar_path: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, default=None)
    theme: Mapped[str] = mapped_column(String(32), default="default")
    accent_color: Mapped[str] = mapped_column(String(7), default="#6366f1")
    # JSON blob of bio-page appearance prefs (see app/bio_style.py).
    bio_prefs: Mapped[str] = mapped_column(Text, default="")
    # Set by an admin: shows the "Verified" badge on the public bio page.
    is_verified: Mapped[bool] = mapped_column(default=False)
    must_change_password: Mapped[bool] = mapped_column(default=False)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(TZDateTime, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class Link(Base):
    __tablename__ = "links"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    domain_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("domains.id", ondelete="SET NULL"), nullable=True, default=None, index=True
    )
    original_url: Mapped[str] = mapped_column(Text)
    title: Mapped[str] = mapped_column(String(200), default="")
    is_active: Mapped[bool] = mapped_column(default=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(TZDateTime, nullable=True, default=None)
    landing_enabled: Mapped[bool] = mapped_column(default=False)
    landing_title: Mapped[str] = mapped_column(String(200), default="")
    landing_body: Mapped[str] = mapped_column(Text, default="")
    landing_image: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, default=None)
    clicks_cached: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (Index("ix_links_user_created", "user_id", "created_at"),)


class Click(Base):
    __tablename__ = "clicks"

    id: Mapped[int] = mapped_column(primary_key=True)
    link_id: Mapped[int] = mapped_column(ForeignKey("links.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, index=True)
    ip_hash: Mapped[str] = mapped_column(String(64), default="", index=True)
    ua: Mapped[str] = mapped_column(String(500), default="")
    referer: Mapped[str] = mapped_column(Text, default="")
    country: Mapped[str] = mapped_column(String(64), default="")
    device: Mapped[str] = mapped_column(String(32), default="")
    browser: Mapped[str] = mapped_column(String(32), default="")
    os_name: Mapped[str] = mapped_column(String(32), default="")

    __table_args__ = (Index("ix_clicks_link_ts", "link_id", "ts"),)


class ProfileView(Base):
    __tablename__ = "profile_views"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, index=True)
    ip_hash: Mapped[str] = mapped_column(String(64), default="")
    referer: Mapped[str] = mapped_column(Text, default="")
    country: Mapped[str] = mapped_column(String(64), default="")
    device: Mapped[str] = mapped_column(String(32), default="")


class BioLink(Base):
    __tablename__ = "bio_links"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(100))
    url: Mapped[str] = mapped_column(Text)
    position: Mapped[int] = mapped_column(default=0)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    # Rich content (added in v12.1): brand icon key, sub-description, section.
    icon: Mapped[str] = mapped_column(String(40), default="")
    description: Mapped[str] = mapped_column(String(600), default="")
    section: Mapped[str] = mapped_column(String(60), default="")
    # link | copy | text | notice_warn | notice_info  (see bio_style.LINK_KINDS)
    kind: Mapped[str] = mapped_column(String(16), default="link")
    # optional icon-tile colour override, "#rrggbb" or ""
    color: Mapped[str] = mapped_column(String(7), default="")

    __table_args__ = (Index("ix_bio_links_user_pos", "user_id", "position"),)


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="pending")
    root_url: Mapped[str] = mapped_column(Text, default="")
    notfound_url: Mapped[str] = mapped_column(Text, default="")
    verified_at: Mapped[Optional[datetime]] = mapped_column(TZDateTime, nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class StoredFile(Base):
    __tablename__ = "stored_files"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    stored_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    original_name: Mapped[str] = mapped_column(String(255), default="")
    mime: Mapped[str] = mapped_column(String(100), default="application/octet-stream")
    size: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)

    @property
    def url(self) -> str:
        return f"/uploads/{self.stored_name}"


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_slug: Mapped[str] = mapped_column(String(30), index=True)
    reporter_email: Mapped[str] = mapped_column(String(254), default="")
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="open")
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(60))
    prefix: Mapped[str] = mapped_column(String(16), default="")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scopes: Mapped[str] = mapped_column(String(255), default="links:read links:write")
    last_used_at: Mapped[Optional[datetime]] = mapped_column(TZDateTime, nullable=True, default=None)
    revoked: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[Optional[int]] = mapped_column(nullable=True, default=None, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    ts: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, index=True)


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(TZDateTime, index=True)
    ip: Mapped[str] = mapped_column(String(64), default="")
    ua: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
