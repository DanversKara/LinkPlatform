"""Async SQLAlchemy engine, session factory, and startup helpers."""
from __future__ import annotations

import os
import secrets

from sqlalchemy import event, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings
from .models import Base, Setting, User
from .security import hash_password

os.makedirs(settings.DATA_DIR, exist_ok=True)

engine = create_async_engine(
    f"sqlite+aiosqlite:///{settings.DATA_DIR}/app.db",
    connect_args={"check_same_thread": False},
)


@event.listens_for(engine.sync_engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


# Lightweight additive migrations for SQLite. create_all() never adds
# columns to existing tables, so each (table, column, ddl) here is applied
# idempotently on startup.
MIGRATIONS: list[tuple[str, str, str]] = [
    ("bio_links", "icon", "ALTER TABLE bio_links ADD COLUMN icon VARCHAR(40) NOT NULL DEFAULT ''"),
    ("bio_links", "description", "ALTER TABLE bio_links ADD COLUMN description VARCHAR(160) NOT NULL DEFAULT ''"),
    ("bio_links", "section", "ALTER TABLE bio_links ADD COLUMN section VARCHAR(60) NOT NULL DEFAULT ''"),
    ("bio_links", "kind", "ALTER TABLE bio_links ADD COLUMN kind VARCHAR(16) NOT NULL DEFAULT 'link'"),
    ("bio_links", "color", "ALTER TABLE bio_links ADD COLUMN color VARCHAR(7) NOT NULL DEFAULT ''"),
    ("users", "bio_prefs", "ALTER TABLE users ADD COLUMN bio_prefs TEXT NOT NULL DEFAULT ''"),
    ("users", "is_verified", "ALTER TABLE users ADD COLUMN is_verified BOOLEAN NOT NULL DEFAULT 0"),
]


async def _apply_migrations(conn) -> None:
    for table, column, ddl in MIGRATIONS:
        cols = {r[1] for r in (await conn.exec_driver_sql(f"PRAGMA table_info({table})")).fetchall()}
        if not cols:
            continue  # table doesn't exist yet; create_all() will build it whole
        if column not in cols:
            await conn.exec_driver_sql(ddl)


async def get_db():
    """FastAPI dependency yielding a per-request async session."""
    async with AsyncSessionLocal() as session:
        yield session


DEFAULT_SETTINGS = {
    "site_name": settings.SITE_NAME,
    "site_tagline": settings.SITE_TAGLINE,
    "registration_open": "1" if settings.REGISTRATION_OPEN else "0",
    "click_retention_days": str(settings.CLICK_RETENTION_DAYS),
    "server_ip": "",
    "smtp_host": settings.SMTP_HOST,
    "smtp_port": str(settings.SMTP_PORT),
    "smtp_user": settings.SMTP_USER,
    "smtp_password": settings.SMTP_PASSWORD,
    "smtp_from": settings.SMTP_FROM,
}


async def init_db() -> None:
    """Create tables, seed default settings, and ensure an admin user exists."""
    os.makedirs(settings.DATA_DIR, exist_ok=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await _apply_migrations(conn)

    async with AsyncSessionLocal() as db:
        for key, value in DEFAULT_SETTINGS.items():
            if await db.get(Setting, key) is None:
                db.add(Setting(key=key, value=value))
        await db.commit()

        user_count = (await db.execute(select(func.count()).select_from(User))).scalar_one()
        if user_count == 0:
            password = settings.ADMIN_PASSWORD
            generated = False
            if not password:
                password = secrets.token_urlsafe(15)
                generated = True
            admin = User(
                email=settings.ADMIN_EMAIL.strip().lower(),
                password_hash=hash_password(password),
                display_name="Administrator",
                role="admin",
                slug="admin",
                must_change_password=True,
            )
            db.add(admin)
            await db.commit()
            if generated:
                print(f"ADMIN_PASSWORD_GENERATED={password}", flush=True)


async def backup_checkpoint() -> None:
    """Checkpoint the WAL file so backups capture a consistent database."""
    try:
        async with engine.connect() as conn:
            await conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    except Exception:
        pass
