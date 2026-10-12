"""Async click/view tracking: in-memory queue plus a batched DB writer.

Redirects stay fast because they only ``put_nowait`` an event. A single
background task drains the queue, bulk-inserts rows, bumps the cached
click counters, and enforces the click retention window.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import delete, insert, update

from .db import AsyncSessionLocal
from .models import Click, Link, ProfileView, Setting
from .utils import utcnow

log = logging.getLogger("linkplatform.tracking")


@dataclass
class ClickEvent:
    link_id: int
    ip_hash: str
    ua: str = ""
    referer: str = ""
    country: str = ""
    device: str = ""
    browser: str = ""
    os_name: str = ""
    ts: datetime = field(default_factory=utcnow)


@dataclass
class ViewEvent:
    user_id: int
    ip_hash: str = ""
    referer: str = ""
    country: str = ""
    device: str = ""
    ts: datetime = field(default_factory=utcnow)


_queue: asyncio.Queue = asyncio.Queue(maxsize=20000)


async def enqueue_click(event: ClickEvent) -> None:
    try:
        _queue.put_nowait(("click", event))
    except asyncio.QueueFull:
        pass


async def enqueue_view(event: ViewEvent) -> None:
    try:
        _queue.put_nowait(("view", event))
    except asyncio.QueueFull:
        pass


async def _drain_batch(max_items: int = 500, wait_seconds: float = 5.0) -> list:
    batch: list = []
    try:
        batch.append(await asyncio.wait_for(_queue.get(), timeout=wait_seconds))
    except asyncio.TimeoutError:
        return batch
    while len(batch) < max_items:
        try:
            batch.append(_queue.get_nowait())
        except asyncio.QueueEmpty:
            break
    return batch


async def _write_batch(batch: list) -> None:
    clicks = [e for kind, e in batch if kind == "click"]
    views = [e for kind, e in batch if kind == "view"]
    async with AsyncSessionLocal() as db:
        try:
            if clicks:
                await db.execute(
                    insert(Click),
                    [
                        {
                            "link_id": e.link_id,
                            "ts": e.ts,
                            "ip_hash": e.ip_hash,
                            "ua": e.ua[:500],
                            "referer": e.referer[:2048],
                            "country": e.country[:64],
                            "device": e.device[:32],
                            "browser": e.browser[:32],
                            "os_name": e.os_name[:32],
                        }
                        for e in clicks
                    ],
                )
                counts: dict[int, int] = {}
                for e in clicks:
                    counts[e.link_id] = counts.get(e.link_id, 0) + 1
                for link_id, n in counts.items():
                    await db.execute(
                        update(Link)
                        .where(Link.id == link_id)
                        .values(clicks_cached=Link.clicks_cached + n)
                    )
            if views:
                await db.execute(
                    insert(ProfileView),
                    [
                        {
                            "user_id": e.user_id,
                            "ts": e.ts,
                            "ip_hash": e.ip_hash,
                            "referer": e.referer[:2048],
                            "country": e.country[:64],
                            "device": e.device[:32],
                        }
                        for e in views
                    ],
                )
            await db.commit()
        except Exception:
            await db.rollback()
            raise


async def _apply_retention() -> None:
    async with AsyncSessionLocal() as db:
        try:
            days = 90
            row = await db.get(Setting, "click_retention_days")
            if row is not None:
                try:
                    days = max(1, int(row.value))
                except (TypeError, ValueError):
                    pass
            cutoff = utcnow() - timedelta(days=days)
            await db.execute(delete(Click).where(Click.ts < cutoff))
            await db.execute(delete(ProfileView).where(ProfileView.ts < cutoff))
            await db.commit()
        except Exception:
            await db.rollback()
            raise


async def click_writer(app) -> None:
    """Background task: drain the queue forever. Never crashes the loop."""
    last_cleanup = 0.0
    while True:
        try:
            batch = await _drain_batch()
            if batch:
                await _write_batch(batch)
            now = asyncio.get_event_loop().time()
            if now - last_cleanup > 3600:
                await _apply_retention()
                last_cleanup = now
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("tracking writer error; continuing")
            await asyncio.sleep(5)


async def flush_tracking() -> None:
    """Drain any queued events (called on shutdown)."""
    while True:
        batch: list = []
        while len(batch) < 500:
            try:
                batch.append(_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if not batch:
            break
        try:
            await _write_batch(batch)
        except Exception:
            log.exception("tracking flush error")
            break
