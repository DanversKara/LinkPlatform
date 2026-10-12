"""Shared helpers: time formatting, codes, UA parsing, charts, QR, pagination."""
from __future__ import annotations

import html
import io
import math
import secrets
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import qrcode

CODE_CHARSET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def timeago(dt: datetime | None) -> str:
    if dt is None:
        return "never"
    seconds = max(0, (utcnow() - _as_utc(dt)).total_seconds())
    if seconds < 60:
        return "just now"
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes}m ago"
    hours = int(minutes // 60)
    if hours < 24:
        return f"{hours}h ago"
    days = int(hours // 24)
    if days < 7:
        return f"{days}d ago"
    weeks = int(days // 7)
    if weeks < 5:
        return f"{weeks}w ago"
    months = int(days // 30)
    if months < 12:
        return f"{months}mo ago"
    years = int(days // 365)
    return f"{years}y ago"


def fmt_dt(dt: datetime | None) -> str:
    if dt is None:
        return "-"
    return _as_utc(dt).strftime("%Y-%m-%d %H:%M UTC")


def gen_code(n: int = 6) -> str:
    """Random short code from an unambiguous charset (no 0/O/1/l)."""
    return "".join(secrets.choice(CODE_CHARSET) for _ in range(n))


_BOT_SUBSTRINGS = (
    "bot", "spider", "crawl", "slurp", "mediapartners", "facebookexternalhit",
    "embedly", "quora", "pinterest", "slack", "twitterbot", "linkedinbot",
    "whatsapp", "telegrambot", "discordbot", "curl", "wget", "python-requests",
    "go-http-client", "ahrefs", "semrush", "mj12bot", "baidu", "yandex",
    "headless", "phantomjs",
)


def parse_ua(ua: str | None) -> tuple[str, str, str]:
    """Hand-rolled user-agent parsing. Returns (device, browser, os)."""
    low = (ua or "").lower()
    if any(b in low for b in _BOT_SUBSTRINGS):
        return ("Bot", "Bot", "Unknown")

    if "ipad" in low:
        device = "Tablet"
    elif "android" in low and "mobile" not in low:
        device = "Tablet"
    elif "tablet" in low and "mobile" not in low:
        device = "Tablet"
    elif "mobile" in low or "iphone" in low or "ipod" in low or "android" in low:
        device = "Mobile"
    elif any(x in low for x in ("windows", "macintosh", "mac os", "linux", "x11", "cros")):
        device = "Desktop"
    else:
        device = "Unknown"

    if "windows" in low:
        os_name = "Windows"
    elif "cros" in low:
        os_name = "ChromeOS"
    elif "iphone" in low or "ipad" in low or "ipod" in low:
        os_name = "iOS"
    elif "android" in low:
        os_name = "Android"
    elif "mac os" in low or "macintosh" in low:
        os_name = "macOS"
    elif "linux" in low:
        os_name = "Linux"
    else:
        os_name = "Unknown"

    if "edg/" in low or "edge/" in low:
        browser = "Edge"
    elif "opr/" in low or "opera" in low:
        browser = "Opera"
    elif "vivaldi" in low:
        browser = "Vivaldi"
    elif "brave" in low:
        browser = "Brave"
    elif "samsungbrowser" in low:
        browser = "SamsungBrowser"
    elif "firefox" in low or "fxios" in low:
        browser = "Firefox"
    elif "crios" in low or "chrome" in low:
        browser = "Chrome"
    elif "safari" in low:
        browser = "Safari"
    else:
        browser = "Unknown"

    return (device, browser, os_name)


def ref_domain(referer: str | None) -> str:
    """Extract the host from a referer URL, or ''."""
    if not referer:
        return ""
    try:
        return (urlsplit(referer.strip()).hostname or "").lower()
    except ValueError:
        return ""


def _chart_labels(points: list[tuple[str, int]], n: int) -> list[int]:
    if n <= 2:
        return list(range(n))
    return list(dict.fromkeys([0, n // 2, n - 1]))


def svg_line_chart(points: list[tuple[str, int]], w: int = 560, h: int = 160) -> str:
    """Smooth line + area SVG chart. Values are ints; labels are date strings."""
    pad_l, pad_r, pad_t, pad_b = 8, 8, 14, 22
    iw, ih = w - pad_l - pad_r, h - pad_t - pad_b
    n = len(points)
    if n == 0:
        points = [("", 0)]
        n = 1
    max_v = max((int(v) for _, v in points), default=0)
    if max_v <= 0:
        max_v = 1

    def xy(i: int, v: int) -> tuple[float, float]:
        x = pad_l + (iw * i / (n - 1) if n > 1 else iw / 2)
        y = pad_t + ih * (1 - int(v) / max_v)
        return (round(x, 1), round(y, 1))

    coords = [xy(i, v) for i, (_, v) in enumerate(points)]
    d = f"M {coords[0][0]:.1f},{coords[0][1]:.1f}"
    for i in range(len(coords) - 1):
        p0 = coords[i - 1] if i > 0 else coords[i]
        p1 = coords[i]
        p2 = coords[i + 1]
        p3 = coords[i + 2] if i + 2 < len(coords) else p2
        c1 = (p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6)
        c2 = (p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6)
        d += (
            f" C {c1[0]:.1f},{c1[1]:.1f} {c2[0]:.1f},{c2[1]:.1f}"
            f" {p2[0]:.1f},{p2[1]:.1f}"
        )
    base = pad_t + ih
    area = f"{d} L {coords[-1][0]:.1f},{base:.1f} L {coords[0][0]:.1f},{base:.1f} Z"
    labels = ""
    for i in _chart_labels(points, n):
        label = html.escape(str(points[i][0]))
        x = pad_l + (iw * i / (n - 1) if n > 1 else iw / 2)
        labels += (
            f'<text x="{x:.1f}" y="{h - 6}" text-anchor="middle"'
            f' class="chart-label">{label}</text>'
        )
    return (
        f'<svg viewBox="0 0 {w} {h}" class="chart" role="img"'
        f' aria-label="activity chart">'
        f'<path d="{area}" class="chart-area"/>'
        f'<path d="{d}" class="chart-line" fill="none"/>'
        f'<text x="{pad_l}" y="{pad_t - 3}" class="chart-label">max {max_v}</text>'
        f"{labels}</svg>"
    )


def svg_bars(pairs: list[tuple[str, int]], w: int = 560, h: int = 180) -> str:
    """Vertical bar chart SVG. Labels are HTML-escaped."""
    pad_l, pad_r, pad_t, pad_b = 8, 8, 14, 40
    iw, ih = w - pad_l - pad_r, h - pad_t - pad_b
    n = len(pairs)
    if n == 0:
        return (
            f'<svg viewBox="0 0 {w} {h}" class="chart" role="img"'
            f' aria-label="bar chart"><text x="{w // 2}" y="{h // 2}"'
            f' text-anchor="middle" class="chart-label">No data yet</text></svg>'
        )
    max_v = max((int(v) for _, v in pairs), default=0)
    if max_v <= 0:
        max_v = 1
    slot = iw / n
    bar_w = min(slot * 0.6, 48)
    base = pad_t + ih
    parts = []
    for i, (label, value) in enumerate(pairs):
        value = int(value)
        bh = ih * value / max_v
        x = pad_l + slot * i + (slot - bar_w) / 2
        y = base - bh
        safe_label = html.escape(str(label)[:18])
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}"'
            f' height="{bh:.1f}" class="chart-bar" rx="3"/>'
            f'<text x="{x + bar_w / 2:.1f}" y="{base + 14}" text-anchor="middle"'
            f' class="chart-label">{safe_label}</text>'
            f'<text x="{x + bar_w / 2:.1f}" y="{y - 4:.1f}" text-anchor="middle"'
            f' class="chart-label">{value}</text>'
        )
    return (
        f'<svg viewBox="0 0 {w} {h}" class="chart" role="img"'
        f' aria-label="bar chart">{"".join(parts)}</svg>'
    )


def qr_png_bytes(text: str) -> bytes:
    """Render a QR code PNG for the given text."""
    img = qrcode.make(text, box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def paginate(total: int, page: int, per_page: int) -> dict:
    per_page = max(1, min(per_page, 100))
    pages = max(1, math.ceil(total / per_page)) if total else 1
    page = max(1, min(page, pages))
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
        "has_prev": page > 1,
        "has_next": page < pages,
        "prev": page - 1,
        "next": page + 1,
        "start": (page - 1) * per_page + 1 if total else 0,
        "end": min(page * per_page, total),
        "offset": (page - 1) * per_page,
    }


def flash(url: str, msg: str, type_: str = "success") -> str:
    """Append toast query params to a URL safely."""
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q["toast"] = msg
    q["toast_type"] = type_
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))
