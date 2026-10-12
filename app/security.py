"""Security primitives: password hashing, tokens, validators, IP handling."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import secrets
import time
from collections import deque
from urllib.parse import urlsplit

from pwdlib import PasswordHash

_ph = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Hash a password with Argon2id (pwdlib recommended hasher)."""
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time password verification. Never raises."""
    try:
        return bool(_ph.verify(password, password_hash))
    except Exception:
        return False


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_token(n: int = 32) -> str:
    return secrets.token_hex(n)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def random_password(n: int = 16) -> str:
    """Readable random password without ambiguous characters."""
    charset = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(charset) for _ in range(n))


_URL_MAX_LEN = 2048
_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
_SLUG_RE = re.compile(r"^[a-z0-9_]{3,30}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def valid_url(url: str | None) -> str | None:
    """Validate an http/https URL. Returns the normalized URL or None.

    Rejects non-http(s) schemes, embedded userinfo / ``@`` tricks, control
    characters, and overlong values.
    """
    if not url:
        return None
    url = url.strip()
    if not url or len(url) > _URL_MAX_LEN:
        return None
    if any(ord(c) < 32 for c in url):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https"):
        return None
    if not parts.hostname:
        return None
    if "@" in parts.netloc:
        return None
    return url


def valid_bio_url(url: str | None) -> str | None:
    """Validate a bio-page link URL. http(s) via valid_url, plus mailto:.

    Bio links render directly as <a href>, never through the /s/ redirector,
    so mailto: is safe here.
    """
    norm = valid_url(url)
    if norm:
        return norm
    u = (url or "").strip()
    if not u or len(u) > 500 or any(ord(c) < 32 for c in u):
        return None
    if not u.lower().startswith("mailto:"):
        return None
    addr = u[7:].split("?", 1)[0].strip()
    if "@" not in addr or len(addr) < 3:
        return None
    return u


def valid_code(code: str | None) -> str | None:
    if not code:
        return None
    return code if _CODE_RE.fullmatch(code) else None


def valid_slug(slug: str | None) -> str | None:
    if not slug:
        return None
    return slug if _SLUG_RE.fullmatch(slug) else None


def valid_domain(domain: str | None) -> str | None:
    """Validate a bare domain name (no scheme, no path). Returns it or None."""
    if not domain:
        return None
    domain = domain.strip().lower()
    if "://" in domain or "/" in domain or len(domain) > 253:
        return None
    return domain if _DOMAIN_RE.fullmatch(domain) else None


def valid_email(email: str | None) -> str | None:
    """Validate an email address. Returns the normalized address or None."""
    if not email:
        return None
    email = email.strip().lower()
    if len(email) < 5 or len(email) > 254:
        return None
    return email if _EMAIL_RE.fullmatch(email) else None


def valid_hex_color(color: str | None) -> str | None:
    if not color:
        return None
    return color if _HEX_COLOR_RE.fullmatch(color.strip()) else None


def _is_trusted_peer(peer: str) -> bool:
    try:
        ip = ipaddress.ip_address(peer)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def get_client_ip(request) -> str:
    """Best-effort client IP. Never raises.

    ``X-Forwarded-For`` is only trusted when TRUST_PROXY is enabled and the
    direct peer is loopback or a private address (i.e. our own reverse
    proxy). The LAST entry is used because our proxy appends the address it
    observed; earlier entries may be client-supplied.
    """
    try:
        peer = request.client.host if request.client else ""
    except Exception:
        peer = ""
    if not peer:
        return "0.0.0.0"
    try:
        from .config import settings

        if settings.TRUST_PROXY and _is_trusted_peer(peer):
            xff = request.headers.get("x-forwarded-for", "")
            if xff:
                last = xff.split(",")[-1].strip()
                try:
                    ipaddress.ip_address(last)
                    return last
                except ValueError:
                    pass
    except Exception:
        pass
    return peer


class RateLimiter:
    """In-memory sliding-window rate limiter."""

    def __init__(self, max_keys: int = 10000):
        self._hits: dict[str, deque[float]] = {}
        self._max_keys = max_keys

    def allowed(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        dq = self._hits.get(key)
        if dq is None:
            if len(self._hits) >= self._max_keys:
                self._hits.pop(next(iter(self._hits)))
            dq = deque()
            self._hits[key] = dq
        cutoff = now - window_seconds
        while dq and dq[0] <= cutoff:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True


def mask_ip(ip: str) -> str:
    """Mask an IP address for display (last octet / /48 for IPv6)."""
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            return ".".join(ip.split(".")[:3]) + ".0"
        return str(ipaddress.ip_network(f"{ip}/48", strict=False).network_address)
    except ValueError:
        return ""


def hash_ip(ip: str, salt: str) -> str:
    """One-way hash of an IP for privacy-preserving analytics."""
    return sha256_hex(f"{salt}|{ip}")
