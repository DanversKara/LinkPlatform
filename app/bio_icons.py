"""Brand + generic icons for bio links.

Self-hosted inline SVGs (no CDN -- the Content-Security-Policy blocks
third-party icon fonts). All icons draw in currentColor on a 24x24 grid.
Keys are validated against BIO_ICONS before render.
"""
from __future__ import annotations

_S = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">'
_T = "</svg>"

BIO_ICONS: dict[str, str] = {
    "youtube": _S + '<path d="M22 12s0-3.3-.42-4.86a2.5 2.5 0 0 0-1.76-1.76C18.25 5 12 5 12 5s-6.25 0-7.82.38A2.5 2.5 0 0 0 2.42 7.14C2 8.7 2 12 2 12s0 3.3.42 4.86a2.5 2.5 0 0 0 1.76 1.76c1.57.38 7.82.38 7.82.38s6.25 0 7.82-.38a2.5 2.5 0 0 0 1.76-1.76C22 15.3 22 12 22 12zm-11 3.5v-7l6 3.5-6 3.5z"/>' + _T,
    "x": _S + '<path d="M18.9 2H22l-6.8 7.8L23.3 22h-6.3l-4.9-6.4L6.5 22H3.4l7.3-8.3L1 2h6.4l4.4 5.9L18.9 2zm-1.1 18h1.7L7.6 3.9H5.7l12.1 16.1z"/>' + _T,
    "facebook": _S + '<path d="M13.5 22v-8h2.7l.4-3.2h-3.1V8.7c0-.9.3-1.6 1.6-1.6h1.7V4.2c-.3 0-1.3-.1-2.4-.1-2.4 0-4 1.4-4 4.1v2.6H7.7V14h2.7v8h3.1z"/>' + _T,
    "instagram": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="3" y="3" width="18" height="18" rx="5"/><circle cx="12" cy="12" r="4"/><circle cx="17.2" cy="6.8" r="1.3" fill="currentColor" stroke="none"/></svg>',
    "tiktok": _S + '<path d="M16.6 3c.4 2.1 1.8 3.6 4 3.9v3c-1.6 0-3-.5-4-1.3v6.6c0 3.4-2.6 6.1-6 6.1-3.3 0-6-2.7-6-6.1s2.7-6.1 6-6.1c.3 0 .7 0 1 .1v3.1c-.3-.1-.7-.2-1-.2-1.6 0-3 1.3-3 3s1.4 3 3 3c1.7 0 3-1.4 3-3.1V3h3z"/>' + _T,
    "github": _S + '<path d="M12 2C6.5 2 2 6.5 2 12c0 4.4 2.9 8.2 6.8 9.5.5.1.7-.2.7-.5v-1.7c-2.8.6-3.4-1.2-3.4-1.2-.4-1.2-1.1-1.5-1.1-1.5-.9-.6.1-.6.1-.6 1 .1 1.5 1 1.5 1 .9 1.6 2.4 1.1 3 .9.1-.7.4-1.1.6-1.4-2.2-.3-4.6-1.1-4.6-5 0-1.1.4-2 1-2.7-.1-.2-.4-1.3.1-2.6 0 0 .8-.3 2.7 1a9.4 9.4 0 0 1 5 0c1.9-1.3 2.7-1 2.7-1 .5 1.3.2 2.4.1 2.6.6.7 1 1.6 1 2.7 0 3.9-2.4 4.7-4.6 5 .4.3.7.9.7 1.9v2.8c0 .3.2.6.7.5A10 10 0 0 0 22 12c0-5.5-4.5-10-10-10z"/>' + _T,
    "mastodon": _S + '<path d="M20.5 8.2c-.4-1.7-1.6-2.9-3.3-3.2C15.9 4.8 14 4.6 12 4.6s-3.9.2-5.2.4c-1.7.3-2.9 1.5-3.3 3.2C3.2 9.7 3 11.4 3 13v2.6c0 1 .8 1.9 1.9 1.9h.9c1 0 1.9-.8 1.9-1.9v-1.5c0-1 .8-1.9 1.9-1.9h2.8c1 0 1.9.8 1.9 1.9v1.5c0 1 .8 1.9 1.9 1.9h.9c1 0 1.9-.8 1.9-1.9V13c0-1.6-.2-3.3-.5-4.8zM8.5 12.4a1.3 1.3 0 1 1 0-2.6 1.3 1.3 0 0 1 0 2.6zm7 0a1.3 1.3 0 1 1 0-2.6 1.3 1.3 0 0 1 0 2.6z"/>' + _T,
    "bluesky": _S + '<ellipse cx="8" cy="12" rx="5.2" ry="7" transform="rotate(-18 8 12)"/><ellipse cx="16" cy="12" rx="5.2" ry="7" transform="rotate(18 16 12)"/><rect x="11" y="6.5" width="2" height="11" rx="1"/>' + _T,
    "linkedin": _S + '<path d="M4.98 3.5C4.98 4.88 3.87 6 2.5 6S.02 4.88.02 3.5 1.12 1 2.5 1s2.48 1.12 2.48 2.5zM.5 8h4V24h-4V8zm7.5 0h3.8v2.2h.05c.53-1 1.83-2.2 3.77-2.2 4.03 0 4.78 2.65 4.78 6.1V24h-4v-8.5c0-2-.04-4.6-2.8-4.6-2.8 0-3.2 2.2-3.2 4.5V24H8V8z"/>' + _T,
    "twitch": _S + '<path d="M4 2 2.5 6v14.5h5V23h3l2.5-2.5h4L22 15V2H4zm16.5 12-3 3h-4.5L10.5 19.5V17H7V4h13.5v10zM17 7.5v5h-2v-5h2zm-5 0v5h-2v-5h2z"/>' + _T,
    "discord": _S + '<path d="M18.6 5.3A16 16 0 0 0 14.7 4l-.5 1a14 14 0 0 0-4.4 0L9.3 4a16 16 0 0 0-3.9 1.3C2.9 9.1 2.2 12.8 2.5 16.4A16 16 0 0 0 7.4 19l1-1.6a9 9 0 0 1-1.6-.8l.4-.3a11.4 11.4 0 0 0 9.6 0l.4.3c-.5.3-1 .6-1.6.8l1 1.6a16 16 0 0 0 4.9-2.6c.4-4.2-.7-7.8-2.9-11.1zM9.7 14.3c-1 0-1.8-.9-1.8-2s.8-2 1.8-2 1.8.9 1.8 2-.8 2-1.8 2zm6.6 0c-1 0-1.8-.9-1.8-2s.8-2 1.8-2 1.8.9 1.8 2-.8 2-1.8 2z"/>' + _T,
    "telegram": _S + '<path d="M21.9 3.6 2.7 11c-.8.3-.8 1.4.1 1.6l4.7 1.5 1.8 5.6c.3.8 1.3.9 1.8.2l2.6-3.1 4.9 3.6c.6.5 1.6.1 1.8-.7l3.1-14.4c.2-1-.9-1.9-1.6-1.7zM8.5 13.6l9.5-6.7c.2-.1.4.1.2.3l-7.8 7.1-.3 3-1.6-3.7z"/>' + _T,
    "whatsapp": _S + '<path d="M12 2a10 10 0 0 0-8.6 15.1L2 22l5-1.3A10 10 0 1 0 12 2zm5.4 14.1c-.2.7-1.3 1.3-1.9 1.4-.5.1-1.2.2-3.9-.8-3.3-1.4-5.4-4.7-5.5-5-.2-.3-1.3-1.8-1.3-3.4s.8-2.4 1.1-2.7c.3-.3.7-.4 1-.4h.7c.2 0 .5-.1.8.6l1.1 2.7c.1.2.1.5 0 .7l-.5.7-.6.6c-.2.2-.4.5-.1.9.3.4 1.3 2.1 2.7 3.4 1.9 1.7 3.4 2.2 3.9 2.5.4.2.7.2.9-.1l1.2-1.4c.2-.3.5-.4.8-.2l2.5 1.2c.4.2.6.3.7.5 0 .2 0 .7-.4 1.3z"/>' + _T,
    "signal": _S + '<path d="M12 2C6.5 2 2 6.5 2 12c0 2.4.9 4.7 2.4 6.4-.1 1-.6 2.5-1.9 3.6 1.7-.1 3.2-.7 4.3-1.4.7.2 1.4.3 2.2.3h2c5.5 0 10-4.5 10-10S17.5 2 12 2z"/>' + _T,
    "reddit": _S + '<path d="M12 4c.6 0 1.1.5 1.1 1.1 0 .3-.1.5-.3.7 2.9.5 5.4 2 7 4.1l1.6-1.1c.3-.2.8-.1 1 .2.2.3.1.8-.2 1l-2 1.4c.2.7.4 1.5.4 2.3 0 3.9-4.5 7-10.1 7S2.4 18.6 2.4 14.7c0-.8.1-1.6.4-2.3l-2-1.4c-.3-.2-.4-.7-.2-1 .2-.3.7-.4 1-.2l1.6 1.1c1.6-2.1 4.1-3.6 7-4.1-.2-.2-.3-.4-.3-.7C10.9 4.5 11.4 4 12 4zm-4.5 8.2c-.9 0-1.6.7-1.6 1.6s.7 1.6 1.6 1.6 1.6-.7 1.6-1.6-.7-1.6-1.6-1.6zm9 0c-.9 0-1.6.7-1.6 1.6s.7 1.6 1.6 1.6 1.6-.7 1.6-1.6-.7-1.6-1.6-1.6zM9.2 17.3c.8.7 1.8 1 2.8 1s2-.3 2.8-1c.2-.2.2-.6 0-.8-.2-.2-.6-.2-.8 0-.6.5-1.3.8-2 .8s-1.4-.3-2-.8c-.2-.2-.6-.2-.8 0-.2.2-.2.6 0 .8z"/>' + _T,
    "pinterest": _S + '<path d="M12 2a10 10 0 0 0-3.7 19.3c-.1-.8-.2-2 0-2.9l1.2-5s-.3-.6-.3-1.5c0-1.4.8-2.5 1.9-2.5.9 0 1.3.7 1.3 1.5 0 .9-.6 2.2-.9 3.5-.2 1 .5 1.9 1.6 1.9 1.9 0 3.3-2 3.3-4.9 0-2.5-1.8-4.3-4.4-4.3-3 0-4.8 2.2-4.8 4.6 0 .9.3 1.9.8 2.4.1.1.1.2.1.3l-.3 1.1c0 .2-.2.2-.4.1-1.2-.6-2-2.4-2-3.9 0-3.2 2.3-6.1 6.7-6.1 3.5 0 6.2 2.5 6.2 5.8 0 3.5-2.2 6.3-5.3 6.3-1 0-2-.5-2.3-1.2l-.6 2.4c-.2.9-.8 2-1.2 2.6A10 10 0 1 0 12 2z"/>' + _T,
    "email": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M2.5 7l9.5 6 9.5-6"/></svg>',
    "globe": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.7 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.7-3.8-9S9.5 5.6 12 3z"/></svg>',
    "rss": _S + '<circle cx="6" cy="18" r="2.6"/><path d="M3.5 10.5a11 11 0 0 1 11 11H11a7.5 7.5 0 0 0-7.5-7.5v-3.5zM3.5 4.5a17 17 0 0 1 17 17H17A13.5 13.5 0 0 0 3.5 8V4.5z"/>' + _T,
    "link": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1.5 1.5M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1.5-1.5"/></svg>',
    "play": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M10 8.5l6 3.5-6 3.5z" fill="currentColor" stroke="none"/></svg>',
    "music": _S + '<circle cx="7" cy="17" r="3"/><circle cx="17" cy="14" r="3"/><path d="M10 17V5l10-2v10" fill="none" stroke="currentColor" stroke-width="2"/>' + _T,
    "book": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 6C10 4.5 7 4 4 4v14c3 0 6 .5 8 2 2-1.5 5-2 8-2V4c-3 0-6 .5-8 2zm0 0v14"/></svg>',
    "gift": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><rect x="4" y="9" width="16" height="4" rx="1"/><path d="M6 13v7a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1v-7M12 9v12M12 9S8.5 9 7 7.3C5.8 5.9 7 4 8.8 4.8 10.3 5.5 12 9 12 9zm0 0s3.5 0 5-1.7C18.2 5.9 17 4 15.2 4.8 13.7 5.5 12 9 12 9z"/></svg>',
    "gamepad": _S + '<path d="M7.5 7h9a5.5 5.5 0 0 1 5.4 6.6l-.9 4.4a3 3 0 0 1-5.3 1.4L14 17.5H10l-1.7 1.9a3 3 0 0 1-5.3-1.4l-.9-4.4A5.5 5.5 0 0 1 7.5 7zM8 11v4M6 13h4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="16" cy="11.5" r="1.3"/><circle cx="18.2" cy="14" r="1.3"/>' + _T,
    "heart": _S + '<path d="M12 21S3 14.5 3 8.9C3 6 5.2 4 7.7 4c1.7 0 3.3.9 4.3 2.4C13 4.9 14.6 4 16.3 4 18.8 4 21 6 21 8.9c0 5.6-9 12.1-9 12.1z"/>' + _T,
    "star": _S + '<path d="M12 2l2.9 6.3 6.9.8-5.1 4.7 1.4 6.8L12 17.2 5.9 20.6l1.4-6.8L2.2 9.1l6.9-.8L12 2z"/>' + _T,
    "coffee": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M4 9h12v6a5 5 0 0 1-5 5H9a5 5 0 0 1-5-5V9zM16 10h2a3 3 0 0 1 0 6h-2M8 5.5c0-1 .8-1 .8-2M12 5.5c0-1 .8-1 .8-2"/></svg>',
    "cart": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M3 4h2l2.5 11h10.5l2-8H7"/><circle cx="9.5" cy="19" r="1.6" fill="currentColor" stroke="none"/><circle cx="16.5" cy="19" r="1.6" fill="currentColor" stroke="none"/></svg>',
    "image": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="1.8"/><path d="M4.5 18l5-5 3 3 4-4 3.5 3.5"/></svg>',
    "video": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="2" y="6" width="13" height="12" rx="2"/><path d="M15 10.5l7-3.5v10l-7-3.5"/></svg>',
    "file": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M6 2h8l4 4v14a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z"/><path d="M14 2v4h4"/></svg>',
    "calendar": '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>',
}

ICON_CHOICES: list[tuple[str, str]] = [
    ("", "Auto (from URL)"),
    ("youtube", "YouTube"),
    ("x", "X (Twitter)"),
    ("facebook", "Facebook"),
    ("instagram", "Instagram"),
    ("tiktok", "TikTok"),
    ("github", "GitHub"),
    ("mastodon", "Mastodon"),
    ("bluesky", "Bluesky"),
    ("linkedin", "LinkedIn"),
    ("twitch", "Twitch"),
    ("discord", "Discord"),
    ("telegram", "Telegram"),
    ("whatsapp", "WhatsApp"),
    ("signal", "Signal"),
    ("reddit", "Reddit"),
    ("pinterest", "Pinterest"),
    ("email", "Email"),
    ("globe", "Website"),
    ("rss", "RSS / Blog"),
    ("link", "Link"),
    ("play", "Video"),
    ("music", "Music"),
    ("book", "Book / Reading"),
    ("gift", "Gift / Wishlist"),
    ("gamepad", "Gaming"),
    ("heart", "Heart"),
    ("star", "Star"),
    ("coffee", "Coffee"),
    ("cart", "Shop"),
    ("image", "Photo"),
    ("video", "Video file"),
    ("file", "File"),
    ("calendar", "Event"),
]


# host suffix -> icon key (checked with endswith so subdomains match)
_DOMAIN_ICONS: tuple[tuple[str, str], ...] = (
    ("youtube", "youtube"),
    ("youtu", "youtube"),
    ("twitter", "x"),
    ("facebook", "facebook"),
    ("instagram", "instagram"),
    ("tiktok", "tiktok"),
    ("github", "github"),
    ("bsky", "bluesky"),
    ("linkedin", "linkedin"),
    ("twitch", "twitch"),
    ("discord", "discord"),
    ("telegram", "telegram"),
    ("whatsapp", "whatsapp"),
    ("signal", "signal"),
    ("reddit", "reddit"),
    ("pinterest", "pinterest"),
    ("mastodon", "mastodon"),
    ("fosstodon", "mastodon"),
    ("spotify", "music"),
    ("soundcloud", "music"),
    ("bandcamp", "music"),
    ("wattpad", "book"),
    ("substack", "rss"),
    ("medium", "rss"),
    ("amazon", "cart"),
    ("etsy", "cart"),
    ("ko-fi", "coffee"),
    ("buymeacoffee", "coffee"),
    ("patreon", "heart"),
    ("roblox", "gamepad"),
    ("steam", "gamepad"),
    ("vimeo", "play"),
    ("peertube", "play"),
    ("threads", "instagram"),
    ("drive.google", "file"),
)


def detect_icon(url: str) -> str:
    """Guess an icon key from a URL's host. Returns "" when unknown."""
    try:
        u = (url or "").strip().lower()
        if u.startswith("mailto:"):
            return "email"
        host = u.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
        host = host.split("@")[-1].split(":")[0].strip()
        if host.startswith("www."):
            host = host[4:]
    except Exception:
        return ""
    for frag, icon in _DOMAIN_ICONS:
        if frag in host:
            return icon
    return ""


def resolve_icon(icon_key: str, url: str) -> str:
    """Final icon key for a link: explicit choice wins, else auto-detect."""
    if icon_key in BIO_ICONS:
        return icon_key
    return detect_icon(url)

_DOT = chr(46)
_DOMAIN_EXACT: tuple[tuple[str, str], ...] = (
    ("youtu" + _DOT + "be", "youtube"),
    ("x" + _DOT + "com", "x"),
    ("fb" + _DOT + "com", "facebook"),
    ("fb" + _DOT + "me", "facebook"),
    ("t" + _DOT + "me", "telegram"),
)

_orig_detect_icon = detect_icon


def detect_icon(url: str) -> str:
    """Guess an icon key from a URL's host. Returns "" when unknown."""
    hit = _orig_detect_icon(url)
    if hit:
        return hit
    try:
        u = (url or "").strip().lower()
        host = u.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
        host = host.split("@")[-1].split(":")[0].strip()
        if host.startswith("www" + _DOT):
            host = host[4:]
    except Exception:
        return ""
    for domain, icon in _DOMAIN_EXACT:
        if host == domain or host.endswith(_DOT + domain):
            return icon
    return ""


# ---------------------------------------------------------------------------
# v12.1 additions: extra link icons (karas.page parity) and UI-only icons.
# ---------------------------------------------------------------------------
_O = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'

BIO_ICONS.update({
    "home": _O + '<path d="M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6h-6v6H4a1 1 0 0 1-1-1z"/>' + _T,
    "chat": _O + '<path d="M21 12a8 8 0 0 1-11.6 7.1L4 20.5l1.4-4.6A8 8 0 1 1 21 12z"/><circle cx="8.5" cy="12" r=".6" fill="currentColor"/><circle cx="12" cy="12" r=".6" fill="currentColor"/><circle cx="15.5" cy="12" r=".6" fill="currentColor"/>' + _T,
    "phone": _O + '<path d="M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1 1 .4 1.9.7 2.8a2 2 0 0 1-.5 2.1L8 9.9a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.9.3 1.8.6 2.8.7a2 2 0 0 1 1.7 2z"/>' + _T,
    "map": _O + '<path d="M12 21s-7-6.2-7-11.5a7 7 0 0 1 14 0C19 14.8 12 21 12 21z"/><circle cx="12" cy="9.5" r="2.5"/>' + _T,
    "ban": _O + '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>' + _T,
    "shield": _O + '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' + _T,
    "code": _O + '<path d="M16 18l6-6-6-6M8 6l-6 6 6 6"/>' + _T,
    "server": _O + '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01"/>' + _T,
    "cog": _O + '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1A1.7 1.7 0 0 0 9 19.4a1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 4.6 9a1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>' + _T,
    "user": _O + '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>' + _T,
    "camera": _O + '<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>' + _T,
})

ICON_CHOICES.extend([
    ("home", "Home / Address"),
    ("map", "Location"),
    ("phone", "Phone"),
    ("chat", "Chat"),
    ("user", "Person"),
    ("camera", "Camera"),
    ("code", "Code"),
    ("server", "Server / Docs"),
    ("shield", "Shield"),
    ("ban", "Blocked / Not me"),
    ("cog", "Settings / Misc"),
])

# UI-only icons used by the public bio page chrome (never stored on links).
UI_ICONS: dict[str, str] = {
    "share": _O + '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><path d="M8.6 13.5l6.8 4M15.4 6.5l-6.8 4"/>' + _T,
    "flag": _O + '<path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1zM4 22v-7"/>' + _T,
    "palette": _O + '<path d="M12 22a10 10 0 1 1 10-10c0 2.8-2.2 4-4 4h-2a2 2 0 0 0-1.5 3.3A1.6 1.6 0 0 1 12 22z"/><circle cx="7.5" cy="11.5" r="1" fill="currentColor"/><circle cx="10.5" cy="7.5" r="1" fill="currentColor"/><circle cx="15.5" cy="7.5" r="1" fill="currentColor"/>' + _T,
    "access": _O + '<circle cx="12" cy="4" r="2"/><path d="M4 8l8 1.5L20 8M12 9.5V15m0 0-3 6m3-6 3 6"/>' + _T,
    "warn": _O + '<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01"/>' + _T,
    "info": _O + '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/>' + _T,
    "close": _O + '<path d="M18 6 6 18M6 6l12 12"/>' + _T,
    "pause": _O + '<path d="M8 5v14M16 5v14"/>' + _T,
    "stop": _O + '<rect x="6" y="6" width="12" height="12" rx="1"/>' + _T,
    "arrow": _O + '<path d="M5 12h14M13 6l6 6-6 6"/>' + _T,
    "copy": _O + '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>' + _T,
    "user": BIO_ICONS["user"],
    # Scalloped verification seal with a check (fill = currentColor).
    "verified": '<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M12 1.5l2.4 1.8 3-.2.9 2.9 2.5 1.7-.9 2.9.9 2.9-2.5 1.7-.9 2.9-3-.2L12 22.5l-2.4-1.8-3 .2-.9-2.9-2.5-1.7.9-2.9-.9-2.9 2.5-1.7.9-2.9 3 .2z"/><path d="M7.8 12.3l2.8 2.8 5.6-5.8" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>',
}
