"""Look-and-feel for public bio pages (karas.page style).

Everything that decides how a ``/@slug`` page *looks* lives here so the
router and templates stay small:

* ``PALETTES``      - colour sets for each selectable theme
* ``SEASONS``       - the month-by-month holiday themes used by "Seasonal"
* ``BRAND_COLORS``  - per-icon tile colours for link cards
* ``bio_prefs()``   - per-profile appearance settings stored as JSON
* ``section_icon()``- picks a heading icon from a section's name
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Themes. Every palette drives the same CSS variables the karas.page design
# uses (--primary/--secondary/--accent/--bg/--text/--text-muted); the sky,
# hills, city and trees are all colour-mixed from these, so one palette
# re-tints the whole landscape.
# ---------------------------------------------------------------------------
PALETTES: dict[str, dict[str, str]] = {
    "seasonal": {"name": "Seasonal (changes monthly)"},  # resolved per month
    "default":  {"name": "Meadow", "primary": "#2ecc71", "secondary": "#3498db", "accent": "#9b59b6",
                 "bg": "#061a0e", "text": "#ecf0f1", "muted": "#9fc4ab"},
    "midnight": {"name": "Midnight", "primary": "#818cf8", "secondary": "#22d3ee", "accent": "#c084fc",
                 "bg": "#070b1d", "text": "#e8ecff", "muted": "#a3acd9"},
    "sunset":   {"name": "Sunset", "primary": "#ff9f43", "secondary": "#ee5253", "accent": "#feca57",
                 "bg": "#2a0f10", "text": "#fff7ed", "muted": "#e0b090"},
    "forest":   {"name": "Forest", "primary": "#27ae60", "secondary": "#f1c40f", "accent": "#16a085",
                 "bg": "#08210f", "text": "#ecf0f1", "muted": "#8ed4a2"},
    "ocean":    {"name": "Ocean", "primary": "#00b4d8", "secondary": "#48cae4", "accent": "#90e0ef",
                 "bg": "#031a2e", "text": "#f0f9ff", "muted": "#9dc4e0"},
    "mono":     {"name": "Mono", "primary": "#e5e7eb", "secondary": "#9ca3af", "accent": "#f9fafb",
                 "bg": "#111214", "text": "#f5f5f5", "muted": "#a3a3a3"},
}

# Month index (0 = January) -> holiday theme. Same table as karas.page.
SEASONS: list[dict[str, str]] = [
    {"name": "Winter Frost", "primary": "#3498db", "secondary": "#1abc9c", "accent": "#9b59b6", "bg": "#0a1a2e", "text": "#ecf0f1", "muted": "#9dc4e0", "bio": "Embracing winter with fresh tech insights ❄️", "fx": "snow"},
    {"name": "Valentine's Love", "primary": "#e74c3c", "secondary": "#e84393", "accent": "#fd79a8", "bg": "#2a0d14", "text": "#fdf2f8", "muted": "#dda0b8", "bio": "Spreading love and tech tips this Valentine's season 💖", "fx": "hearts"},
    {"name": "St. Patrick's Day", "primary": "#2ecc71", "secondary": "#f1c40f", "accent": "#27ae60", "bg": "#08210f", "text": "#ecf0f1", "muted": "#8ed4a2", "bio": "Feeling lucky with new tech discoveries! 🍀", "fx": "fireflies"},
    {"name": "Easter", "primary": "#9b59b6", "secondary": "#e84393", "accent": "#f1c40f", "bg": "#1e1030", "text": "#f8f9fa", "muted": "#bda0d8", "bio": "Fresh tech reviews and creative experiments 🌼", "fx": "bunnies"},
    {"name": "May Flowers", "primary": "#e91e8c", "secondary": "#9b59b6", "accent": "#1abc9c", "bg": "#1c0e28", "text": "#f8f9fa", "muted": "#d68ec0", "bio": "Blooming with new content and discoveries 🌺", "fx": "petals"},
    {"name": "Summer Pride", "primary": "#e74c3c", "secondary": "#f39c12", "accent": "#3498db", "bg": "#2a0f10", "text": "#ffffff", "muted": "#e0a898", "bio": "Celebrating diversity in tech this Pride month 🌈", "fx": "fireflies"},
    {"name": "4th of July", "primary": "#e74c3c", "secondary": "#3498db", "accent": "#f1c40f", "bg": "#0a1428", "text": "#ffffff", "muted": "#9cb0d4", "bio": "Celebrating freedom and innovation! 🇺🇸", "fx": "stars"},
    {"name": "Summer Heat", "primary": "#e67e22", "secondary": "#e74c3c", "accent": "#f1c40f", "bg": "#26140a", "text": "#fdf2e9", "muted": "#e0b090", "bio": "Enjoying summer vibes with hot tech takes 🌅", "fx": "fireflies"},
    {"name": "Labor Day", "primary": "#d35400", "secondary": "#3498db", "accent": "#f1c40f", "bg": "#1a2222", "text": "#ecf0f1", "muted": "#a8bcbc", "bio": "Honoring hard work and innovation 🔧", "fx": "leaves"},
    {"name": "Halloween", "primary": "#9b59b6", "secondary": "#f1c40f", "accent": "#e74c3c", "bg": "#1a0f18", "text": "#f8f9fa", "muted": "#b898d0", "bio": "Spooky tech tricks and treats! 🎃👻", "fx": "bats"},
    {"name": "Thanksgiving", "primary": "#d35400", "secondary": "#f39c12", "accent": "#27ae60", "bg": "#241608", "text": "#fdf2e9", "muted": "#e0b078", "bio": "Grateful for tech and community 🦃", "fx": "leaves"},
    {"name": "Christmas", "primary": "#e74c3c", "secondary": "#2ecc71", "accent": "#f1c40f", "bg": "#0a1c0e", "text": "#ffffff", "muted": "#a0d4a8", "bio": "Spreading holiday cheer with tech gifts 🎄", "fx": "snow"},
]

# "MM-DD" -> single-day override.
SEASON_DAYS: dict[str, dict[str, str]] = {
    "01-01": {"name": "New Year's Day", "primary": "#3498db", "secondary": "#9b59b6", "accent": "#1abc9c", "bg": "#0c1430", "text": "#ecf0f1", "muted": "#9dc4e0", "bio": "Happy New Year! 🎉", "fx": "confetti"},
    "02-14": {"name": "Valentine's Day", "primary": "#e84393", "secondary": "#e74c3c", "accent": "#fd79a8", "bg": "#2a0d14", "text": "#fdf2f8", "muted": "#dda0b8", "bio": "Happy Valentine's Day! 💝", "fx": "hearts"},
    "03-17": {"name": "St. Patrick's Day", "primary": "#2ecc71", "secondary": "#27ae60", "accent": "#f1c40f", "bg": "#08210f", "text": "#ffffff", "muted": "#8ed4a2", "bio": "Happy St. Patrick's Day! 🍀", "fx": "fireflies"},
    "10-31": {"name": "Halloween", "primary": "#f1c40f", "secondary": "#9b59b6", "accent": "#e74c3c", "bg": "#1a0b1c", "text": "#f8f9fa", "muted": "#b898d0", "bio": "Happy Halloween! 🎃", "fx": "bats"},
    "12-25": {"name": "Christmas", "primary": "#e74c3c", "secondary": "#2ecc71", "accent": "#f1c40f", "bg": "#0a1c0e", "text": "#ffffff", "muted": "#a0d4a8", "bio": "Merry Christmas! 🎄", "fx": "snow"},
    "12-31": {"name": "New Year's Eve", "primary": "#9b59b6", "secondary": "#3498db", "accent": "#f1c40f", "bg": "#141632", "text": "#ffffff", "muted": "#9cb0d4", "bio": "Happy New Year's Eve! 🥂", "fx": "confetti"},
}

EFFECTS: list[tuple[str, str]] = [
    ("auto", "Match the season"),
    ("none", "None"),
    ("snow", "Snow"),
    ("hearts", "Hearts"),
    ("fireflies", "Fireflies"),
    ("leaves", "Falling leaves"),
    ("petals", "Petals"),
    ("stars", "Twinkling stars"),
    ("confetti", "Confetti"),
    ("bats", "Bats"),
    ("bunnies", "Bunnies"),
]
EFFECT_IDS = {k for k, _ in EFFECTS}

LINK_KINDS: list[tuple[str, str, str]] = [
    # id, label, help
    ("link", "Link", "Opens a URL"),
    ("copy", "Copy card", "Copies its text when tapped (addresses, handles)"),
    ("text", "Info card", "A card with no link"),
    ("notice_warn", "Warning notice", "Red callout under the section"),
    ("notice_info", "Note", "Yellow callout under the section"),
]
LINK_KIND_IDS = {k for k, _, _ in LINK_KINDS}
NOTICE_KINDS = {"notice_warn", "notice_info"}

# Tile colour per icon (background is this colour at ~18% alpha).
BRAND_COLORS: dict[str, str] = {
    "youtube": "#ff4d4d", "x": "#e7e9ea", "facebook": "#4c8bf5", "instagram": "#ff5c9a",
    "tiktok": "#25f4ee", "github": "#e6edf3", "mastodon": "#8f90ff", "bluesky": "#3d9bff",
    "linkedin": "#4ba3ff", "twitch": "#a970ff", "discord": "#7f8cff", "telegram": "#3fb6ef",
    "whatsapp": "#25d366", "signal": "#3fd0ff", "reddit": "#ff6a2b", "pinterest": "#ff3d57",
    "email": "#5fe39a", "globe": "#5cb8f0", "rss": "#ffa53d", "link": "#c66ce0",
    "play": "#c66ce0", "music": "#1ed760", "book": "#ff6b75", "gift": "#ffb340",
    "gamepad": "#ff6b75", "heart": "#ff6b9d", "star": "#ffd447", "coffee": "#d4a373",
    "cart": "#ffb340", "image": "#5cb8f0", "video": "#ff6b75", "file": "#9fc4ab",
    "calendar": "#5cb8f0", "home": "#5cb8f0", "map": "#ff6b75", "phone": "#5fe39a",
    "chat": "#3fd0ff", "user": "#c66ce0", "camera": "#ffb340", "code": "#5fe39a",
    "server": "#5cb8f0", "shield": "#5fe39a", "ban": "#8cc08c", "cog": "#9fc4ab",
}

_SECTION_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("social",), "globe"),
    (("contact", "email", "mail", "reach"), "email"),
    (("referral", "affiliate", "link"), "link"),
    (("misc", "other", "more", "extra"), "cog"),
    (("shop", "store", "merch", "buy"), "cart"),
    (("music", "listen", "podcast"), "music"),
    (("video", "watch", "stream"), "play"),
    (("game", "gaming"), "gamepad"),
    (("support", "donat", "tip", "sponsor"), "heart"),
    (("project", "code", "dev", "work", "portfolio"), "code"),
    (("book", "read", "blog", "writing", "stories"), "book"),
    (("doc",), "server"),
    (("event", "calendar"), "calendar"),
)


def section_icon(name: str) -> str:
    n = (name or "").lower()
    for needles, icon in _SECTION_RULES:
        if any(x in n for x in needles):
            return icon
    return "star"


def season_for(now: datetime | None = None) -> dict[str, str]:
    now = now or datetime.now(timezone.utc)
    return SEASON_DAYS.get(now.strftime("%m-%d")) or SEASONS[now.month - 1]


# ---------------------------------------------------------------------------
# Per-profile preferences (stored as JSON in users.bio_prefs).
# ---------------------------------------------------------------------------
DEFAULT_PREFS: dict = {
    "scene": True,             # animated landscape background
    "effects": "auto",         # particle effect (see EFFECTS)
    "tech": True,              # tech/binary animation inside the header card
    "layout": "grid",          # "grid" (2-3 columns on desktop) or "list"
    "custom_accent": False,    # use users.accent_color instead of the palette primary
    "seasonal_tagline": False,  # replace the bio line with the holiday line
    "show_share": True,
    "show_report": True,
    "show_a11y": True,         # accessibility toolbar
    "show_date": True,
    "footer_text": "",         # blank -> "© YEAR Name"
}
_BOOL_KEYS = [k for k, v in DEFAULT_PREFS.items() if isinstance(v, bool)]


def bio_prefs(user) -> dict:
    """Merged preferences for a user (defaults + stored JSON)."""
    prefs = dict(DEFAULT_PREFS)
    raw = getattr(user, "bio_prefs", "") or ""
    if raw:
        try:
            stored = json.loads(raw)
            if isinstance(stored, dict):
                for k, v in stored.items():
                    if k in prefs and type(v) is type(prefs[k]):
                        prefs[k] = v
        except (ValueError, TypeError):
            pass
    if prefs["effects"] not in EFFECT_IDS:
        prefs["effects"] = "auto"
    if prefs["layout"] not in ("grid", "list"):
        prefs["layout"] = "grid"
    return prefs


def prefs_from_form(form) -> dict:
    """Build a prefs dict from a submitted editor form (checkbox semantics)."""
    prefs = dict(DEFAULT_PREFS)
    for k in _BOOL_KEYS:
        prefs[k] = form.get(f"pref_{k}") is not None
    eff = str(form.get("pref_effects") or "auto")
    prefs["effects"] = eff if eff in EFFECT_IDS else "auto"
    layout = str(form.get("pref_layout") or "grid")
    prefs["layout"] = layout if layout in ("grid", "list") else "grid"
    prefs["footer_text"] = str(form.get("pref_footer_text") or "").strip()[:140]
    return prefs


def palette_for(theme: str) -> dict[str, str]:
    """Concrete colours for a theme id ("seasonal" -> current month)."""
    if theme == "seasonal":
        return season_for()
    return PALETTES.get(theme) or PALETTES["default"]


def palette_payload() -> str:
    """JSON blob the editor/preview JS uses (palettes + seasons)."""
    return json.dumps({
        "palettes": {k: v for k, v in PALETTES.items() if k != "seasonal"},
        "seasons": SEASONS,
        "days": SEASON_DAYS,
    }, ensure_ascii=False)
