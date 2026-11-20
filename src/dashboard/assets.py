"""SHEBA SHIELD — Assets, logos and SVG iconography.
Reproduces all brand and icon assets from index/index.html.
"""

from __future__ import annotations

import base64
from functools import lru_cache
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_CREST_PATHS = [
    _ROOT / "index" / "img" / "crest.png",
    Path(__file__).parent / "static" / "crest.png",
    _ROOT / "src" / "dashboard" / "static" / "crest.png",
]


@lru_cache(maxsize=1)
def get_crest_data_uri() -> str:
    """Read the SHEBA SHIELD royal crest PNG and return as base64 data URI."""
    for p in _CREST_PATHS:
        if p.exists():
            data = p.read_bytes()
            b64 = base64.b64encode(data).decode("utf-8")
            return f"data:image/png;base64,{b64}"
    # Fallback placeholder if file is not found
    return "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="


# SVG Icons matching index/index.html
ICON_REQ = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="#D9AE5B" stroke-width="2">'
    '<path d="M3 12h4l3 8 4-16 3 8h4"/></svg>'
)
ICON_SAFE = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="#3DBE8B" stroke-width="2">'
    '<path d="M20 6L9 17l-5-5"/></svg>'
)
ICON_BLOCK = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="#E5554F" stroke-width="2">'
    '<circle cx="12" cy="12" r="9"/><path d="M5.7 5.7l12.6 12.6"/></svg>'
)
ICON_RATE = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="#D9AE5B" stroke-width="2">'
    '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/></svg>'
)
ICON_LAT = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="#D9AE5B" stroke-width="2">'
    '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>'
)
ICON_REFRESH = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
    '<path d="M21 12a9 9 0 11-3-6.7L21 8M21 3v5h-5"/></svg>'
)
ICON_EXPORT = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
    '<path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16"/></svg>'
)
ICON_WARNING = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">'
    '<path d="M12 9v4m0 4h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z"/></svg>'
)
ICON_SHIELD = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">'
    '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/></svg>'
)
ICON_ANALYTICS = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">'
    '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/></svg>'
)
ICON_LOGS = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">'
    '<path d="M4 6h16M4 12h16M4 18h10"/></svg>'
)
ICON_CONFIG = (
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">'
    '<circle cx="12" cy="12" r="3"/>'
    '<path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 01-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 010-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 014 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 010 4h-.1a1.7 1.7 0 00-1.5 1z"/>'
    '</svg>'
)
