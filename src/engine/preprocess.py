"""Input pre-processing: normalise a prompt and expose hidden (encoded) text.

Why this exists
---------------
Layer 1 matches regex and keyword rules, and Layer 2 reads plain text. An
attacker can hide an instruction from both by encoding it (Base64, hex, ROT13,
URL or unicode escapes), by inserting invisible characters ("ig<ZWSP>nore"),
by using lookalike letters (Cyrillic "а" for Latin "a"), by leetspeak, by
spacing the letters out, or by reversing the text. A capable LLM can often
decode such text and obey it anyway.

What it does
------------
``preprocess(text)`` returns:

* ``text``      the normalised prompt (NFKC, invisible characters removed,
                whitespace collapsed). This is the primary text to scan.
* ``variants``  extra ``(label, text)`` views of the prompt that must ALSO be
                scanned: a folded view (accents and lookalikes folded), a
                leetspeak view, a spaced-letters view, a reversed view, a ROT13
                view and the decoded contents of every Base64, hex,
                percent-encoded and escape-encoded blob. Decoded text is itself
                decoded once more, so double encoding is caught.
* ``flags`` / ``suspicious``
                human-readable reasons, and whether the prompt looks
                deliberately obfuscated (invisible characters, a large encoded
                blob, ...). The pipeline sends suspicious prompts that no layer
                blocked to Layer 3 instead of passing them straight through.

Nothing here changes the request that is forwarded to the LLM: these texts are
only used for inspection.

Everything is bounded (input size, number of blobs, number of variants) so the
pre-processor cannot be used to slow the firewall down.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

# --------------------------------------------------------------------- limits
MAX_SCAN_CHARS = 200_000        # only this many characters are decoded / folded
MAX_BLOBS = 20                  # encoded blobs decoded per prompt
MAX_VARIANTS = 16               # extra views returned per prompt
MAX_DECODE_DEPTH = 2            # decoded text is decoded again once more
MIN_BASE64_CHARS = 20           # shorter runs are ordinary words
OPAQUE_BLOB_CHARS = 256         # long undecodable blob = suspicious
SUSPICIOUS_ENCODED_CHARS = 40   # decoded blob this long = suspicious
SUSPICIOUS_ENCODED_RATIO = 0.30 # or this share of the prompt
SUSPICIOUS_INVISIBLE = 3        # invisible characters in one prompt

# ------------------------------------------------------- invisible characters
_EXTRA_INVISIBLE = frozenset(
    {0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x3164, 0xFFA0}
)
_KEEP_CONTROL = frozenset("\n\r\t\f\v")


def _is_invisible(ch: str) -> bool:
    if ch in _KEEP_CONTROL:
        return False
    code = ord(ch)
    if code in _EXTRA_INVISIBLE or 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF:
        return True
    # Cf = format (zero-width space/joiner, bidi marks, tag characters, BOM),
    # Cc = other control characters, Cs/Co = surrogates / private use.
    return unicodedata.category(ch) in ("Cf", "Cc", "Cs", "Co")


def strip_invisible(text: str) -> tuple[str, int]:
    """Remove invisible / control characters. Returns (clean_text, removed_count)."""
    if text.isascii() and text.isprintable():
        return text, 0
    kept = [ch for ch in text if not _is_invisible(ch)]
    return "".join(kept), len(text) - len(kept)


# --------------------------------------------------------------- normalisation
_WS_RE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """NFKC, drop invisible characters, collapse whitespace. Never raises."""
    if not text:
        return ""
    cleaned, _ = strip_invisible(unicodedata.normalize("NFKC", text))
    return _WS_RE.sub(" ", cleaned).strip()


# Visually identical Cyrillic / Greek letters -> Latin. Only used for the
# separate "folded" view, so genuine Russian or Greek text is still scanned
# unchanged in the primary view.
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic lower
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
        "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ӏ": "l", "ԛ": "q",
        "ԝ": "w", "ɡ": "g", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
        # Cyrillic upper
        "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
        "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
        # Greek
        "α": "a", "ο": "o", "ν": "v", "ρ": "p", "ι": "i", "κ": "k", "τ": "t",
        "υ": "u", "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I",
        "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
        "Υ": "Y", "Ζ": "Z",
    }
)

_LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
     "@": "a", "$": "s", "!": "i", "+": "t", "|": "l"}
)


def _fold(text: str) -> str:
    """Strip accents / combining marks and map lookalike letters to Latin."""
    decomposed = unicodedata.normalize("NFKD", text)
    no_marks = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return no_marks.translate(_CONFUSABLES)


# "i g n o r e", "i.g.n.o.r.e", "i-g-n-o-r-e", "i_g_n_o_r_e"
_SPACED_RE = re.compile(r"(?<![^\W_])(?:[^\W_][\s.\-_*]){4,}[^\W_](?![^\W_])")


def _unspace(text: str) -> str:
    return _SPACED_RE.sub(lambda m: re.sub(r"[\s.\-_*]", "", m.group(0)), text)


# -------------------------------------------------------------------- decoders
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/_\-=])[A-Za-z0-9+/_\-]{%d,}={0,2}(?![A-Za-z0-9+/_\-=])" % MIN_BASE64_CHARS)
_HEX_ESC_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_HEX_RUN_RE = re.compile(r"(?<![0-9A-Za-z])(?:0x)?(?:[0-9a-fA-F]{2}[\s:,\-]?){8,}(?![0-9A-Za-z])")
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_UNI_ESC_RE = re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})")
_HTML_ENT_RE = re.compile(r"&#[xX]?[0-9a-fA-F]+;|&[A-Za-z]{2,8};")


def _readable(raw: bytes) -> str | None:
    """Decode bytes as UTF-8 text if it looks like human text, else None."""
    if len(raw) < 6:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    letters = sum(1 for ch in text if ch.isalpha() or ch.isspace())
    if printable / len(text) < 0.95 or letters / len(text) < 0.6:
        return None
    return text


def _decode_base64(blob: str) -> str | None:
    cleaned = blob.rstrip("=").replace("-", "+").replace("_", "/")
    cleaned += "=" * (-len(cleaned) % 4)
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _readable(raw)


def _decode_hex(blob: str) -> str | None:
    digits = re.sub(r"(?i)0x|\\x|[^0-9a-f]", "", blob)
    if len(digits) < 12 or len(digits) % 2:
        return None
    try:
        raw = bytes.fromhex(digits)
    except ValueError:
        return None
    return _readable(raw)


def _decode_unicode_escapes(text: str) -> str:
    def repl(m: re.Match) -> str:
        code = int(m.group(1) or m.group(2), 16)
        try:
            return chr(code)
        except (ValueError, OverflowError):
            return ""

    return _UNI_ESC_RE.sub(repl, text)


@dataclass
class PreprocessResult:
    text: str = ""                                         # primary, normalised prompt
    variants: list[tuple[str, str]] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    suspicious: bool = False
    invisible_removed: int = 0
    encoded_chars: int = 0
    truncated: bool = False

    def all_texts(self) -> list[tuple[str, str]]:
        """Every text that must be inspected, primary first."""
        return [("original", self.text), *self.variants]

    def summary(self) -> dict:
        """Small dict for layer_details / logs. Never contains prompt text."""
        return {
            "variants": [label for label, _ in self.variants],
            "flags": list(self.flags),
            "suspicious": self.suspicious,
            "invisible_removed": self.invisible_removed,
        }


def _find_decoded(text: str, depth: int, out: list[tuple[str, str]], stats: dict) -> None:
    """Append ``(label, decoded_text)`` for every encoded blob found in ``text``."""
    if depth > MAX_DECODE_DEPTH or len(out) >= MAX_VARIANTS or stats["blobs"] >= MAX_BLOBS:
        return

    found: list[tuple[str, str, int]] = []   # (label, decoded, encoded_length)

    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        stats["blobs"] += 1
        decoded = _decode_base64(blob)
        if decoded:
            found.append(("base64", decoded, len(blob)))
        elif len(blob) >= OPAQUE_BLOB_CHARS and "opaque_blob" not in stats["flags"]:
            stats["flags"].append("opaque_blob")
        if stats["blobs"] >= MAX_BLOBS:
            break

    for m in list(_HEX_ESC_RE.finditer(text)) + list(_HEX_RUN_RE.finditer(text)):
        stats["blobs"] += 1
        decoded = _decode_hex(m.group(0))
        if decoded:
            found.append(("hex", decoded, len(m.group(0))))

    if len(_PCT_RE.findall(text)) >= 3:
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            found.append(("url", decoded, len(text) - len(decoded)))

    if len(_UNI_ESC_RE.findall(text)) >= 3:
        decoded = _decode_unicode_escapes(text)
        if decoded != text:
            found.append(("unicode_escape", decoded, len(text) - len(decoded)))

    if len(_HTML_ENT_RE.findall(text)) >= 3:
        decoded = html.unescape(text)
        if decoded != text:
            found.append(("html_entity", decoded, len(text) - len(decoded)))

    for label, decoded, enc_len in found:
        if len(out) >= MAX_VARIANTS:
            return
        stats["encoded_chars"] += max(enc_len, 0)
        norm = normalize_text(decoded)
        if not norm:
            continue
        out.append((f"decoded_{label}" if depth == 0 else f"decoded_{label}_l{depth + 1}", norm))
        if label not in stats["flags"]:
            stats["flags"].append(label)
        _find_decoded(decoded, depth + 1, out, stats)


def preprocess(text: str) -> PreprocessResult:
    """Normalise ``text`` and collect every extra view that must be inspected."""
    if not text:
        return PreprocessResult()

    truncated = len(text) > MAX_SCAN_CHARS
    raw = text[:MAX_SCAN_CHARS] if truncated else text

    nfkc = unicodedata.normalize("NFKC", raw)
    stripped, removed = strip_invisible(nfkc)
    primary = _WS_RE.sub(" ", stripped).strip()

    result = PreprocessResult(text=primary, invisible_removed=removed, truncated=truncated)
    if not primary:
        return result

    seen = {primary}
    variants: list[tuple[str, str]] = []

    def add(label: str, value: str) -> None:
        value = _WS_RE.sub(" ", value).strip()
        if value and value not in seen and len(variants) < MAX_VARIANTS:
            seen.add(value)
            variants.append((label, value))

    # ---- obfuscation views (cheap string operations) ----
    folded = _fold(primary)
    add("folded", folded)
    add("leetspeak", folded.translate(_LEET))
    spaced = _unspace(folded)
    if spaced != folded:
        add("spaced_letters", spaced)
        result.flags.append("spaced_letters")
    if sum(ch.isalpha() for ch in primary) >= 12:
        add("rot13", codecs.decode(primary, "rot13"))
        add("reversed", primary[::-1])

    # ---- decoded blobs (Base64 / hex / percent / escapes), also from the raw text ----
    decoded: list[tuple[str, str]] = []
    stats = {"blobs": 0, "encoded_chars": 0, "flags": []}
    _find_decoded(stripped, 0, decoded, stats)
    for label, value in decoded:
        add(label, value)
        # The decoded text can itself be obfuscated: fold it too.
        add(label + "_folded", _fold(value))

    result.variants = variants
    result.encoded_chars = stats["encoded_chars"]
    for flag in stats["flags"]:
        if flag not in result.flags:
            result.flags.append(flag)

    reasons: list[str] = []
    if removed >= SUSPICIOUS_INVISIBLE:
        reasons.append("invisible_characters")
    if stats["encoded_chars"] >= SUSPICIOUS_ENCODED_CHARS or (
        stats["encoded_chars"] and stats["encoded_chars"] / max(len(raw), 1) >= SUSPICIOUS_ENCODED_RATIO
    ):
        reasons.append("large_encoded_blob")
    if "opaque_blob" in stats["flags"]:
        reasons.append("opaque_blob")
    if "spaced_letters" in result.flags:
        reasons.append("spaced_letters")
    for r in reasons:
        if r not in result.flags:
            result.flags.append(r)
    result.suspicious = bool(reasons)
    return result
