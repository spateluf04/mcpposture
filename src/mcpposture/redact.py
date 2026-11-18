"""Secret detection and redaction.

Nothing this module returns for display ever contains more of a secret than
its provider label and, for secrets of 12 or more characters, the last four
characters.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

_B = r"(?<![A-Za-z0-9])"
PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "private-key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)",
            re.DOTALL,
        ),
    ),
    ("anthropic", re.compile(_B + r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai", re.compile(_B + r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("github", re.compile(_B + r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")),
    ("gitlab", re.compile(_B + r"glpat-[A-Za-z0-9_-]{20,}")),
    ("aws", re.compile(_B + r"(?:AKIA|ASIA)[0-9A-Z]{16}(?![0-9A-Z])")),
    ("google", re.compile(_B + r"AIza[0-9A-Za-z_-]{35}")),
    ("slack", re.compile(_B + r"xox[abeprs]-[A-Za-z0-9-]{10,}")),
    ("stripe", re.compile(_B + r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("huggingface", re.compile(_B + r"hf_[A-Za-z0-9]{30,}")),
    ("npm", re.compile(_B + r"npm_[A-Za-z0-9]{36}")),
    ("jwt", re.compile(_B + r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
)

# ${VAR}, ${env:VAR}, ${input:id}: the name part is a reference, not a value.
# A ${VAR:-default} default is a literal, so it stays subject to scanning.
_REFERENCE_NAME = re.compile(r"\$\{[^}:]*(?::(?!-)[^}]*)?")
_REFERENCE_ONLY = re.compile(r"^\s*(?:\$\{[^}]*\}\s*)+$")
# No '/' or '.' so paths, URLs and package names split into short pieces.
_TOKEN = re.compile(r"[A-Za-z0-9+_-]{20,}={0,2}")
ENTROPY_MIN_LENGTH = 20
ENTROPY_MIN_BITS = 3.5

SENSITIVE_NAME = re.compile(
    r"(?i)(api[_-]?key|apikey|token|secret|passw(?:or)?d|pwd|credential|"
    r"authorization|auth[_-]?key|private[_-]?key|access[_-]?key|bearer|cookie|session[_-]?id)"
)
_FLAG_EQ = re.compile(r"^(--?[A-Za-z0-9][A-Za-z0-9_.-]*)=(.*)$", re.DOTALL)


@dataclass(frozen=True)
class SecretMatch:
    provider: str
    start: int
    end: int
    method: str  # "pattern" | "entropy" | "name"


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def looks_random(token: str) -> bool:
    # Requiring mixed case plus digits excludes hex digests and commit SHAs,
    # which in these files are version pins rather than credentials.
    return (
        len(token) >= ENTROPY_MIN_LENGTH
        and any(c.isupper() for c in token)
        and any(c.islower() for c in token)
        and any(c.isdigit() for c in token)
        and shannon_entropy(token) >= ENTROPY_MIN_BITS
    )


def is_reference_only(value: str) -> bool:
    return bool(_REFERENCE_ONLY.match(value))


def find_secrets(text: str) -> list[SecretMatch]:
    """Provider-pattern and high-entropy matches in ``text``, non-overlapping."""
    safe = [m.span() for m in _REFERENCE_NAME.finditer(text)]

    def in_safe(start: int, end: int) -> bool:
        return any(s <= start and end <= e for s, e in safe)

    found: list[SecretMatch] = []

    def overlaps(start: int, end: int) -> bool:
        return any(start < f.end and f.start < end for f in found)

    for provider, pattern in PROVIDER_PATTERNS:
        for m in pattern.finditer(text):
            if not in_safe(*m.span()) and not overlaps(*m.span()):
                found.append(SecretMatch(provider, m.start(), m.end(), "pattern"))
    for m in _TOKEN.finditer(text):
        if looks_random(m.group()) and not in_safe(*m.span()) and not overlaps(*m.span()):
            found.append(SecretMatch("high-entropy", m.start(), m.end(), "entropy"))
    return sorted(found, key=lambda f: f.start)


def _benign_named_value(value: str) -> bool:
    v = value.strip()
    return (
        len(v) < 6
        or is_reference_only(v)
        or v.lower() in {"true", "false", "null", "none", "changeme", "placeholder"}
        or v.isdigit()
        or v.startswith(("/", "./", "../", "~/", "http://", "https://"))
        or bool(re.match(r"^[A-Za-z]:[\\/]", v))
    )


def named_secret(name: str, value: str) -> bool:
    """True when a sensitive-sounding key holds a literal that is not a path, URL or reference."""
    return bool(SENSITIVE_NAME.search(name)) and not _benign_named_value(value)


def classify(value: str, name: str | None = None) -> list[SecretMatch]:
    matches = find_secrets(value)
    if not matches and name is not None and named_secret(name, value):
        matches = [SecretMatch("named-secret", 0, len(value), "name")]
    return matches


def mask(secret: str, provider: str) -> str:
    if provider != "private-key" and len(secret) >= 12:
        return f"[REDACTED {provider} ...{secret[-4:]}]"
    return f"[REDACTED {provider}]"


def _apply(text: str, matches: list[SecretMatch]) -> str:
    for m in sorted(matches, key=lambda m: m.start, reverse=True):
        text = text[: m.start] + mask(text[m.start : m.end], m.provider) + text[m.end :]
    return text


def redact(text: str) -> str:
    return _apply(text, find_secrets(text))


def redact_value(value: str, name: str | None = None) -> str:
    return _apply(value, classify(value, name))


def redact_args(args: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    out: list[str] = []
    mask_next = False
    for arg in args:
        if mask_next:
            mask_next = False
            if not arg.startswith("-"):
                out.append(redact_value(arg, "token"))
                continue
        m = _FLAG_EQ.match(arg)
        if m:
            out.append(f"{m.group(1)}={redact_value(m.group(2), m.group(1))}")
            continue
        if arg.startswith("-") and SENSITIVE_NAME.search(arg):
            mask_next = True
        out.append(redact(arg))
    return tuple(out)


def redact_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return redact(url)
    netloc = parts.netloc
    if "@" in netloc:
        netloc = "[REDACTED credentials]@" + netloc.rsplit("@", 1)[1]
    query_items = []
    for pair in parts.query.split("&") if parts.query else []:
        key, sep, val = pair.partition("=")
        query_items.append(f"{key}{sep}{redact_value(val, key) if sep else redact(key)}")
    return urlunsplit(
        (parts.scheme, netloc, redact(parts.path), "&".join(query_items), redact(parts.fragment))
    )
