"""Redaction of sensitive runtime data in IAST report text.

IAST engines see live requests. Vendor text fields routinely quote request
data — query strings, headers, cookies, tainted values. None of that is needed
to fix a vulnerability, so free text is redacted before it leaves the CI job,
and the backend applies the same rules again (it never trusts the client).

Keep the patterns in sync with ``SensitiveDataRedactor`` in SecureObs.Application.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

_TEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
     "[redacted private key]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*"), "[redacted jwt]"),
    (re.compile(r"(?i)\b(bearer|basic|digest|negotiate|ntlm)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 [redacted]"),
    (re.compile(
        r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|"
        r"api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|client[-_]?secret|secret|"
        r"password|passwd|pwd|passphrase|token|session[-_]?id|sessionid|jsessionid|sid|"
        r"csrf[-_]?token|xsrf[-_]?token|credentials?|ssn|card[-_]?number)"
        r"(\s*[:=]\s*|\"\s*:\s*\"?)(\"[^\"]*\"|'[^']*'|[^\s,;&\"'}]+)"),
     r"\1=[redacted]"),
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[redacted aws key]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "[redacted github token]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[redacted slack token]"),
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1[redacted]@"),
    (re.compile(r"\?[^\s#\"'<>]*=[^\s#\"'<>]*"), "?[query removed]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[redacted email]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[redacted number]"),
)

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_TOKENISH_RE = re.compile(r"^[A-Za-z0-9_\-+=~.]{24,}$")
_HTML_TAG_RE = re.compile(r"<[^>]{0,200}>")
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}


def redact_text(text: str | None) -> str | None:
    if text is None:
        return None
    out = _HTML_TAG_RE.sub("", text)
    for pattern, replacement in _TEXT_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _segment(seg: str) -> str:
    if not seg:
        return seg
    if seg.isdigit():
        return "{id}"
    if _UUID_RE.match(seg):
        return "{uuid}"
    if seg.startswith("eyJ") or _HEX_RE.match(seg):
        return "{token}"
    if "@" in seg:
        return "{email}"
    if _TOKENISH_RE.match(seg) and any(c.isdigit() for c in seg) and any(c.isalpha() for c in seg):
        return "{token}"
    return seg


def sanitize_route(target: str | None, max_len: int = 512) -> str | None:
    """Path-only route template: no scheme, host, credentials, query or fragment.

    ``https://user:pw@shop.internal:8443/api/users/42/orders?token=abc#x``
    → ``/api/users/{id}/orders``. Identifier-like segments are templated so the
    same route observed with different IDs keeps one stable identity.
    """
    if not target:
        return None
    text = str(target).strip()
    if not text or any(ord(c) < 32 for c in text):
        text = "".join(c for c in text if ord(c) >= 32)
    try:
        parts = urlsplit(text)
        path = parts.path if (parts.scheme or parts.netloc) else text.split("?", 1)[0].split("#", 1)[0]
    except ValueError:
        return None
    if not path.startswith("/"):
        path = "/" + path
    segments = [_segment(s) for s in path.split("/")]
    route = "/".join(segments)
    route = re.sub(r"/{2,}", "/", route)
    return route[:max_len] if route else "/"


def sanitize_method(method: str | None) -> str | None:
    text = (method or "").strip().upper()
    return text if text in HTTP_METHODS else None
