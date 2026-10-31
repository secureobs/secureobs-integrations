"""Sanitized, versioned evidence envelopes for ``rawPayload``.

Drivers used to forward each tool's raw JSON record as ``rawPayload``. That made
the payload tool-specific, occasionally invalid (it was truncated mid-JSON), and
able to carry data nobody reviewed (ANSI-highlighted code, secret context lines).

Drivers now send a small, allowlisted envelope instead::

    {"schema": "secureobs.evidence.v1", "kind": "sca", "sca": {...}}

The backend projects only the fields it knows into a typed DTO and ignores the
rest, so this module is the client-side half of a deny-by-default contract.
Every string that leaves this module is length-capped, single-purpose and free
of control characters.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

SCHEMA = "secureobs.evidence.v1"

# The API rejects rawPayload over 65,536 characters (ScannerIngestLimits); stay
# well below it so a whole batch is never refused because of one record.
MAX_ENVELOPE_CHARS = 32_000
# The API rejects descriptions over 8,192 characters.
MAX_DESCRIPTION_CHARS = 8_000
MAX_RULE_ID_CHARS = 512
MAX_PATH_CHARS = 1_024

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏  ‪-‮⁦-⁩]")
_ADVISORY_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{1,63}$")
_CWE_RE = re.compile(r"^CWE-\d{1,6}$")

# Advisory links are only ever rendered when they point at a well-known
# vulnerability database. Anything else is dropped rather than shown.
_ADVISORY_HOSTS: dict[str, tuple[str, ...]] = {
    "osv.dev": ("/vulnerability/",),
    "nvd.nist.gov": ("/vuln/detail/",),
    "github.com": ("/advisories/",),
    "avd.aquasec.com": ("/",),
    "www.cve.org": ("/CVERecord",),
    "cve.mitre.org": ("/cgi-bin/cvename.cgi",),
    "pkg.go.dev": ("/vuln/",),
    "rustsec.org": ("/advisories/",),
    "security-tracker.debian.org": ("/tracker/",),
    "access.redhat.com": ("/security/cve/",),
    "ubuntu.com": ("/security/",),
}


def clean_text(value: Any, max_len: int) -> str | None:
    """Plain text: no ANSI escapes or control characters, capped length."""
    if value is None:
        return None
    text = _ANSI_RE.sub("", str(value))
    text = _CONTROL_RE.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
    text = text.strip()
    if not text:
        return None
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def clean_line(value: Any, max_len: int) -> str | None:
    """A single line of text (identifiers, titles, versions)."""
    text = clean_text(value, max_len * 2)
    if text is None:
        return None
    text = " ".join(text.split())
    return text[:max_len] or None


def advisory_id(value: Any) -> str | None:
    text = clean_line(value, 64)
    return text if text and _ADVISORY_ID_RE.match(text) else None


def cwe_ids(values: Any) -> list[str]:
    out: list[str] = []
    for raw in values or []:
        text = (clean_line(raw, 16) or "").upper()
        if _CWE_RE.match(text) and text not in out:
            out.append(text)
    return out[:16]


def advisory_url(value: Any) -> str | None:
    """Return ``value`` only if it is an https link to an allowlisted advisory DB."""
    text = clean_line(value, 400)
    if not text:
        return None
    try:
        parts = urlsplit(text)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or parts.username or parts.password or parts.port not in (None, 443):
        return None
    prefixes = _ADVISORY_HOSTS.get(host)
    if not prefixes or not any(parts.path.startswith(p) for p in prefixes):
        return None
    # Fragments are never needed for an advisory page.
    return urlunsplit(("https", host, parts.path, parts.query, ""))


def osv_advisory_url(identifier: str | None) -> str | None:
    """Canonical, trusted advisory link. osv.dev resolves CVE, GHSA, PYSEC, GO, … IDs."""
    ident = advisory_id(identifier)
    return f"https://osv.dev/vulnerability/{ident}" if ident else None


def relative_path(path: Any, root: str) -> str | None:
    """Workspace-relative POSIX path, or ``None`` when the path escapes ``root``.

    Tool output is untrusted: a crafted lockfile name or a tool bug must never
    let an absolute host path, a ``..`` escape, or control characters through.
    """
    text = clean_line(path, MAX_PATH_CHARS * 2)
    if not text or "\x00" in text:
        return None
    root_abs = os.path.normpath(os.path.abspath(root))
    candidate = text.replace("\\", "/")
    if not os.path.isabs(candidate):
        candidate = os.path.join(root_abs, candidate)
    candidate = os.path.normpath(candidate)
    if candidate != root_abs and not candidate.startswith(root_abs + os.sep):
        return None
    rel = os.path.relpath(candidate, root_abs).replace(os.sep, "/")
    if rel in (".", "") or rel.startswith("../"):
        return None
    return rel[:MAX_PATH_CHARS]


def envelope(kind: str, body: dict[str, Any]) -> str:
    """Serialize an evidence envelope, dropping empty values, within size limits."""
    compact = {k: v for k, v in body.items() if v not in (None, "", [], {})}
    payload = {"schema": SCHEMA, "kind": kind, kind: compact}
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    if len(text) <= MAX_ENVELOPE_CHARS:
        return text
    # Shed the bulkiest optional fields until it fits — never truncate JSON text.
    for field_name in ("references", "summary", "aliases", "flow", "description"):
        compact.pop(field_name, None)
        text = json.dumps({"schema": SCHEMA, "kind": kind, kind: compact},
                          separators=(",", ":"), ensure_ascii=False)
        if len(text) <= MAX_ENVELOPE_CHARS:
            return text
    return json.dumps({"schema": SCHEMA, "kind": kind}, separators=(",", ":"))
