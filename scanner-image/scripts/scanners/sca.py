"""Shared SCA normalization for the Trivy and OSV-Scanner drivers.

Both engines can report the same advisory against the same dependency. They
spell things differently (``PyYAML`` vs ``pyyaml``, ``v0.3.5`` vs ``0.3.5``,
``web/package-lock.json`` vs ``/workspace/web/package-lock.json``, a CVE vs a
GHSA primary ID), so identity is normalized here before anything is hashed.

The backend recomputes the cross-engine canonical key from the same fields
(``ScaIdentity`` in SecureObs.Application); ``tests/fixtures/sca-identity-vectors.json``
pins both implementations to identical results.
"""
from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from . import evidence

# Trivy's PURL type → OSV ecosystem name (the vocabulary the dashboard shows).
_PURL_TYPE_TO_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "nuget": "NuGet",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "composer": "Packagist",
    "hex": "Hex",
    "pub": "Pub",
    "cocoapods": "CocoaPods",
    "swift": "SwiftURL",
    "conan": "ConanCenter",
}

# Trivy's Result.Type (analyzer) → ecosystem, used when a record has no PURL.
_TRIVY_TYPE_TO_ECOSYSTEM = {
    "npm": "npm", "yarn": "npm", "pnpm": "npm", "bun": "npm", "node-pkg": "npm",
    "pip": "PyPI", "pipenv": "PyPI", "poetry": "PyPI", "uv": "PyPI", "python-pkg": "PyPI",
    "nuget": "NuGet", "dotnet-core": "NuGet", "packages-props": "NuGet",
    "pom": "Maven", "gradle": "Maven", "jar": "Maven", "sbt": "Maven",
    "gomod": "Go", "gobinary": "Go",
    "cargo": "crates.io", "rustbinary": "crates.io",
    "bundler": "RubyGems", "gemspec": "RubyGems",
    "composer": "Packagist", "composer-vendor": "Packagist",
    "hex": "Hex", "pub": "Pub", "cocoapods": "CocoaPods", "swift": "SwiftURL",
    "conan": "ConanCenter",
}

_KNOWN_ECOSYSTEMS = set(_PURL_TYPE_TO_ECOSYSTEM.values())

# OSV dependency_groups / lockfile scopes that describe *how* a package is used.
# Anything else (e.g. OSV's "requirements" group for requirements.txt) is a file
# grouping, not a scope, and is ignored.
_SCOPE_GROUPS = {"dev": "development", "development": "development",
                 "optional": "optional", "test": "test"}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$", re.IGNORECASE)
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def ecosystem_from_purl(purl: Any) -> str | None:
    text = evidence.clean_line(purl, 512) or ""
    match = re.match(r"^pkg:([a-z0-9.+-]+)/", text, re.IGNORECASE)
    return _PURL_TYPE_TO_ECOSYSTEM.get(match.group(1).lower()) if match else None


def ecosystem_from_trivy_type(result_type: Any) -> str | None:
    return _TRIVY_TYPE_TO_ECOSYSTEM.get(str(result_type or "").lower())


def normalize_ecosystem(value: Any) -> str | None:
    text = evidence.clean_line(value, 64)
    if not text:
        return None
    for known in _KNOWN_ECOSYSTEMS:
        if known.lower() == text.lower():
            return known
    return text


def normalize_name(ecosystem: str | None, name: str) -> str:
    """Comparison key for a package name within its ecosystem."""
    eco = (ecosystem or "").lower()
    if eco == "pypi":
        # PEP 503 normalization: case-insensitive, runs of -_. are equivalent.
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco == "go":
        return name  # module paths are case-sensitive
    return name.lower()


def normalize_version(ecosystem: str | None, version: str) -> str:
    text = version.strip()
    if (ecosystem or "").lower() == "go" and re.match(r"^v\d", text):
        return text[1:]
    return text


def vulnerability_key(primary: str | None, aliases: list[str]) -> str | None:
    """Engine-independent advisory key: lowest CVE, else lowest GHSA, else lowest ID."""
    ids = {a for a in ([primary] + list(aliases)) if a}
    cves = sorted(i.upper() for i in ids if _CVE_RE.match(i))
    if cves:
        return cves[0]
    ghsas = sorted(i.lower() for i in ids if _GHSA_RE.match(i))
    if ghsas:
        return "GHSA" + ghsas[0][4:]
    # Other databases (PYSEC-, GO-, RUSTSEC-, OSV-, …) are case-sensitive on
    # osv.dev, so keep the original spelling; order case-insensitively.
    return sorted(ids, key=lambda i: (i.upper(), i))[0] if ids else None


def severity_from_cvss(score: Any) -> str | None:
    """CVSS v3/v4 qualitative bands. ``None`` when no reliable score exists."""
    try:
        value = float(str(score).strip())
    except (TypeError, ValueError):
        return None
    if value <= 0 or value > 10:
        return None
    if value >= 9.0:
        return "CRITICAL"
    if value >= 7.0:
        return "HIGH"
    if value >= 4.0:
        return "MEDIUM"
    return "LOW"


def normalize_severity(value: Any) -> str | None:
    text = (evidence.clean_line(value, 16) or "").upper()
    if text == "MODERATE":
        return "MEDIUM"
    return text if text in _SEVERITIES else None


def _version_tuple(version: str) -> tuple[int, ...] | None:
    match = re.match(r"^v?(\d+(?:\.\d+)*)", version.strip())
    if not match:
        return None
    return tuple(int(p) for p in match.group(1).split("."))


def upgrade_targets(installed: str, fixed: list[str]) -> list[str]:
    """Fixed versions that are actually upgrades from ``installed``.

    Advisories list a fix per release line (e.g. ``2.9.9.2, 2.8.11.4, 2.7.9.6``).
    A fix on an *older* line can never remediate the installed version, so it is
    dropped. Versions that cannot be compared are kept rather than hidden.
    """
    current = _version_tuple(installed)
    seen: list[str] = []
    for raw in fixed:
        v = evidence.clean_line(raw, 64)
        if v and v not in seen:
            seen.append(v)
    if current is None:
        return seen[:10]
    kept = []
    for v in seen:
        t = _version_tuple(v)
        if t is None or t > current:
            kept.append(v)
    return (kept or seen)[:10]


def fingerprint(*parts: Any) -> str:
    """Same encoding as every other driver (base64 SHA-256 of ``|``-joined parts)."""
    raw = "|".join(str(p or "") for p in parts).encode()
    return base64.b64encode(hashlib.sha256(raw).digest()).decode().strip()


@dataclass
class ScaRecord:
    """One vulnerable dependency occurrence, engine-neutral."""
    tool: str
    ecosystem: str | None
    package_name: str
    installed_version: str
    manifest_path: str | None
    vulnerability_id: str
    aliases: list[str] = field(default_factory=list)
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    severity_source: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    fixed_versions: list[str] = field(default_factory=list)
    fix_status: str = "unknown"          # fixed | no_fix | unknown
    purl: str | None = None
    relationship: str | None = None      # direct | transitive | None (unknown)
    scope: str | None = None             # development | optional | test | None
    cwe_ids: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published_at: str | None = None

    @property
    def key(self) -> str | None:
        return vulnerability_key(self.vulnerability_id, self.aliases)

    def identity(self) -> tuple[str, str, str, str, str]:
        """(ecosystem, name, version, manifest, vuln-key) — the dedup identity."""
        eco = (self.ecosystem or "").lower()
        return (
            eco,
            normalize_name(self.ecosystem, self.package_name),
            normalize_version(self.ecosystem, self.installed_version),
            (self.manifest_path or "").lower(),
            self.key or "",
        )

    def evidence_json(self) -> str:
        aliases = sorted({a for a in self.aliases if a and a != self.vulnerability_id})
        links = [u for u in (evidence.osv_advisory_url(self.vulnerability_id), *self.references) if u]
        return evidence.envelope("sca", {
            "ecosystem": self.ecosystem,
            "packageName": evidence.clean_line(self.package_name, 256),
            "installedVersion": evidence.clean_line(self.installed_version, 128),
            "fixedVersions": self.fixed_versions,
            "fixStatus": self.fix_status,
            "purl": evidence.clean_line(self.purl, 512),
            "manifestPath": self.manifest_path,
            "dependencyRelationship": self.relationship,
            "dependencyScope": self.scope,
            "vulnerabilityId": self.vulnerability_id,
            "aliases": aliases[:20],
            "title": evidence.clean_line(self.title, 300),
            "summary": evidence.clean_text(self.description, 1_500),
            "severity": self.severity,
            "severitySource": evidence.clean_line(self.severity_source, 32),
            "cvssScore": self.cvss_score,
            "cvssVector": evidence.clean_line(self.cvss_vector, 200),
            "cweIds": self.cwe_ids,
            "advisoryUrl": links[0] if links else None,
            "references": list(dict.fromkeys(links[1:]))[:5],
            "publishedAt": evidence.clean_line(self.published_at, 40),
            "detectedBy": [self.tool],
        })

    def description_text(self) -> str:
        """Human description: what is vulnerable and why, never an empty string."""
        headline = self.title or self.vulnerability_id
        version = self.installed_version or "unknown version"
        first = f"{headline} ({self.package_name} {version})."
        body = evidence.clean_text(self.description, evidence.MAX_DESCRIPTION_CHARS - len(first) - 2)
        return f"{first}\n\n{body}" if body else first


def scope_from_groups(groups: Any) -> str | None:
    for g in groups or []:
        mapped = _SCOPE_GROUPS.get(str(g).lower())
        if mapped:
            return mapped
    return None
