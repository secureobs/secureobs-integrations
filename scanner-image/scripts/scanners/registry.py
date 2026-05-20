"""Driver registry for the scanner orchestrator.

Adding a new scanner:

1. Implement ``run(workspace, project_id, pipeline_run_id, config)`` in
   ``scanners/<module>.py`` returning ``ScanResult`` with payloads shaped for
   ``POST /api/findings/bulk-universal`` (camelCase JSON — see backend
   ``UniversalFindingDto``) **or**, for legacy Semgrep/GitLeaks, the dedicated
   bulk endpoints shown below.

2. Register the catalog ``key``, ``bulk_endpoint``, and runner here.

``bulk-universal`` is the ingestion path for Trivy, Bandit, Checkov, … — one
consistent DTO regardless of tooling. Keys must match backend ``Scanner.Key``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from . import bandit, checkov, eslint_security, gitleaks, osv_scanner, semgrep, trivy
from .base import ScanResult

DriverRunner = Callable[[str, str, str, "dict[str, str] | None"], ScanResult]

_BULK_UNIVERSAL = "findings/bulk-universal"


@dataclass(frozen=True)
class Driver:
    key: str
    bulk_endpoint: str
    runner: DriverRunner


def _semgrep_runner(w: str, p: str, r: str, c: dict | None) -> ScanResult:
    return semgrep.run(w, p, r, c)


def _gitleaks_runner(w: str, p: str, r: str, c: dict | None) -> ScanResult:
    return gitleaks.run(w, p, r, c)


def _trivy_runner(w: str, p: str, r: str, c: dict | None) -> ScanResult:
    return trivy.run(w, p, r, c)


def _bandit_runner(w: str, p: str, r: str, c: dict | None) -> ScanResult:
    return bandit.run(w, p, r, c)


def _checkov_runner(w: str, p: str, r: str, c: dict | None) -> ScanResult:
    return checkov.run(w, p, r, c)


def _osv_runner(w: str, p: str, r: str, c: dict | None) -> ScanResult:
    return osv_scanner.run(w, p, r, c)


def _eslint_runner(w: str, p: str, r: str, c: dict | None) -> ScanResult:
    return eslint_security.run(w, p, r, c)


REGISTRY: dict[str, Driver] = {
    "semgrep": Driver("semgrep", "findings/bulk-semgrep", _semgrep_runner),
    "gitleaks": Driver("gitleaks", "findings/bulk-gitleaks", _gitleaks_runner),
    "trivy": Driver("trivy", _BULK_UNIVERSAL, _trivy_runner),
    "bandit": Driver("bandit", _BULK_UNIVERSAL, _bandit_runner),
    "eslint-security": Driver("eslint-security", _BULK_UNIVERSAL, _eslint_runner),
    "osv-scanner": Driver("osv-scanner", _BULK_UNIVERSAL, _osv_runner),
    "checkov": Driver("checkov", _BULK_UNIVERSAL, _checkov_runner),
    # codeql / sonarqube / snyk / owasp-zap are not bundled. They run inside a
    # vendor's CI (token, SARIF, or AST analysis) and would only ever be added
    # here when there is a real driver. The catalog hides them via
    # IsEnabledGlobally=false in migration 20260520040000.
}

DEFAULT_KEYS: list[str] = ["semgrep", "gitleaks"]
