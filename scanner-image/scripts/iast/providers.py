"""IAST report providers accepted by ``import-iast``.

SecureObs does not instrument applications. It imports what a genuine IAST
engine observed while the customer's tests exercised an instrumented app.

A provider entry says which report format is accepted and how the producing
tool is recognised. ``verified`` is True when the provider's export is the format the
import contract is defined against (generic SARIF 2.1.0 with runtime evidence, tested with
synthetic fixtures) — not a claim that a specific vendor's real output was imported. A
vendor-specific export that has not been validated with real output is unverified: it is importable but
labelled as such everywhere (CLI output, dashboard, docs).

Keep in sync with ``IastProviders`` in SecureObs.Application.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Provider:
    id: str
    display_name: str
    report_format: str
    verified: bool
    # When set, the SARIF tool.driver.name must match (case-insensitive).
    tool_name_pattern: re.Pattern[str] | None
    note: str


PROVIDERS: dict[str, Provider] = {
    "sarif": Provider(
        id="sarif",
        display_name="Generic SARIF 2.1.0 (IAST engine)",
        report_format="sarif",
        verified=True,
        tool_name_pattern=None,
        note=("Any IAST engine that exports SARIF 2.1.0 with the observed HTTP request "
              "(result.webRequest) for each finding."),
    ),
    "contrast": Provider(
        id="contrast",
        display_name="Contrast Assess (contrast sarif export)",
        report_format="sarif",
        verified=False,
        tool_name_pattern=re.compile(r"contrast", re.IGNORECASE),
        note=("Unverified: Contrast documents a SARIF export of Assess findings via the "
              "Contrast CLI `contrast sarif` command, but SecureObs has not validated that "
              "export against a licensed Contrast tenant. Findings are accepted only when "
              "they meet the generic SARIF runtime-evidence contract."),
    ),
}

# Producers of static, dependency, secret, IaC or DAST results. Their SARIF is
# never IAST, whatever the upload command is called. Matched case-insensitively
# against tool.driver.name (and fullName) as whole words.
NON_IAST_TOOLS = (
    "semgrep", "codeql", "trivy", "osv-scanner", "osv scanner", "gitleaks", "bandit",
    "eslint", "checkov", "tfsec", "terrascan", "kics", "sonarqube", "sonarcloud", "sonar",
    "snyk", "dependabot", "dependency-check", "grype", "brakeman", "gosec", "pmd",
    "spotbugs", "findsecbugs", "devskim", "security code scan", "roslyn", "fortify",
    "checkmarx", "veracode static", "zap", "owasp zap", "zaproxy", "burp", "nuclei",
    "nikto", "arachni", "w3af", "wapiti", "contrast scan",
)

_NON_IAST_RE = re.compile(
    r"(?<![a-z0-9])(" + "|".join(re.escape(t) for t in NON_IAST_TOOLS) + r")(?![a-z0-9])",
    re.IGNORECASE,
)


def non_iast_tool(name: str) -> str | None:
    """The denylisted tool ``name`` refers to, or None."""
    match = _NON_IAST_RE.search(name or "")
    return match.group(1).lower() if match else None
