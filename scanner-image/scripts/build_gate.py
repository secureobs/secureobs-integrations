import logging
import os
import sys

from api_client import get_blocking, get_pr_findings
from pr_comments.common import finding_line, normalize_path

log = logging.getLogger(__name__)

_GATE_SEVERITIES = {"MEDIUM", "LOW"}


def _github_annotation(rule: str, severity: str, path: str, line: int | None) -> str:
    props = []
    if path:
        props.append(f"file={path}")
        if line:
            props.append(f"line={line}")
    prefix = f"::warning {','.join(props)}::" if props else "::warning::"
    return f"{prefix}{rule} ({severity})"


def _azdo_annotation(rule: str, severity: str, path: str, line: int | None) -> str:
    props = ["type=warning"]
    if path:
        props.append(f"sourcepath={path}")
        if line:
            props.append(f"linenumber={line}")
    return f"##vso[task.logissue {';'.join(props)}]{rule} ({severity})"


def _print_non_blocking_summary(rows: list[tuple[str, str, str]]) -> None:
    """Readable recap of non-blocking findings, in the same box-drawing style
    as cli._print_scan_summary — used when we can't emit a CI-native
    annotation (unrecognized CI vendor, or running outside CI)."""
    if not rows:
        return

    col_w = max(len(severity) for severity, _, _ in rows) + 2
    sep = "─" * (col_w + 50)

    lines = [f"\n{sep}"]
    for severity, rule, scanner in rows:
        lines.append(f"  {severity.ljust(col_w)}{rule} ({scanner})")
    lines.append(sep)

    log.warning("\n".join(lines))


def _report_non_blocking(findings: list[dict]) -> None:
    """Surface MEDIUM/LOW findings without affecting the gate's pass/fail.

    On GitHub Actions / Azure Pipelines we emit each as a native annotation
    so it's highlighted in the Checks/Pipeline UI. Elsewhere we fall back to
    a single readable block in the plain log.
    """
    on_github = os.environ.get("GITHUB_ACTIONS") == "true"
    on_azdo = os.environ.get("TF_BUILD") == "True"
    fallback_rows: list[tuple[str, str, str]] = []

    for f in findings:
        severity = (f.get("severity") or "").upper()
        if severity not in _GATE_SEVERITIES:
            continue
        rule = f.get("ruleId") or "finding"
        scanner = f.get("scanner") or "secureobs"
        path = normalize_path(f.get("filePath"))
        line = finding_line(f)

        if on_github:
            print(_github_annotation(rule, severity, path, line))
        elif on_azdo:
            print(_azdo_annotation(rule, severity, path, line))
        else:
            fallback_rows.append((severity, rule, scanner))

    _print_non_blocking_summary(fallback_rows)


def run(api_url: str, api_key: str, project_id: str, pipeline_run_id: str) -> None:
    log.info("Checking build gate for pipeline run %s", pipeline_run_id)
    is_blocking = get_blocking(api_url, api_key, pipeline_run_id)
    findings = get_pr_findings(api_url, api_key, project_id, pipeline_run_id)
    _report_non_blocking(findings or [])

    if is_blocking:
        log.error("Gate FAILED — blocking findings detected. Pipeline is blocked.")
        sys.exit(3)

    log.info("Gate PASSED — no blocking findings.")
    sys.exit(0)
