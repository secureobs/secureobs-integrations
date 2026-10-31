import logging
import os
import sys

import re

from api_client import get_blocking, get_gate_decision, get_pr_findings
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

    # Neutral heading: whether these block depends on the project's policy (AnyFinding
    # blocks on them), which the decision printed below states.
    lines = [f"\n{sep}", f"  MEDIUM/LOW findings in this run ({len(rows)}); the gate decision below says what blocks."]
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


EXIT_PASSED = 0
EXIT_BLOCKED = 3
EXIT_INCOMPLETE = 4

_CONTROL_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|[\x00-\x1f\x7f]")


def _clean(value: object, limit: int = 300) -> str:
    return _CONTROL_RE.sub("", str(value or ""))[:limit]


def _print_decision(decision: dict) -> None:
    """Human-readable gate decision: why it passed, blocked, or is incomplete."""
    outcome = _clean(decision.get("outcome"), 32).upper()
    lines = [f"Build gate decision: {outcome}  (policy: {_clean(decision.get('policy'), 32)})"]
    for reason in decision.get("reasons") or []:
        if not isinstance(reason, dict):
            continue
        marker = "✗" if reason.get("blocking") else "ℹ"
        scanner = f" [{_clean(reason.get('scanner'), 64)}]" if reason.get("scanner") else ""
        lines.append(f"  {marker} {_clean(reason.get('code'), 64)}{scanner}: {_clean(reason.get('message'))}")
    scanners = [s for s in decision.get("scanners") or [] if isinstance(s, dict)]
    if scanners:
        width = max(len(_clean(s.get("key"), 64)) for s in scanners) + 2
        lines.append("  Scanner status for this run:")
        for s in scanners:
            required = " (required)" if s.get("required") else ""
            count = s.get("findingCount")
            suffix = f", {count} finding(s)" if isinstance(count, int) and count else ""
            lines.append(f"    {_clean(s.get('key'), 64).ljust(width)}{_clean(s.get('status'), 40)}{suffix}{required}")
    log.info("\n".join(lines))


def run(api_url: str, api_key: str, project_id: str, pipeline_run_id: str) -> None:
    log.info("Checking build gate for pipeline run %s", pipeline_run_id)
    decision = get_gate_decision(api_url, api_key, project_id, pipeline_run_id)
    findings = get_pr_findings(api_url, api_key, project_id, pipeline_run_id)
    _report_non_blocking(findings or [])

    if decision is None:
        # Older SecureObs API without the structured gate: keep the original
        # boolean behaviour exactly.
        is_blocking = get_blocking(api_url, api_key, pipeline_run_id)
        if is_blocking:
            log.error("Gate FAILED — blocking findings detected. Pipeline is blocked.")
            sys.exit(EXIT_BLOCKED)
        log.info("Gate PASSED — no blocking findings.")
        sys.exit(EXIT_PASSED)

    _print_decision(decision)
    outcome = decision.get("outcome")
    if outcome == "blocked":
        log.error("Gate FAILED — blocking findings detected. Pipeline is blocked.")
        sys.exit(EXIT_BLOCKED)
    if outcome == "incomplete":
        log.error("Gate FAILED — a required security check did not complete, so this run cannot "
                  "be called clean. This is not a security finding; see the reasons above.")
        sys.exit(EXIT_INCOMPLETE)
    if outcome == "passed":
        log.info("Gate PASSED — no blocking findings.")
        sys.exit(EXIT_PASSED)
    log.error("Gate returned an unknown outcome %r; refusing to pass.", _clean(outcome, 32))
    sys.exit(2)
